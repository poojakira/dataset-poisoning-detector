"""
Multi-tenant isolation for the poisoning detector.

A single deployment often serves several customers/teams ("tenants"). Before
this module the detector had ONE global baseline: samples from tenant B would
update the rolling statistics and IsolationForest that scored tenant A. That is
both a correctness bug (one tenant's distribution pollutes another's detector,
wrecking accuracy) and a security/privacy problem (cross-tenant data influence,
and quarantined samples pooled without a tenant boundary).

This module gives each tenant a fully isolated lane:
    - Baseline isolation : one StreamingDetector per tenant, created lazily.
      A sample scored for tenant A can never touch tenant B's Welford stats,
      window, or fitted model.
    - Quarantine namespacing : flagged samples are stored with a tenant tag and
      every read is scoped to a tenant, so reviewers never see another tenant's
      data through this layer.
    - Rate-limit quotas : per-tenant request budgets via an isolated sliding
      window, so one noisy tenant cannot exhaust another's throughput.

Threat Model Assumptions:
    - tenant_id is supplied by the trusted auth/routing layer (derived from a
      validated JWT/API-key/mTLS identity), NOT taken raw from an untrusted body
      field. This module validates and length-bounds it defensively regardless.
    - Tenants are mutually distrusting. The isolation here is logical (in one
      process); hostile multi-tenancy at the strongest level still warrants
      separate processes/pods per tenant.

Honest Limitations:
    - Isolation is in-process and in-memory. It prevents accidental and
      data-level cross-tenant influence, but a memory-safety exploit in the host
      process could still cross the boundary -- use per-tenant pods for hard
      isolation of untrusted tenants.
    - Per-tenant detectors multiply memory by the number of active tenants.
      There is an idle-eviction hook (evict_tenant) but no automatic LRU here.
    - The quarantine namespacing relies on the underlying store; if a caller
      bypasses TenantQuarantine and hits the raw store, the boundary is lost.

Security Notes:
    - tenant_id is validated against an allowlist pattern and length bound to
      prevent it being abused as an injection vector into storage keys.
    - No pickle/eval. All state is plain Python objects.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from .stream import StreamingDetector, ScoringResult, StreamStats
from .storage import QuarantineStore, QuarantinedSample, ResolutionStatus
from .rate_limiter import SlidingWindowRateLimiter, RateLimitResult

# Tenant ids must be short, printable identifiers -- not arbitrary strings.
_TENANT_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def validate_tenant_id(tenant_id: str) -> str:
    """Validate and return a tenant id, raising on anything suspicious.

    Args:
        tenant_id: The tenant identifier supplied by the routing/auth layer.

    Returns:
        The same tenant_id if it is well-formed.

    Raises:
        ValueError: If the id is empty, too long, or contains disallowed chars.
    """
    if not isinstance(tenant_id, str) or not _TENANT_ID_RE.match(tenant_id):
        raise ValueError(
            "tenant_id must be 1-128 chars of [A-Za-z0-9._:-]; got "
            f"{tenant_id!r}"
        )
    return tenant_id


@dataclass
class TenantConfig:
    """Per-tenant detector and quota configuration.

    Attributes:
        window_size: Rolling window size for this tenant's detector.
        contamination: Expected poison fraction for this tenant.
        vote_threshold: Minimum method votes to flag a sample.
        reduce_dim: Optional dimensionality reduction target.
        max_requests: Per-tenant request budget per rate-limit window.
        window_seconds: Rate-limit window length in seconds.
    """

    window_size: int = 10000
    contamination: float = 0.05
    vote_threshold: int = 2
    reduce_dim: int | None = None
    max_requests: int = 1000
    window_seconds: float = 60.0


class TenantQuarantine:
    """Tenant-scoped wrapper over a shared QuarantineStore.

    Every write is tagged with the tenant id (in ``source`` and ``metadata``)
    and every read is filtered to a single tenant, so the tenant boundary holds
    even though the underlying store is shared.
    """

    def __init__(self, store: QuarantineStore) -> None:
        self._store = store

    def store_sample(
        self,
        tenant_id: str,
        sample_data: list[float] | dict[str, Any],
        scores: dict[str, float],
        source: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Store a flagged sample, namespaced to a tenant."""
        tenant_id = validate_tenant_id(tenant_id)
        meta = dict(metadata or {})
        meta["tenant_id"] = tenant_id
        namespaced_source = f"{tenant_id}:{source}" if source else tenant_id
        return self._store.store_sample(
            sample_data=sample_data,
            scores=scores,
            source=namespaced_source,
            metadata=meta,
        )

    def get_pending_reviews(
        self, tenant_id: str, limit: int = 100
    ) -> list[QuarantinedSample]:
        """Return pending reviews belonging ONLY to the given tenant."""
        tenant_id = validate_tenant_id(tenant_id)
        # Over-fetch then filter, since the base interface has no tenant column.
        candidates = self._store.get_pending_reviews(limit=limit * 5)
        scoped = [
            s for s in candidates if s.metadata.get("tenant_id") == tenant_id
        ]
        return scoped[:limit]

    def resolve(
        self,
        tenant_id: str,
        sample_id: str,
        resolution: ResolutionStatus,
        reviewer: str = "",
        notes: str = "",
    ) -> bool:
        """Resolve an entry, but only if it belongs to the tenant.

        Prevents a reviewer scoped to tenant A from resolving tenant B's entries.
        """
        tenant_id = validate_tenant_id(tenant_id)
        existing = self._store.get_sample(sample_id)
        if existing is None or existing.metadata.get("tenant_id") != tenant_id:
            return False
        return self._store.resolve(sample_id, resolution, reviewer, notes)


class TenantManager:
    """Routes scoring, baselines, quarantine and rate limits per tenant.

    Each tenant gets its own StreamingDetector (created lazily on first use) so
    baselines never cross. Quarantine and rate limiting are likewise scoped.

    Usage:
        mgr = TenantManager(default_config=TenantConfig(window_size=5000))
        mgr.update_baseline("acme", clean_rows_for_acme)
        result = mgr.score("acme", sample)          # uses only acme's baseline
        if not mgr.allow_request("acme"):
            raise RateLimited
    """

    def __init__(
        self,
        default_config: TenantConfig | None = None,
        quarantine_store: QuarantineStore | None = None,
        detector_factory: Callable[[TenantConfig], StreamingDetector] | None = None,
    ) -> None:
        """Initialize the tenant manager.

        Args:
            default_config: Config applied to tenants without an explicit one.
            quarantine_store: Optional shared store; wrapped in TenantQuarantine.
            detector_factory: Optional custom factory for per-tenant detectors.
                Defaults to constructing a StreamingDetector from the config.
        """
        self._default_config = default_config or TenantConfig()
        self._configs: dict[str, TenantConfig] = {}
        self._detectors: dict[str, StreamingDetector] = {}
        self._rate_limiters: dict[str, SlidingWindowRateLimiter] = {}
        self._lock = threading.Lock()
        self._detector_factory = detector_factory or self._default_factory
        self.quarantine = (
            TenantQuarantine(quarantine_store) if quarantine_store else None
        )

    def _default_factory(self, config: TenantConfig) -> StreamingDetector:
        """Build a StreamingDetector from a TenantConfig."""
        return StreamingDetector(
            window_size=config.window_size,
            contamination=config.contamination,
            vote_threshold=config.vote_threshold,
            reduce_dim=config.reduce_dim,
        )

    def set_tenant_config(self, tenant_id: str, config: TenantConfig) -> None:
        """Register an explicit config for a tenant (before first use)."""
        tenant_id = validate_tenant_id(tenant_id)
        with self._lock:
            self._configs[tenant_id] = config

    def _config_for(self, tenant_id: str) -> TenantConfig:
        return self._configs.get(tenant_id, self._default_config)

    def _get_detector(self, tenant_id: str) -> StreamingDetector:
        """Return (creating if needed) the isolated detector for a tenant."""
        tenant_id = validate_tenant_id(tenant_id)
        with self._lock:
            detector = self._detectors.get(tenant_id)
            if detector is None:
                detector = self._detector_factory(self._config_for(tenant_id))
                self._detectors[tenant_id] = detector
            return detector

    def _get_rate_limiter(self, tenant_id: str) -> SlidingWindowRateLimiter:
        with self._lock:
            limiter = self._rate_limiters.get(tenant_id)
            if limiter is None:
                cfg = self._config_for(tenant_id)
                limiter = SlidingWindowRateLimiter(
                    max_requests=cfg.max_requests,
                    window_seconds=cfg.window_seconds,
                    key_prefix=f"tenant:{tenant_id}",
                )
                self._rate_limiters[tenant_id] = limiter
            return limiter

    def score(
        self, tenant_id: str, sample: Any
    ) -> ScoringResult:
        """Score a sample using ONLY the given tenant's detector/baseline."""
        return self._get_detector(tenant_id).score_sample(sample)

    def update_baseline(self, tenant_id: str, clean_samples: Any) -> None:
        """Update ONLY the given tenant's baseline with known-clean data."""
        self._get_detector(tenant_id).update_baseline(clean_samples)

    def get_stats(self, tenant_id: str) -> StreamStats:
        """Return the given tenant's detector statistics."""
        return self._get_detector(tenant_id).get_stats()

    def allow_request(self, tenant_id: str) -> RateLimitResult:
        """Check (and consume) one unit of the tenant's rate-limit budget."""
        tenant_id = validate_tenant_id(tenant_id)
        return self._get_rate_limiter(tenant_id).check(f"tenant:{tenant_id}")

    def active_tenants(self) -> list[str]:
        """Return the ids of tenants that currently have a live detector."""
        with self._lock:
            return sorted(self._detectors.keys())

    def evict_tenant(self, tenant_id: str) -> bool:
        """Drop a tenant's detector/limiter state to reclaim memory.

        Returns:
            True if any state for the tenant was removed.
        """
        tenant_id = validate_tenant_id(tenant_id)
        with self._lock:
            removed = self._detectors.pop(tenant_id, None) is not None
            self._rate_limiters.pop(tenant_id, None)
            return removed
