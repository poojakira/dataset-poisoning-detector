"""
Input sanitization for dataset poisoning detection.

Provides the first line of defense against adversarial inputs by validating
all samples before any processing occurs. Rejects malformed, oversized, or
suspicious inputs that could crash downstream ML components (e.g., sklearn's
IsolationForest segfaults on NaN), exhaust memory, or degrade detection quality.

Threat Model Assumptions:
    - All sample data arriving via API or pipeline is UNTRUSTED. Samples may
      come from compromised data sources, malicious clients, or adversarial
      pipelines designed to crash the detector or evade detection.
    - An attacker may craft inputs with NaN/Inf values to crash sklearn
      estimators (which do not handle non-finite values gracefully), or send
      extremely high-dimensional samples to trigger OOM conditions.
    - Value range attacks send samples with feature values at float64 extremes
      (e.g., 1e308) to overflow accumulators in Welford statistics or cause
      numerical instability in z-score calculations.
    - Per-client rate limiting at the sanitization layer prevents a single
      client from monopolizing detector resources even if upstream rate limits
      are bypassed.

Honest Limitations:
    - Configurable bounds are static. An attacker who knows the bounds can
      craft inputs that pass sanitization but are still adversarial (within
      bounds but positioned to poison the model). Sanitization is necessary
      but not sufficient -- downstream detection methods handle that case.
    - Per-client tracking uses in-memory state. On process restart, rate limit
      windows reset. In multi-process deployments, each process has independent
      limits unless an external store (Redis) is used.
    - Dimension validation assumes all samples share a fixed dimensionality
      per deployment. Variable-length inputs (e.g., text embeddings of different
      sizes) require the caller to configure max_dimensions appropriately.
    - The forensic log records rejection metadata but NOT the full sample
      (which could itself be an exfiltration vector if logs are accessible).

Security Notes:
    - This module MUST be called before any numpy/sklearn operation on the data.
    - Never log raw sample values (data leakage risk). Log only metadata:
      dimension count, which validation failed, client identifier.
    - Rate limit state is not shared across processes by default. Deploy behind
      a distributed rate limiter (see rate_limiter.py) for multi-replica setups.
    - Rejection reasons are intentionally generic in client-facing responses
      to avoid leaking validation logic to attackers.
"""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)


class RejectionReason(Enum):
    """Reasons a sample may be rejected during sanitization."""

    NAN_VALUES = "nan_values"
    INF_VALUES = "inf_values"
    EXCEEDS_MAX_DIMENSIONS = "exceeds_max_dimensions"
    BELOW_MIN_DIMENSIONS = "below_min_dimensions"
    VALUE_OUT_OF_RANGE = "value_out_of_range"
    RATE_LIMITED = "rate_limited"
    EMPTY_SAMPLE = "empty_sample"


@dataclass
class SanitizationResult:
    """Result of input sanitization.

    Attributes:
        is_valid: Whether the sample passed all checks.
        rejection_reason: Why the sample was rejected (None if valid).
        rejection_detail: Additional context for forensic logging.
        sanitized_sample: The validated numpy array (None if rejected).
    """

    is_valid: bool
    rejection_reason: RejectionReason | None = None
    rejection_detail: str = ""
    sanitized_sample: np.ndarray | None = None


@dataclass
class RejectionEvent:
    """Forensic record of a rejected input.

    Logged for security auditing and incident response. Does NOT
    contain the raw sample data to prevent data leakage via logs.

    Attributes:
        timestamp: Unix timestamp of the rejection.
        client_id: Identifier for the client that submitted the sample.
        reason: The rejection reason enum value.
        detail: Human-readable context about the rejection.
        sample_dimensions: Number of features in the rejected sample.
        metadata: Additional context (source, endpoint, etc.).
    """

    timestamp: float
    client_id: str
    reason: RejectionReason
    detail: str
    sample_dimensions: int
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class _RateLimitEntry:
    """Internal per-client rate tracking."""

    timestamps: list[float] = field(default_factory=list)


class InputSanitizer:
    """Validates and sanitizes input samples before detection processing.

    This is the first line of defense in the detection pipeline. All samples
    MUST pass through sanitization before reaching any numpy/sklearn operation.

    The sanitizer enforces:
        1. No NaN values (crash sklearn estimators)
        2. No Inf/-Inf values (crash sklearn, overflow accumulators)
        3. Dimension bounds (prevent memory exhaustion)
        4. Value range bounds (prevent numerical overflow)
        5. Per-client rate limiting (prevent resource exhaustion)

    Usage:
        sanitizer = InputSanitizer(
            max_dimensions=10000,
            min_dimensions=1,
            value_lower_bound=-1e6,
            value_upper_bound=1e6,
            max_requests_per_minute=100,
        )

        result = sanitizer.sanitize(features=[1.0, 2.0, 3.0], client_id="svc-pipeline")
        if result.is_valid:
            # Safe to pass to detection pipeline
            detector.score_sample(result.sanitized_sample)
        else:
            # Handle rejection
            log_rejection(result.rejection_reason)

    Args:
        max_dimensions: Maximum allowed feature dimensions per sample.
        min_dimensions: Minimum required feature dimensions per sample.
        value_lower_bound: Minimum allowed feature value (inclusive).
        value_upper_bound: Maximum allowed feature value (inclusive).
        max_requests_per_minute: Per-client rate limit for sanitization calls.
        enable_rate_limiting: Whether to enforce per-client rate limits.
    """

    def __init__(
        self,
        max_dimensions: int = 100000,
        min_dimensions: int = 1,
        value_lower_bound: float = -1e10,
        value_upper_bound: float = 1e10,
        max_requests_per_minute: int = 1000,
        enable_rate_limiting: bool = True,
    ) -> None:
        """Initialize the input sanitizer.

        Args:
            max_dimensions: Maximum allowed number of features per sample.
                Default of 100000 prevents memory bombs while supporting
                high-dimensional embeddings.
            min_dimensions: Minimum required number of features. Must be >= 1.
            value_lower_bound: Minimum allowed value for any feature.
                Values below this are rejected as out-of-range.
            value_upper_bound: Maximum allowed value for any feature.
                Values above this are rejected as out-of-range.
            max_requests_per_minute: Maximum sanitization calls per client
                within a 60-second sliding window.
            enable_rate_limiting: If False, skip per-client rate limiting.
                Useful for batch ingestion where upstream already limits.
        """
        if min_dimensions < 1:
            raise ValueError("min_dimensions must be >= 1")
        if max_dimensions < min_dimensions:
            raise ValueError("max_dimensions must be >= min_dimensions")
        if value_lower_bound >= value_upper_bound:
            raise ValueError("value_lower_bound must be < value_upper_bound")

        self._max_dimensions = max_dimensions
        self._min_dimensions = min_dimensions
        self._value_lower_bound = value_lower_bound
        self._value_upper_bound = value_upper_bound
        self._max_requests_per_minute = max_requests_per_minute
        self._enable_rate_limiting = enable_rate_limiting

        # Per-client rate tracking
        self._rate_state: dict[str, _RateLimitEntry] = defaultdict(
            _RateLimitEntry
        )

        # Forensic log of rejections (bounded to prevent memory leak)
        self._rejection_log: list[RejectionEvent] = []
        self._max_log_size = 10000

        # Statistics
        self._total_processed: int = 0
        self._total_rejected: int = 0

    def sanitize(
        self,
        features: list[float] | np.ndarray,
        client_id: str = "anonymous",
        metadata: dict[str, Any] | None = None,
    ) -> SanitizationResult:
        """Validate and sanitize an input sample.

        Applies all validation checks in order of computational cost
        (cheapest first). Returns immediately on first failure.

        Args:
            features: The feature vector to validate. Can be a list of floats
                or a numpy array.
            client_id: Identifier for the submitting client. Used for
                rate limiting and forensic logging.
            metadata: Optional metadata for forensic logging (source, endpoint).

        Returns:
            SanitizationResult with is_valid=True and sanitized numpy array,
            or is_valid=False with rejection reason and detail.
        """
        self._total_processed += 1

        # Rate limiting check (cheapest -- just a timestamp comparison)
        if self._enable_rate_limiting:
            if not self._check_rate_limit(client_id):
                return self._reject(
                    reason=RejectionReason.RATE_LIMITED,
                    detail=f"Client '{client_id}' exceeded {self._max_requests_per_minute} requests/minute",
                    client_id=client_id,
                    sample_dimensions=len(features) if features else 0,
                    metadata=metadata,
                )

        # Empty check
        if features is None or (hasattr(features, "__len__") and len(features) == 0):
            return self._reject(
                reason=RejectionReason.EMPTY_SAMPLE,
                detail="Sample has no features",
                client_id=client_id,
                sample_dimensions=0,
                metadata=metadata,
            )

        # Dimension checks (cheap -- just a length check)
        num_dims = len(features)

        if num_dims > self._max_dimensions:
            return self._reject(
                reason=RejectionReason.EXCEEDS_MAX_DIMENSIONS,
                detail=f"Sample has {num_dims} dimensions, max is {self._max_dimensions}",
                client_id=client_id,
                sample_dimensions=num_dims,
                metadata=metadata,
            )

        if num_dims < self._min_dimensions:
            return self._reject(
                reason=RejectionReason.BELOW_MIN_DIMENSIONS,
                detail=f"Sample has {num_dims} dimensions, min is {self._min_dimensions}",
                client_id=client_id,
                sample_dimensions=num_dims,
                metadata=metadata,
            )

        # Convert to numpy for efficient validation
        try:
            arr = np.asarray(features, dtype=np.float64)
        except (ValueError, TypeError) as e:
            return self._reject(
                reason=RejectionReason.NAN_VALUES,
                detail=f"Cannot convert to numeric array: {type(e).__name__}",
                client_id=client_id,
                sample_dimensions=num_dims,
                metadata=metadata,
            )

        # NaN check (crashes sklearn estimators)
        if np.any(np.isnan(arr)):
            nan_count = int(np.sum(np.isnan(arr)))
            return self._reject(
                reason=RejectionReason.NAN_VALUES,
                detail=f"Sample contains {nan_count} NaN value(s)",
                client_id=client_id,
                sample_dimensions=num_dims,
                metadata=metadata,
            )

        # Inf/-Inf check (crashes sklearn, overflows accumulators)
        if np.any(np.isinf(arr)):
            inf_count = int(np.sum(np.isinf(arr)))
            return self._reject(
                reason=RejectionReason.INF_VALUES,
                detail=f"Sample contains {inf_count} infinite value(s)",
                client_id=client_id,
                sample_dimensions=num_dims,
                metadata=metadata,
            )

        # Value range check (prevents numerical overflow in statistics)
        if np.any(arr < self._value_lower_bound) or np.any(arr > self._value_upper_bound):
            min_val = float(np.min(arr))
            max_val = float(np.max(arr))
            return self._reject(
                reason=RejectionReason.VALUE_OUT_OF_RANGE,
                detail=(
                    f"Values outside allowed range [{self._value_lower_bound}, "
                    f"{self._value_upper_bound}]. "
                    f"Sample range: [{min_val}, {max_val}]"
                ),
                client_id=client_id,
                sample_dimensions=num_dims,
                metadata=metadata,
            )

        # All checks passed
        return SanitizationResult(
            is_valid=True,
            sanitized_sample=arr,
        )

    def _check_rate_limit(self, client_id: str) -> bool:
        """Check if a client is within their rate limit.

        Uses a sliding window algorithm: count requests in the last 60 seconds.

        Args:
            client_id: The client identifier.

        Returns:
            True if allowed, False if rate limited.
        """
        now = time.time()
        window_start = now - 60.0

        entry = self._rate_state[client_id]

        # Prune expired timestamps
        entry.timestamps = [t for t in entry.timestamps if t > window_start]

        if len(entry.timestamps) >= self._max_requests_per_minute:
            return False

        entry.timestamps.append(now)
        return True

    def _reject(
        self,
        reason: RejectionReason,
        detail: str,
        client_id: str,
        sample_dimensions: int,
        metadata: dict[str, Any] | None = None,
    ) -> SanitizationResult:
        """Record a rejection and return the result.

        Logs the rejection event for forensics and increments counters.

        Args:
            reason: Why the sample was rejected.
            detail: Human-readable detail for logging.
            client_id: The client that submitted the sample.
            sample_dimensions: Number of features in the rejected sample.
            metadata: Optional metadata from the request.

        Returns:
            SanitizationResult with is_valid=False.
        """
        self._total_rejected += 1

        event = RejectionEvent(
            timestamp=time.time(),
            client_id=client_id,
            reason=reason,
            detail=detail,
            sample_dimensions=sample_dimensions,
            metadata=metadata or {},
        )

        # Bounded log to prevent memory leak from sustained attacks
        if len(self._rejection_log) >= self._max_log_size:
            # Drop oldest 10% to avoid constant list reallocation
            drop_count = self._max_log_size // 10
            self._rejection_log = self._rejection_log[drop_count:]

        self._rejection_log.append(event)

        # Log for operational visibility (never log raw sample data)
        logger.warning(
            "Input rejected: reason=%s client=%s dims=%d detail=%s",
            reason.value,
            client_id,
            sample_dimensions,
            detail,
        )

        return SanitizationResult(
            is_valid=False,
            rejection_reason=reason,
            rejection_detail=detail,
        )

    def get_rejection_log(self, limit: int = 100) -> list[RejectionEvent]:
        """Get recent rejection events for forensic analysis.

        Args:
            limit: Maximum number of events to return.

        Returns:
            List of recent rejection events, newest first.
        """
        return list(reversed(self._rejection_log[-limit:]))

    def get_stats(self) -> dict[str, Any]:
        """Get sanitizer statistics.

        Returns:
            Dictionary with processing and rejection counts.
        """
        return {
            "total_processed": self._total_processed,
            "total_rejected": self._total_rejected,
            "rejection_rate": (
                self._total_rejected / self._total_processed
                if self._total_processed > 0
                else 0.0
            ),
            "active_clients": len(self._rate_state),
            "log_size": len(self._rejection_log),
        }

    def reset_rate_limits(self) -> None:
        """Clear all rate limit state.

        Use after a known state change or during testing.
        """
        self._rate_state.clear()

    @property
    def max_dimensions(self) -> int:
        """Maximum allowed feature dimensions."""
        return self._max_dimensions

    @property
    def value_bounds(self) -> tuple[float, float]:
        """Configured value range bounds (lower, upper)."""
        return (self._value_lower_bound, self._value_upper_bound)
