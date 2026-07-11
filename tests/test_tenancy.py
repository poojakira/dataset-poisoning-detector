"""Tests for multi-tenant isolation (baselines, quarantine, rate limits)."""

import numpy as np
import pytest

from poison_detector.storage import ResolutionStatus, SQLiteStore
from poison_detector.tenancy import (
    TenantConfig,
    TenantManager,
    TenantQuarantine,
    validate_tenant_id,
)


def test_validate_tenant_id():
    assert validate_tenant_id("acme-1") == "acme-1"
    for bad in ["", "a" * 200, "has space", "drop;table", 123]:
        with pytest.raises(ValueError):
            validate_tenant_id(bad)  # type: ignore[arg-type]


def test_baseline_isolation_between_tenants():
    """A baseline established for one tenant must not affect another's scoring."""
    mgr = TenantManager(default_config=TenantConfig(window_size=1000, vote_threshold=1))

    rng = np.random.default_rng(0)
    # Tenant A lives near 0; tenant B lives near 100.
    a_clean = rng.normal(0.0, 1.0, size=(200, 4)).tolist()
    b_clean = rng.normal(100.0, 1.0, size=(200, 4)).tolist()
    mgr.update_baseline("tenant-a", a_clean)
    mgr.update_baseline("tenant-b", b_clean)

    # A sample normal for B (near 100) must look highly anomalous to A's detector.
    sample_b = [100.0, 100.0, 100.0, 100.0]
    res_a = mgr.score("tenant-a", sample_b)
    res_b = mgr.score("tenant-b", sample_b)
    assert res_a.is_poisoned is True
    assert res_b.is_poisoned is False
    # Distinct detector instances.
    assert mgr._get_detector("tenant-a") is not mgr._get_detector("tenant-b")


def test_active_tenants_and_eviction():
    mgr = TenantManager()
    mgr.score("t1", [1.0, 2.0])
    mgr.score("t2", [3.0, 4.0])
    assert set(mgr.active_tenants()) == {"t1", "t2"}
    assert mgr.evict_tenant("t1") is True
    assert mgr.active_tenants() == ["t2"]
    assert mgr.evict_tenant("nope") is False


def test_per_tenant_rate_limit_quota():
    mgr = TenantManager(
        default_config=TenantConfig(max_requests=3, window_seconds=60.0)
    )
    # First 3 allowed, 4th denied -- and this budget is per-tenant.
    assert all(mgr.allow_request("t1").allowed for _ in range(3))
    assert mgr.allow_request("t1").allowed is False
    # A different tenant has its own budget.
    assert mgr.allow_request("t2").allowed is True


def test_tenant_config_override():
    mgr = TenantManager(default_config=TenantConfig(window_size=100))
    mgr.set_tenant_config("big", TenantConfig(window_size=9999))
    det = mgr._get_detector("big")
    assert det.window_size == 9999


def test_quarantine_namespacing_and_scoped_reads():
    store = SQLiteStore(":memory:")
    tq = TenantQuarantine(store)

    id_a = tq.store_sample("tenant-a", [1.0, 2.0], {"iso": 0.9}, source="pipe")
    tq.store_sample("tenant-b", [3.0, 4.0], {"iso": 0.8})

    # Each tenant only sees its own pending reviews.
    pending_a = tq.get_pending_reviews("tenant-a")
    assert len(pending_a) == 1
    assert pending_a[0].metadata["tenant_id"] == "tenant-a"
    assert pending_a[0].source.startswith("tenant-a")

    pending_b = tq.get_pending_reviews("tenant-b")
    assert len(pending_b) == 1
    assert pending_b[0].metadata["tenant_id"] == "tenant-b"

    # Tenant B cannot resolve tenant A's entry.
    assert tq.resolve("tenant-b", id_a, ResolutionStatus.FALSE_POSITIVE) is False
    # Tenant A can.
    assert tq.resolve("tenant-a", id_a, ResolutionStatus.CONFIRMED_POISON, "alice") is True
    store.close()


def test_tenant_manager_get_stats():
    mgr = TenantManager()
    mgr.score("t1", [1.0, 2.0, 3.0])
    stats = mgr.get_stats("t1")
    assert stats.samples_seen == 1
