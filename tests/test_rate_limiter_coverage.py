"""Coverage tests for the in-memory fallback paths of the rate limiters.

Redis is not reachable in this environment, so these tests drive the
in-memory SlidingWindow / TokenBucket / Composite code paths that the service
falls back to. They verify limit enforcement, refill behavior, reset, usage
accounting, key sanitization, validation, and memory-bound eviction.
"""

import time

import pytest

from poison_detector.rate_limiter import (
    CompositeRateLimiter,
    RateLimitResult,
    SlidingWindowRateLimiter,
    TokenBucketRateLimiter,
)


# --------------------------------------------------------------------------
# Construction validation
# --------------------------------------------------------------------------


def test_sliding_window_validates_arguments():
    """SlidingWindowRateLimiter rejects non-positive limits/windows."""
    with pytest.raises(ValueError):
        SlidingWindowRateLimiter(max_requests=0)
    with pytest.raises(ValueError):
        SlidingWindowRateLimiter(window_seconds=0)


def test_token_bucket_validates_arguments():
    """TokenBucketRateLimiter rejects non-positive capacity/refill."""
    with pytest.raises(ValueError):
        TokenBucketRateLimiter(max_tokens=0)
    with pytest.raises(ValueError):
        TokenBucketRateLimiter(refill_rate=0)


# --------------------------------------------------------------------------
# Sliding window in-memory behavior
# --------------------------------------------------------------------------


def test_sliding_window_usage_reset_and_properties():
    """get_usage tracks the window count; reset clears it; properties expose config."""
    limiter = SlidingWindowRateLimiter(redis_url="", max_requests=3, window_seconds=60.0)
    assert limiter.max_requests == 3
    assert limiter.window_seconds == 60.0
    assert limiter.is_redis_available is False
    assert limiter.get_usage("client") == 0

    limiter.check("client")
    limiter.check("client")
    assert limiter.get_usage("client") == 2

    limiter.reset("client")
    assert limiter.get_usage("client") == 0


def test_sliding_window_retry_after_reflects_oldest_entry():
    """When blocked, retry_after is derived from the oldest in-window request."""
    limiter = SlidingWindowRateLimiter(redis_url="", max_requests=2, window_seconds=30.0)
    limiter.check("c")
    limiter.check("c")
    blocked = limiter.check("c")
    assert blocked.allowed is False
    assert blocked.remaining == 0
    assert 0 < blocked.retry_after <= 30.0
    assert blocked.using_fallback is True


def test_sliding_window_key_sanitization_long_and_empty():
    """Oversized keys are hashed; empty keys map to a stable placeholder."""
    limiter = SlidingWindowRateLimiter(redis_url="", max_requests=5, window_seconds=60.0)
    long_key = "k" * 500
    r = limiter.check(long_key)
    assert r.allowed is True
    # Empty key still tracked under the "empty" placeholder
    r2 = limiter.check("")
    assert r2.allowed is True
    assert limiter.get_usage("") == 1


def test_sliding_window_memory_eviction():
    """When key count hits the bound, the oldest key is evicted."""
    limiter = SlidingWindowRateLimiter(redis_url="", max_requests=5, window_seconds=60.0)
    limiter._max_memory_keys = 3
    for i in range(3):
        limiter.check(f"client-{i}")
    assert len(limiter._memory_store) == 3
    # Adding a 4th unique key triggers eviction of the oldest
    limiter.check("client-new")
    assert len(limiter._memory_store) == 3


# --------------------------------------------------------------------------
# Token bucket in-memory behavior
# --------------------------------------------------------------------------


def test_token_bucket_blocks_then_refills_with_retry_after():
    """Bucket empties, reports retry_after, then refills over time."""
    limiter = TokenBucketRateLimiter(max_tokens=2, refill_rate=50.0, redis_url="")
    assert limiter.max_tokens == 2
    assert limiter.refill_rate == 50.0
    assert limiter.is_redis_available is False

    assert limiter.consume("c").allowed is True
    assert limiter.consume("c").allowed is True
    blocked = limiter.consume("c")
    assert blocked.allowed is False
    assert blocked.retry_after > 0
    assert blocked.using_fallback is True

    time.sleep(0.05)  # 50 tokens/s -> refills quickly
    assert limiter.consume("c").allowed is True


def test_token_bucket_multi_token_consume():
    """Consuming more tokens than available in one call is denied."""
    limiter = TokenBucketRateLimiter(max_tokens=5, refill_rate=1.0, redis_url="")
    ok = limiter.consume("c", tokens=5)
    assert ok.allowed is True
    denied = limiter.consume("c", tokens=3)
    assert denied.allowed is False
    assert denied.remaining < 3


def test_token_bucket_reset_and_eviction():
    """reset refills a bucket; memory bound evicts the least-recently-used key."""
    limiter = TokenBucketRateLimiter(max_tokens=1, refill_rate=1.0, redis_url="")
    limiter.consume("c")
    assert limiter.consume("c").allowed is False
    limiter.reset("c")
    assert limiter.consume("c").allowed is True

    limiter._max_memory_keys = 2
    limiter.consume("a")
    limiter.consume("b")
    assert len(limiter._buckets) <= 2
    limiter.consume("d")  # triggers LRU eviction
    assert len(limiter._buckets) <= 2


# --------------------------------------------------------------------------
# Composite limiter
# --------------------------------------------------------------------------


def test_composite_returns_first_denial():
    """CompositeRateLimiter denies as soon as any sub-limiter denies."""
    composite = CompositeRateLimiter(
        limiters={
            "per_key": SlidingWindowRateLimiter(redis_url="", max_requests=1, window_seconds=60.0),
            "burst": TokenBucketRateLimiter(max_tokens=10, refill_rate=5.0, redis_url=""),
        }
    )
    keys = {"per_key": "api_key:abc", "burst": "api_key:abc"}

    first = composite.check_all(keys)
    assert first.allowed is True

    second = composite.check_all(keys)  # per_key now exhausted
    assert second.allowed is False


def test_composite_tracks_most_restrictive_when_all_allow():
    """When every limiter allows, the most restrictive (lowest remaining) wins."""
    composite = CompositeRateLimiter(
        limiters={
            "small": SlidingWindowRateLimiter(redis_url="", max_requests=3, window_seconds=60.0),
            "large": SlidingWindowRateLimiter(redis_url="", max_requests=100, window_seconds=60.0),
        }
    )
    result = composite.check_all({"small": "k", "large": "k"})
    assert result.allowed is True
    assert result.remaining == 2  # from the small limiter


def test_composite_ignores_unknown_and_missing_keys():
    """Keys with no matching limiter are skipped; unmatched limiters are ignored."""
    composite = CompositeRateLimiter(
        limiters={"per_key": SlidingWindowRateLimiter(redis_url="", max_requests=5, window_seconds=60.0)}
    )
    # "unknown" has no limiter; "per_key" limiter has a key -> allowed
    result = composite.check_all({"unknown": "x", "per_key": "k"})
    assert result.allowed is True


def test_composite_empty_keys_returns_allow():
    """With no applicable checks the composite defaults to allow."""
    composite = CompositeRateLimiter(limiters={})
    result = composite.check_all({})
    assert isinstance(result, RateLimitResult)
    assert result.allowed is True
