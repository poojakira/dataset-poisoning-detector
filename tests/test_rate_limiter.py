"""Tests for rate limiting implementations.

Verifies sliding window blocking, token bucket refill behavior,
and graceful in-memory fallback when Redis is unavailable.
"""

import time

from poison_detector.rate_limiter import (
    SlidingWindowRateLimiter,
    TokenBucketRateLimiter,
)


def test_sliding_window_blocks_after_limit():
    """SlidingWindowRateLimiter blocks requests after max_requests is reached."""
    limiter = SlidingWindowRateLimiter(
        redis_url="",  # No Redis, use in-memory
        max_requests=5,
        window_seconds=60.0,
    )

    # Make max_requests calls -- all should be allowed
    for i in range(5):
        result = limiter.check("client-1")
        assert result.allowed is True, f"Request {i+1} should be allowed"
        assert result.remaining == 5 - i - 1

    # Next request should be blocked
    result = limiter.check("client-1")
    assert result.allowed is False
    assert result.remaining == 0
    assert result.retry_after > 0

    # A different client should still be allowed
    result = limiter.check("client-2")
    assert result.allowed is True


def test_token_bucket_refills():
    """TokenBucketRateLimiter refills tokens after time elapses."""
    limiter = TokenBucketRateLimiter(
        max_tokens=3,
        refill_rate=100.0,  # 100 tokens/second = fast refill for test
        redis_url="",  # No Redis
    )

    # Exhaust all tokens
    for _ in range(3):
        result = limiter.consume("client-1")
        assert result.allowed is True

    # Bucket should be empty
    result = limiter.consume("client-1")
    assert result.allowed is False
    assert result.retry_after > 0

    # Wait for refill (at 100 tokens/s, 1 token takes 0.01s)
    time.sleep(0.05)

    # Should have refilled some tokens
    result = limiter.consume("client-1")
    assert result.allowed is True


def test_fallback_without_redis():
    """Rate limiter operates in-memory when Redis is unavailable."""
    # Try to connect to a non-existent Redis instance
    limiter = SlidingWindowRateLimiter(
        redis_url="redis://localhost:59999",  # Non-existent port
        max_requests=10,
        window_seconds=60.0,
    )

    # Should fall back to in-memory
    assert limiter.is_redis_available is False

    # In-memory rate limiting should still work
    result = limiter.check("client-fallback")
    assert result.allowed is True
    assert result.using_fallback is True

    # Fill up to the limit
    for _ in range(9):
        result = limiter.check("client-fallback")

    # Should be blocked at limit
    result = limiter.check("client-fallback")
    assert result.allowed is False
    assert result.using_fallback is True
