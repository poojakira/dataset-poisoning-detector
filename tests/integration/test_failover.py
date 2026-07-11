"""
Failover and graceful degradation integration tests.

Tests that the system degrades gracefully when external dependencies
(Redis, downstream services) are unavailable, continuing to provide
core functionality via in-memory fallbacks and circuit breaker patterns.
"""

from __future__ import annotations

import pytest

from poison_detector.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerOpenError,
    CircuitState,
)
from poison_detector.rate_limiter import SlidingWindowRateLimiter


class TestRateLimiterDegradesWithoutRedis:
    """Verify that the sliding window rate limiter falls back to in-memory
    operation when Redis is unavailable, and still correctly enforces limits."""

    def test_rate_limiter_degrades_without_redis(self) -> None:
        """Create a SlidingWindowRateLimiter with no Redis connection and verify
        it falls back to in-memory operation while still rate-limiting correctly."""
        # Create limiter with no Redis (empty URL)
        limiter = SlidingWindowRateLimiter(
            redis_url="",
            max_requests=5,
            window_seconds=60.0,
        )

        # Verify Redis is not available
        assert not limiter.is_redis_available, "Redis should not be available"

        # First 5 requests should be allowed (using in-memory fallback)
        for i in range(5):
            result = limiter.check(f"client-test")
            assert result.allowed, f"Request {i+1} should be allowed"
            assert result.using_fallback, "Should be using in-memory fallback"
            assert result.remaining == 5 - i - 1, f"Remaining should be {5 - i - 1}"

        # 6th request should be denied
        result = limiter.check("client-test")
        assert not result.allowed, "6th request should be denied (rate limited)"
        assert result.using_fallback, "Should still be using in-memory fallback"
        assert result.remaining == 0
        assert result.retry_after > 0, "Should report retry_after > 0"

        # Different client should still be allowed
        result = limiter.check("different-client")
        assert result.allowed, "Different client should not be affected"
        assert result.using_fallback

    def test_rate_limiter_invalid_redis_url_degrades(self) -> None:
        """A limiter configured with an invalid Redis URL should gracefully
        fall back to in-memory limiting without raising an exception."""
        # Provide an unreachable Redis URL
        limiter = SlidingWindowRateLimiter(
            redis_url="redis://localhost:59999",  # Non-existent port
            max_requests=3,
            window_seconds=10.0,
        )

        # Should have failed to connect and fallen back
        assert not limiter.is_redis_available

        # Should still function with in-memory fallback
        result = limiter.check("client-abc")
        assert result.allowed
        assert result.using_fallback


class TestCircuitBreakerReturnsDegradedOnOpen:
    """Verify that when a circuit breaker is forced open by triggering
    failures, subsequent calls either raise CircuitBreakerOpenError
    or return the fallback value, rather than silently failing."""

    def test_circuit_breaker_returns_degraded_on_open(self) -> None:
        """Force the circuit breaker open by triggering failures, then verify
        that calling through it raises CircuitBreakerOpenError when no fallback
        is provided."""
        breaker = CircuitBreaker(
            CircuitBreakerConfig(
                name="test-breaker",
                failure_threshold=3,
                recovery_timeout=60.0,  # Long timeout so it stays open
                success_threshold=2,
            )
        )

        # Initially the circuit should be closed
        assert breaker.state == CircuitState.CLOSED

        # Trigger failures to trip the breaker
        for _ in range(3):
            breaker.record_failure()

        # Circuit should now be OPEN
        assert breaker.state == CircuitState.OPEN

        # Calling without a fallback should raise CircuitBreakerOpenError
        with pytest.raises(CircuitBreakerOpenError) as exc_info:
            breaker.call(func=lambda: "should not execute")

        assert "test-breaker" in str(exc_info.value)
        assert "OPEN" in str(exc_info.value)

        # Verify stats reflect the state
        stats = breaker.get_stats()
        assert stats.state == CircuitState.OPEN
        assert stats.consecutive_failures == 3
        assert stats.total_failures == 3

    def test_circuit_breaker_returns_fallback_on_open(self) -> None:
        """When the circuit is open and a fallback is provided, the fallback
        is invoked instead of the protected function."""
        breaker = CircuitBreaker(
            CircuitBreakerConfig(
                name="fallback-breaker",
                failure_threshold=2,
                recovery_timeout=60.0,
                success_threshold=1,
            )
        )

        # Trip the breaker
        for _ in range(2):
            breaker.record_failure()

        assert breaker.state == CircuitState.OPEN

        # Track whether the primary function was called
        primary_called = False

        def primary_func():
            nonlocal primary_called
            primary_called = True
            return "primary_result"

        def fallback_func():
            return "degraded_result"

        # Call with fallback
        result = breaker.call(func=primary_func, fallback=fallback_func)

        # Primary should NOT have been called
        assert not primary_called, "Primary function should not execute when circuit is open"
        # Should get the fallback result
        assert result == "degraded_result"

    def test_circuit_breaker_reopens_on_half_open_failure(self) -> None:
        """When the circuit is in HALF_OPEN state and a call fails,
        it should immediately transition back to OPEN."""
        breaker = CircuitBreaker(
            CircuitBreakerConfig(
                name="half-open-breaker",
                failure_threshold=2,
                recovery_timeout=0.01,  # Very short so it moves to HALF_OPEN quickly
                success_threshold=2,
            )
        )

        # Trip the breaker
        for _ in range(2):
            breaker.record_failure()

        assert breaker.state == CircuitState.OPEN

        # Wait for recovery timeout to expire (moves to HALF_OPEN)
        import time
        time.sleep(0.02)

        # Accessing state should trigger OPEN -> HALF_OPEN transition
        assert breaker.state == CircuitState.HALF_OPEN

        # A failure in HALF_OPEN should reopen the circuit
        breaker.record_failure()
        assert breaker.state == CircuitState.OPEN
