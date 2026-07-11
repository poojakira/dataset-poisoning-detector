"""Tests for the circuit breaker pattern implementation.

Verifies state transitions (CLOSED->OPEN, OPEN->HALF_OPEN->CLOSED),
failure threshold behavior, and force reset functionality.
"""

import time

from poison_detector.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerOpenError,
    CircuitState,
)


def test_opens_on_failure_threshold():
    """Circuit breaker transitions to OPEN after reaching failure_threshold failures."""
    config = CircuitBreakerConfig(
        name="test-breaker",
        failure_threshold=3,
        recovery_timeout=60.0,
        success_threshold=2,
    )
    breaker = CircuitBreaker(config)

    assert breaker.state == CircuitState.CLOSED

    # Record failures up to threshold
    breaker.record_failure()
    assert breaker.state == CircuitState.CLOSED

    breaker.record_failure()
    assert breaker.state == CircuitState.CLOSED

    breaker.record_failure()
    # Should now be OPEN (3 consecutive failures == threshold)
    assert breaker.state == CircuitState.OPEN

    # Verify stats reflect the failures
    stats = breaker.get_stats()
    assert stats.total_failures == 3
    assert stats.state == CircuitState.OPEN

    # Calls should be rejected while OPEN
    try:
        breaker.call(func=lambda: "should not run")
        assert False, "Expected CircuitBreakerOpenError"
    except CircuitBreakerOpenError:
        pass


def test_half_open_recovery():
    """After recovery_timeout, circuit transitions OPEN->HALF_OPEN->CLOSED on success."""
    config = CircuitBreakerConfig(
        name="test-recovery",
        failure_threshold=2,
        recovery_timeout=0.1,  # 100ms for fast test
        success_threshold=2,
    )
    breaker = CircuitBreaker(config)

    # Trip the breaker
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.state == CircuitState.OPEN

    # Wait for recovery timeout to expire
    time.sleep(0.15)

    # Accessing state should trigger transition to HALF_OPEN
    assert breaker.state == CircuitState.HALF_OPEN

    # One success is not enough (success_threshold=2)
    breaker.record_success()
    assert breaker.state == CircuitState.HALF_OPEN

    # Second success should close the circuit
    breaker.record_success()
    assert breaker.state == CircuitState.CLOSED

    # Verify the breaker is fully functional again
    result = breaker.call(func=lambda: "works")
    assert result == "works"


def test_force_reset():
    """reset() returns the circuit breaker to CLOSED from any state."""
    config = CircuitBreakerConfig(
        name="test-reset",
        failure_threshold=2,
        recovery_timeout=60.0,
        success_threshold=2,
    )
    breaker = CircuitBreaker(config)

    # Trip to OPEN
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.state == CircuitState.OPEN

    # Force reset
    breaker.reset()
    assert breaker.state == CircuitState.CLOSED

    # Should work normally after reset
    result = breaker.call(func=lambda: 42)
    assert result == 42

    # Trip again and verify reset works from any state
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.state == CircuitState.OPEN

    breaker.reset()
    assert breaker.state == CircuitState.CLOSED

    # Verify failure counters are also reset
    stats = breaker.get_stats()
    assert stats.consecutive_failures == 0
