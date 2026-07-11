"""
Circuit breaker pattern for resilient poisoning detection.

Implements the circuit breaker pattern to prevent cascading failures when
downstream dependencies (IsolationForest, Redis, Kafka, external services)
become unhealthy. Rather than repeatedly calling a failing service and
accumulating timeouts, the circuit breaker fails fast and returns degraded
results while allowing the service time to recover.

Threat Model Assumptions:
    - Downstream services (Redis, Kafka, sklearn) may fail due to resource
      exhaustion, bugs, or deliberate attack (e.g., an attacker flooding
      Redis to degrade detection capabilities).
    - When the circuit is OPEN, the detector operates in degraded mode
      (statistical-only scoring without IsolationForest). This is a known
      reduction in detection capability that must be monitored and alerted.
    - An attacker who can trigger circuit breaker opening (by causing
      repeated downstream failures) gains a window of reduced detection.
      The half-open recovery mechanism limits this window.

Honest Limitations:
    - Circuit breaker state is per-process. In a multi-replica deployment,
      each replica has independent breaker state. One replica may have an
      open circuit while another is closed. This is acceptable because
      failures are typically visible to all replicas simultaneously.
    - The failure threshold is a simple count, not a rate. A burst of failures
      followed by many successes still trips the breaker. For rate-based
      detection, use a time-windowed failure rate instead.
    - Recovery testing in HALF_OPEN state sends real requests to the
      downstream service. If the service is still unhealthy, this adds
      one more failed request per recovery_timeout interval.
    - Thread safety uses simple locking. Under extreme contention (thousands
      of concurrent calls), lock contention may add microseconds of latency.

Security Notes:
    - Circuit breaker metrics expose service health state. Metrics endpoints
      should be on internal networks to avoid revealing when the system is
      in degraded mode (which an attacker could exploit).
    - The fallback/degraded response must be clearly marked as degraded in
      its output so consumers do not treat it as a full-confidence result.
    - State transitions are logged at WARNING level for operational visibility.
      Logs should be monitored for unexpected circuit openings.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, TypeVar, Generic

from prometheus_client import Counter, Gauge, Histogram

logger = logging.getLogger(__name__)


# --- Prometheus Metrics ---
# Following patterns from metrics.py: module-level definitions with labelnames.

CIRCUIT_STATE_TRANSITIONS = Counter(
    "poison_detector_circuit_breaker_transitions_total",
    "Total circuit breaker state transitions",
    labelnames=["breaker_name", "from_state", "to_state"],
)

CIRCUIT_CURRENT_STATE = Gauge(
    "poison_detector_circuit_breaker_state",
    "Current circuit breaker state (0=closed, 1=open, 2=half_open)",
    labelnames=["breaker_name"],
)

CIRCUIT_FAILURE_COUNT = Gauge(
    "poison_detector_circuit_breaker_failures",
    "Current consecutive failure count for each breaker",
    labelnames=["breaker_name"],
)

CIRCUIT_CALL_DURATION = Histogram(
    "poison_detector_circuit_breaker_call_seconds",
    "Duration of calls through the circuit breaker",
    labelnames=["breaker_name", "outcome"],
    buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)


class CircuitState(Enum):
    """Circuit breaker states.

    CLOSED: Normal operation. Calls pass through to the downstream service.
    OPEN: Service is failing. Calls return the fallback immediately.
    HALF_OPEN: Testing recovery. Limited calls are allowed through.
    """

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    @property
    def metric_value(self) -> int:
        """Numeric value for Prometheus gauge."""
        return {"closed": 0, "open": 1, "half_open": 2}[self.value]


@dataclass
class CircuitBreakerConfig:
    """Configuration for a circuit breaker instance.

    Attributes:
        failure_threshold: Number of consecutive failures to trip the breaker.
        recovery_timeout: Seconds to wait in OPEN state before testing recovery.
        success_threshold: Consecutive successes in HALF_OPEN to close the circuit.
        name: Identifier for this breaker (used in metrics and logging).
    """

    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    success_threshold: int = 3
    name: str = "default"

    def __post_init__(self) -> None:
        if self.failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if self.recovery_timeout <= 0:
            raise ValueError("recovery_timeout must be > 0")
        if self.success_threshold < 1:
            raise ValueError("success_threshold must be >= 1")


@dataclass
class CircuitBreakerStats:
    """Runtime statistics for a circuit breaker.

    Attributes:
        state: Current state of the breaker.
        consecutive_failures: Current failure streak.
        consecutive_successes: Current success streak (in HALF_OPEN).
        total_calls: Total number of calls attempted.
        total_failures: Total number of failures recorded.
        total_successes: Total number of successes recorded.
        total_rejected: Total calls rejected (returned fallback while OPEN).
        last_failure_time: Unix timestamp of the most recent failure.
        last_success_time: Unix timestamp of the most recent success.
        last_state_change: Unix timestamp of the last state transition.
    """

    state: CircuitState = CircuitState.CLOSED
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    total_calls: int = 0
    total_failures: int = 0
    total_successes: int = 0
    total_rejected: int = 0
    last_failure_time: float = 0.0
    last_success_time: float = 0.0
    last_state_change: float = 0.0


T = TypeVar("T")


class CircuitBreaker:
    """Circuit breaker for protecting downstream service calls.

    Implements the three-state circuit breaker pattern:
        CLOSED -> (failure_threshold failures) -> OPEN
        OPEN -> (recovery_timeout expires) -> HALF_OPEN
        HALF_OPEN -> (success_threshold successes) -> CLOSED
        HALF_OPEN -> (any failure) -> OPEN

    Usage:
        breaker = CircuitBreaker(CircuitBreakerConfig(
            name="isolation_forest",
            failure_threshold=3,
            recovery_timeout=60.0,
            success_threshold=2,
        ))

        # Using call() with a callable
        result = breaker.call(
            func=lambda: model.predict(sample),
            fallback=lambda: degraded_score(sample),
        )

        # Manual recording (for async or complex flows)
        try:
            result = await async_redis_call()
            breaker.record_success()
        except Exception:
            breaker.record_failure()
            result = fallback_value
    """

    def __init__(self, config: CircuitBreakerConfig | None = None) -> None:
        """Initialize the circuit breaker.

        Args:
            config: Configuration for thresholds and timing.
                Defaults to CircuitBreakerConfig() if not provided.
        """
        self._config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._consecutive_successes = 0
        self._total_calls = 0
        self._total_failures = 0
        self._total_successes = 0
        self._total_rejected = 0
        self._last_failure_time: float = 0.0
        self._last_success_time: float = 0.0
        self._last_state_change: float = time.time()
        self._lock = threading.Lock()

        # Initialize Prometheus metrics
        CIRCUIT_CURRENT_STATE.labels(breaker_name=self._config.name).set(
            self._state.metric_value
        )
        CIRCUIT_FAILURE_COUNT.labels(breaker_name=self._config.name).set(0)

    @property
    def state(self) -> CircuitState:
        """Current state of the circuit breaker."""
        with self._lock:
            # Check if OPEN -> HALF_OPEN transition is due
            if self._state == CircuitState.OPEN:
                elapsed = time.time() - self._last_failure_time
                if elapsed >= self._config.recovery_timeout:
                    self._transition_to(CircuitState.HALF_OPEN)
            return self._state

    @property
    def name(self) -> str:
        """Name of this circuit breaker."""
        return self._config.name

    def call(
        self,
        func: Callable[[], T],
        fallback: Callable[[], T] | None = None,
    ) -> T:
        """Execute a function through the circuit breaker.

        If the circuit is CLOSED or HALF_OPEN, the function is called.
        If the circuit is OPEN, the fallback is called immediately without
        attempting the function.

        Args:
            func: The function to call (the protected operation).
            fallback: Function to call when the circuit is OPEN.
                If None, raises CircuitBreakerOpenError.

        Returns:
            Result from func (if circuit allows) or from fallback (if OPEN).

        Raises:
            CircuitBreakerOpenError: If the circuit is OPEN and no fallback
                is provided.
            Exception: Any exception raised by func is re-raised after
                recording the failure.
        """
        current_state = self.state

        if current_state == CircuitState.OPEN:
            self._total_rejected += 1
            if fallback is not None:
                logger.debug(
                    "Circuit '%s' is OPEN, returning fallback",
                    self._config.name,
                )
                return fallback()
            raise CircuitBreakerOpenError(
                f"Circuit breaker '{self._config.name}' is OPEN. "
                f"Service unavailable, try again after "
                f"{self._config.recovery_timeout}s."
            )

        # Circuit is CLOSED or HALF_OPEN -- attempt the call
        start = time.perf_counter()
        try:
            result = func()
            elapsed = time.perf_counter() - start
            CIRCUIT_CALL_DURATION.labels(
                breaker_name=self._config.name,
                outcome="success",
            ).observe(elapsed)
            self.record_success()
            return result
        except Exception as e:
            elapsed = time.perf_counter() - start
            CIRCUIT_CALL_DURATION.labels(
                breaker_name=self._config.name,
                outcome="failure",
            ).observe(elapsed)
            self.record_failure()
            raise

    def record_success(self) -> None:
        """Record a successful call to the downstream service.

        In HALF_OPEN state, consecutive successes move toward CLOSED.
        In CLOSED state, resets the failure counter.
        """
        with self._lock:
            self._total_calls += 1
            self._total_successes += 1
            self._last_success_time = time.time()
            self._consecutive_failures = 0
            self._consecutive_successes += 1

            if self._state == CircuitState.HALF_OPEN:
                if self._consecutive_successes >= self._config.success_threshold:
                    self._transition_to(CircuitState.CLOSED)

            CIRCUIT_FAILURE_COUNT.labels(
                breaker_name=self._config.name
            ).set(self._consecutive_failures)

    def record_failure(self) -> None:
        """Record a failed call to the downstream service.

        Increments the failure counter. If the threshold is reached,
        transitions to OPEN state.
        """
        with self._lock:
            self._total_calls += 1
            self._total_failures += 1
            self._last_failure_time = time.time()
            self._consecutive_failures += 1
            self._consecutive_successes = 0

            CIRCUIT_FAILURE_COUNT.labels(
                breaker_name=self._config.name
            ).set(self._consecutive_failures)

            if self._state == CircuitState.HALF_OPEN:
                # Any failure in HALF_OPEN immediately reopens
                self._transition_to(CircuitState.OPEN)
            elif self._state == CircuitState.CLOSED:
                if self._consecutive_failures >= self._config.failure_threshold:
                    self._transition_to(CircuitState.OPEN)

    def reset(self) -> None:
        """Manually reset the circuit breaker to CLOSED state.

        Use for testing or after a known service recovery.
        """
        with self._lock:
            self._transition_to(CircuitState.CLOSED)
            self._consecutive_failures = 0
            self._consecutive_successes = 0
            CIRCUIT_FAILURE_COUNT.labels(
                breaker_name=self._config.name
            ).set(0)

    def get_stats(self) -> CircuitBreakerStats:
        """Get current circuit breaker statistics.

        Returns:
            CircuitBreakerStats with current state and counters.
        """
        with self._lock:
            return CircuitBreakerStats(
                state=self._state,
                consecutive_failures=self._consecutive_failures,
                consecutive_successes=self._consecutive_successes,
                total_calls=self._total_calls,
                total_failures=self._total_failures,
                total_successes=self._total_successes,
                total_rejected=self._total_rejected,
                last_failure_time=self._last_failure_time,
                last_success_time=self._last_success_time,
                last_state_change=self._last_state_change,
            )

    def _transition_to(self, new_state: CircuitState) -> None:
        """Transition to a new state and emit metrics.

        Must be called while holding self._lock.

        Args:
            new_state: The state to transition to.
        """
        old_state = self._state
        if old_state == new_state:
            return

        self._state = new_state
        self._last_state_change = time.time()

        # Reset consecutive counters on state change
        if new_state == CircuitState.CLOSED:
            self._consecutive_failures = 0
            self._consecutive_successes = 0
        elif new_state == CircuitState.HALF_OPEN:
            self._consecutive_successes = 0

        # Emit Prometheus metrics
        CIRCUIT_STATE_TRANSITIONS.labels(
            breaker_name=self._config.name,
            from_state=old_state.value,
            to_state=new_state.value,
        ).inc()

        CIRCUIT_CURRENT_STATE.labels(
            breaker_name=self._config.name
        ).set(new_state.metric_value)

        logger.warning(
            "Circuit breaker '%s' state transition: %s -> %s",
            self._config.name,
            old_state.value,
            new_state.value,
        )


class CircuitBreakerOpenError(Exception):
    """Raised when a call is attempted on an OPEN circuit breaker.

    This exception indicates the downstream service is unavailable and
    the circuit breaker is protecting it from further load. The caller
    should use a fallback or retry after the recovery_timeout.
    """

    pass


# --- Convenience factory for common breakers ---


def create_breaker_set() -> dict[str, CircuitBreaker]:
    """Create a standard set of circuit breakers for the detection pipeline.

    Returns breakers pre-configured for the common downstream services:
        - isolation_forest: ML model calls (fast failure, quick recovery)
        - redis: Cache/rate-limit store (moderate tolerance)
        - kafka: Message queue (high tolerance, slow recovery)
        - external: External APIs (conservative thresholds)

    Returns:
        Dictionary mapping service names to configured CircuitBreaker instances.

    Usage:
        breakers = create_breaker_set()
        result = breakers["isolation_forest"].call(
            func=lambda: model.predict(sample),
            fallback=lambda: statistical_only_score(sample),
        )
    """
    return {
        "isolation_forest": CircuitBreaker(CircuitBreakerConfig(
            name="isolation_forest",
            failure_threshold=3,
            recovery_timeout=10.0,
            success_threshold=2,
        )),
        "redis": CircuitBreaker(CircuitBreakerConfig(
            name="redis",
            failure_threshold=5,
            recovery_timeout=30.0,
            success_threshold=3,
        )),
        "kafka": CircuitBreaker(CircuitBreakerConfig(
            name="kafka",
            failure_threshold=10,
            recovery_timeout=60.0,
            success_threshold=5,
        )),
        "external": CircuitBreaker(CircuitBreakerConfig(
            name="external",
            failure_threshold=3,
            recovery_timeout=120.0,
            success_threshold=3,
        )),
    }
