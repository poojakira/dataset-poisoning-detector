"""Coverage tests for InputSanitizer rejection paths and bookkeeping.

Covers empty samples, value-out-of-range, non-numeric conversion failures,
per-client rate limiting, the forensic rejection log, statistics, rate-limit
reset, construction validation, and exposed properties.
"""

import numpy as np
import pytest

from poison_detector.input_sanitizer import (
    InputSanitizer,
    RejectionReason,
)


def test_constructor_validation():
    """Invalid bound configurations are rejected at construction."""
    with pytest.raises(ValueError):
        InputSanitizer(min_dimensions=0)
    with pytest.raises(ValueError):
        InputSanitizer(max_dimensions=2, min_dimensions=5)
    with pytest.raises(ValueError):
        InputSanitizer(value_lower_bound=10.0, value_upper_bound=1.0)


def test_empty_sample_rejected():
    """An empty feature vector is rejected as EMPTY_SAMPLE."""
    s = InputSanitizer(enable_rate_limiting=False)
    result = s.sanitize([], client_id="c")
    assert result.is_valid is False
    assert result.rejection_reason == RejectionReason.EMPTY_SAMPLE


def test_value_out_of_range_rejected():
    """Values outside [lower, upper] are rejected as VALUE_OUT_OF_RANGE."""
    s = InputSanitizer(
        value_lower_bound=-100.0, value_upper_bound=100.0, enable_rate_limiting=False
    )
    result = s.sanitize([1.0, 2.0, 1e6], client_id="c")
    assert result.is_valid is False
    assert result.rejection_reason == RejectionReason.VALUE_OUT_OF_RANGE
    assert "range" in result.rejection_detail


def test_non_numeric_conversion_failure():
    """A sample that cannot be coerced to float64 is rejected."""
    s = InputSanitizer(enable_rate_limiting=False)
    result = s.sanitize(["a", "b", "c"], client_id="c")  # type: ignore[list-item]
    assert result.is_valid is False
    assert result.rejection_reason == RejectionReason.NAN_VALUES


def test_valid_numpy_array_accepted():
    """A clean numpy array passes and is returned as float64."""
    s = InputSanitizer(enable_rate_limiting=False)
    result = s.sanitize(np.array([1.0, 2.0, 3.0]), client_id="c")
    assert result.is_valid is True
    assert result.sanitized_sample.dtype == np.float64


def test_rate_limiting_rejects_excess_requests():
    """Per-client rate limiting rejects once the per-minute quota is exceeded."""
    s = InputSanitizer(max_requests_per_minute=3, enable_rate_limiting=True)
    for _ in range(3):
        assert s.sanitize([1.0, 2.0], client_id="rl").is_valid is True
    blocked = s.sanitize([1.0, 2.0], client_id="rl")
    assert blocked.is_valid is False
    assert blocked.rejection_reason == RejectionReason.RATE_LIMITED

    # A different client is unaffected
    assert s.sanitize([1.0], client_id="other").is_valid is True


def test_rejection_log_and_stats_and_reset():
    """The forensic log records rejections; stats aggregate; reset clears rate state."""
    s = InputSanitizer(max_dimensions=5, enable_rate_limiting=True, max_requests_per_minute=100)
    s.sanitize([float("nan"), 1.0], client_id="c1")
    s.sanitize([1.0] * 50, client_id="c2")  # exceeds max_dimensions

    log = s.get_rejection_log(limit=10)
    assert len(log) == 2
    # newest first
    reasons = [e.reason for e in log]
    assert RejectionReason.EXCEEDS_MAX_DIMENSIONS in reasons
    assert RejectionReason.NAN_VALUES in reasons

    stats = s.get_stats()
    assert stats["total_processed"] == 2
    assert stats["total_rejected"] == 2
    assert stats["rejection_rate"] == 1.0
    assert stats["active_clients"] >= 1

    s.reset_rate_limits()
    assert s.get_stats()["active_clients"] == 0


def test_stats_empty_sanitizer():
    """A fresh sanitizer reports a zero rejection rate (no division error)."""
    s = InputSanitizer(enable_rate_limiting=False)
    assert s.get_stats()["rejection_rate"] == 0.0


def test_properties_expose_config():
    """max_dimensions and value_bounds expose the configured limits."""
    s = InputSanitizer(max_dimensions=42, value_lower_bound=-5.0, value_upper_bound=5.0)
    assert s.max_dimensions == 42
    assert s.value_bounds == (-5.0, 5.0)


def test_rejection_log_is_bounded():
    """The rejection log drops the oldest entries once it hits its cap."""
    s = InputSanitizer(enable_rate_limiting=False)
    s._max_log_size = 20
    for _ in range(30):
        s.sanitize([float("nan")], client_id="flood")
    # Log stays bounded (below cap + one drop batch)
    assert len(s._rejection_log) <= 20
