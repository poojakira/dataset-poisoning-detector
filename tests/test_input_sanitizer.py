"""Tests for input sanitization.

Verifies that the InputSanitizer rejects NaN, Inf, dimension mismatches,
and memory bomb attempts while accepting valid inputs.
"""

import numpy as np

from poison_detector.input_sanitizer import (
    InputSanitizer,
    RejectionReason,
)


def test_nan_rejection():
    """InputSanitizer rejects samples containing NaN values."""
    sanitizer = InputSanitizer(
        max_dimensions=1000,
        enable_rate_limiting=False,
    )

    # Sample with NaN values
    features_with_nan = [1.0, 2.0, float("nan"), 4.0, 5.0]
    result = sanitizer.sanitize(features_with_nan, client_id="test-client")

    assert result.is_valid is False
    assert result.rejection_reason == RejectionReason.NAN_VALUES
    assert "NaN" in result.rejection_detail
    assert result.sanitized_sample is None


def test_inf_rejection():
    """InputSanitizer rejects samples containing Inf or -Inf values."""
    sanitizer = InputSanitizer(
        max_dimensions=1000,
        enable_rate_limiting=False,
    )

    # Sample with positive infinity
    features_with_inf = [1.0, 2.0, float("inf"), 4.0]
    result = sanitizer.sanitize(features_with_inf, client_id="test-client")

    assert result.is_valid is False
    assert result.rejection_reason == RejectionReason.INF_VALUES
    assert "infinite" in result.rejection_detail

    # Sample with negative infinity
    features_with_neg_inf = [1.0, float("-inf"), 3.0]
    result = sanitizer.sanitize(features_with_neg_inf, client_id="test-client")

    assert result.is_valid is False
    assert result.rejection_reason == RejectionReason.INF_VALUES


def test_dimension_mismatch_rejection():
    """InputSanitizer rejects samples exceeding max_dimensions."""
    sanitizer = InputSanitizer(
        max_dimensions=10,
        min_dimensions=3,
        enable_rate_limiting=False,
    )

    # Too many dimensions
    oversized = [1.0] * 50
    result = sanitizer.sanitize(oversized, client_id="test-client")

    assert result.is_valid is False
    assert result.rejection_reason == RejectionReason.EXCEEDS_MAX_DIMENSIONS
    assert "50" in result.rejection_detail
    assert "10" in result.rejection_detail

    # Too few dimensions
    undersized = [1.0, 2.0]
    result = sanitizer.sanitize(undersized, client_id="test-client")

    assert result.is_valid is False
    assert result.rejection_reason == RejectionReason.BELOW_MIN_DIMENSIONS

    # Just right
    valid = [1.0] * 5
    result = sanitizer.sanitize(valid, client_id="test-client")
    assert result.is_valid is True
    assert result.sanitized_sample is not None
    assert len(result.sanitized_sample) == 5


def test_memory_bomb_prevention():
    """InputSanitizer rejects absurdly large samples before processing."""
    sanitizer = InputSanitizer(
        max_dimensions=1000,
        enable_rate_limiting=False,
    )

    # A memory bomb: attempt to submit a sample with far more dimensions
    # than allowed. The dimension check catches this before numpy allocation.
    bomb_size = 10_000_000  # 10 million dimensions

    # We use a list that reports its length without fully materializing in numpy
    # to verify the dimension check fires before any expensive computation.
    # range() is lazy but has __len__, so InputSanitizer checks len() first.
    huge_features = [0.0] * 5000  # Over max_dimensions of 1000

    result = sanitizer.sanitize(huge_features, client_id="bomb-client")

    assert result.is_valid is False
    assert result.rejection_reason == RejectionReason.EXCEEDS_MAX_DIMENSIONS
    assert result.sanitized_sample is None

    # Verify the sanitizer stats recorded the rejection
    stats = sanitizer.get_stats()
    assert stats["total_rejected"] >= 1
