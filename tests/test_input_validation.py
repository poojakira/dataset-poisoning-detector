"""Tests for input-validation hardening in detect() and StreamingDetector.

A poisoning detector that silently returns "0 flagged" on empty/NaN/ragged
input gives false assurance. These tests lock in the fail-loud behavior added
to the detector entry point and the streaming scorer.
"""

import math

import numpy as np
import pytest

from poison_detector import detect
from poison_detector.detector import _validate_matrix
from poison_detector.stream import StreamingDetector


def _clean_matrix(n: int = 20, d: int = 4) -> list[list[float]]:
    return [[float((i * d + j) % 7) for j in range(d)] for i in range(n)]


# ── _validate_matrix contract ─────────────────────────────────────────────────


def test_empty_matrix_raises() -> None:
    with pytest.raises(ValueError, match="empty"):
        _validate_matrix([])


def test_non_list_raises() -> None:
    with pytest.raises(TypeError, match="X must be a list"):
        _validate_matrix("not a matrix")  # type: ignore[arg-type]


def test_zero_feature_rows_raise() -> None:
    with pytest.raises(ValueError, match="zero features"):
        _validate_matrix([[], []])


def test_ragged_matrix_raises() -> None:
    with pytest.raises(ValueError, match="ragged"):
        _validate_matrix([[1.0, 2.0], [3.0]])


def test_nan_value_raises() -> None:
    with pytest.raises(ValueError, match="non-finite"):
        _validate_matrix([[1.0, float("nan")], [2.0, 3.0]])


def test_inf_value_raises() -> None:
    with pytest.raises(ValueError, match="non-finite"):
        _validate_matrix([[1.0, math.inf], [2.0, 3.0]])


def test_non_numeric_value_raises() -> None:
    with pytest.raises(TypeError, match="non-numeric"):
        _validate_matrix([["a", "b"]])  # type: ignore[list-item]


def test_bool_treated_as_non_numeric() -> None:
    with pytest.raises(TypeError, match="non-numeric"):
        _validate_matrix([[True, False]])  # type: ignore[list-item]


# ── detect() surfaces the validation and single-sample guards ─────────────────


def test_detect_empty_raises() -> None:
    with pytest.raises(ValueError, match="empty"):
        detect([], method="ensemble")


def test_detect_nan_raises() -> None:
    X = [[1.0, float("nan")] for _ in range(10)]
    with pytest.raises(ValueError, match="non-finite"):
        detect(X, method="ensemble")


def test_detect_single_sample_ensemble_raises() -> None:
    with pytest.raises(ValueError, match="at least 2 samples"):
        detect([[1.0, 2.0]], method="ensemble")


def test_detect_single_sample_zscore_ok() -> None:
    # zscore/iqr are defined on a single sample (returns nothing flagged).
    report = detect([[1.0, 2.0]], method="zscore")
    assert report.total_samples == 1
    assert report.poisoned_count == 0


def test_detect_spectral_label_length_mismatch() -> None:
    X = _clean_matrix(10, 3)
    with pytest.raises(ValueError, match="labels length"):
        detect(X, method="spectral", labels=[0])


def test_detect_clean_matrix_runs() -> None:
    report = detect(_clean_matrix(), method="ensemble")
    assert report.total_samples == 20
    assert report.poisoned_count >= 0


# ── StreamingDetector.score_sample guards ─────────────────────────────────────


def test_stream_empty_sample_raises() -> None:
    det = StreamingDetector()
    with pytest.raises(ValueError, match="zero features"):
        det.score_sample([])


def test_stream_nan_sample_raises() -> None:
    det = StreamingDetector()
    with pytest.raises(ValueError, match="NaN/inf"):
        det.score_sample([1.0, float("nan"), 3.0])


def test_stream_feature_count_mismatch_raises() -> None:
    det = StreamingDetector()
    det.score_sample([1.0, 2.0, 3.0])  # initializes to 3 features
    with pytest.raises(ValueError, match="feature-count mismatch"):
        det.score_sample([1.0, 2.0])


def test_stream_2d_sample_raises() -> None:
    det = StreamingDetector()
    with pytest.raises(ValueError, match="1D feature vector"):
        det.score_sample(np.zeros((2, 3)))


def test_stream_valid_sample_scores() -> None:
    det = StreamingDetector()
    result = det.score_sample([0.1, 0.2, 0.3])
    assert hasattr(result, "is_poisoned")
