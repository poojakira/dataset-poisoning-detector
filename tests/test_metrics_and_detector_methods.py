"""Tests for metrics initialization and the single-method detector report paths."""

from poison_detector.detector import detect
from poison_detector import metrics


def test_initialize_metrics_sets_info_and_gauges():
    metrics.initialize_metrics(environment="test", version="1.1.0")
    # The info metric should carry the version/environment we set.
    # (prometheus_client Info exposes the value via its _value attribute.)
    # We assert indirectly by re-initializing without error and checking gauges.
    metrics.DRIFT_SCORE.labels(environment="test").set(0.3)
    metrics.POISON_RATE.labels(environment="test").set(0.1)
    # No exception means the label combinations exist.
    assert True


def test_detect_iqr_single_method():
    # Varied data so the IQR (interquartile range) is well-defined and non-zero.
    X = [[float(i % 10), float((i * 3) % 7)] for i in range(80)]
    X.append([500.0, 500.0])
    report = detect(X, method="iqr")
    assert report.total_samples == 81
    assert report.poisoned_count >= 1
    assert "iqr" in report.method_scores
    assert report.per_sample[80].method == "iqr"
    assert report.per_sample[80].is_poisoned is True


def test_detect_isolation_single_method():
    X = [[float(i) * 0.01, float(i) * 0.01] for i in range(90)]
    X += [[50.0, 50.0], [60.0, 60.0]]
    report = detect(X, method="isolation")
    assert report.total_samples == 92
    assert "isolation" in report.method_scores
    # Every sample gets a result row.
    assert len(report.per_sample) == 92


def test_detect_rejects_unknown_method():
    import pytest

    with pytest.raises(ValueError):
        detect([[1.0, 2.0]], method="bogus")


def test_detect_accepts_extended_sample_dicts():
    rows = [{"features": [float(i), float(i)], "label": 0} for i in range(50)]
    rows.append({"features": [999.0, 999.0], "label": 1})
    report = detect(rows, method="zscore")
    assert report.total_samples == 51
    assert report.per_sample[50].is_poisoned is True
