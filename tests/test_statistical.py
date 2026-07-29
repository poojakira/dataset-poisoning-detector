"""Tests for pure-Python statistical anomaly detection methods."""

from poison_detector.statistical import zscore_detect, iqr_detect


def test_zscore_detects_outlier():
    """Inject an obvious outlier at 10x std deviation, verify it is flagged."""
    X = [[5.0 + (i % 10) * 0.1, 3.0 + (i % 5) * 0.2] for i in range(99)]
    X.append([50.0, 3.0])

    flagged = zscore_detect(X, threshold=3.0)
    flagged_indices = [idx for idx, _ in flagged]

    assert 99 in flagged_indices, "Outlier at index 99 should be flagged"
    outlier_score = next(score for idx, score in flagged if idx == 99)
    assert outlier_score > 3.0


def test_zscore_clean_data_passes():
    """Uniform data within narrow range should produce no flags."""
    X = [[5.0 + (i % 10) * 0.1, 5.0 + (i % 10) * 0.1] for i in range(100)]

    flagged = zscore_detect(X, threshold=3.0)
    assert len(flagged) == 0, "Clean uniform data should have no outliers"


def test_iqr_detects_outlier():
    """Inject an obvious outlier beyond IQR fence, verify flagged."""
    X = [[float(i), float(i * 2)] for i in range(100)]
    X.append([1000.0, 2000.0])

    flagged = iqr_detect(X, k=1.5)
    flagged_indices = [idx for idx, _ in flagged]

    assert 100 in flagged_indices, "Extreme outlier should be flagged by IQR"


def test_iqr_threshold_sensitivity():
    """Different k values should change what gets flagged."""
    X = [[float(i)] for i in range(100)]
    X.append([200.0])
    X.append([250.0])

    flagged_strict = iqr_detect(X, k=3.0)
    flagged_loose = iqr_detect(X, k=1.5)

    assert len(flagged_loose) >= len(flagged_strict)
