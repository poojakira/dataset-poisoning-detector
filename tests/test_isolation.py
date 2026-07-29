"""Tests for Isolation Forest anomaly detection wrapper."""

from poison_detector.isolation import IsolationDetector


def test_isolation_detects_cluster_outlier():
    """95 normal points in tight cluster, 5 outliers far away -- outliers detected."""
    X = [[float(i % 10) * 0.1, float(i % 10) * 0.1] for i in range(95)]
    outliers = [[50.0, 50.0], [55.0, 55.0], [60.0, 60.0], [65.0, 65.0], [70.0, 70.0]]
    X.extend(outliers)

    detector = IsolationDetector(contamination=0.1, random_state=42)
    results = detector.fit_predict(X)

    outlier_scores = [score for idx, score in results if idx >= 95]

    for score in outlier_scores:
        assert score > 0.5, f"Outlier score {score} should be > 0.5"


def test_isolation_returns_scores_for_all():
    """Output length must equal input length -- every sample gets a score."""
    X = [[float(i), float(i * 2)] for i in range(50)]

    detector = IsolationDetector()
    results = detector.fit_predict(X)

    assert len(results) == len(X), (
        f"Expected {len(X)} results, got {len(results)}"
    )
    indices = [idx for idx, _ in results]
    assert sorted(indices) == list(range(50))


def test_isolation_contamination_parameter():
    """Lower contamination should flag fewer samples than higher contamination."""
    X = [[float(i), float(i * 2)] for i in range(100)]
    X.extend([[500.0, 1000.0], [600.0, 1200.0], [700.0, 1400.0]])

    detector_low = IsolationDetector(contamination=0.05, random_state=42)
    detector_low.fit_predict(X)
    predictions_low = detector_low._model.predict(X)
    flagged_low = sum(1 for p in predictions_low if p == -1)

    detector_high = IsolationDetector(contamination=0.2, random_state=42)
    detector_high.fit_predict(X)
    predictions_high = detector_high._model.predict(X)
    flagged_high = sum(1 for p in predictions_high if p == -1)

    assert flagged_low < flagged_high, (
        f"contamination=0.05 flagged {flagged_low}, "
        f"contamination=0.2 flagged {flagged_high}. "
        f"Lower contamination should flag fewer samples."
    )
