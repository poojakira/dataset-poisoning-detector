"""Tests for feature-level attribution module."""

from poison_detector.attribution import feature_attribution, format_attribution


def test_attribution_returns_sorted_by_deviation():
    """Feature deviations should be sorted descending by magnitude."""
    X = [[1.0, 2.0, 3.0] for _ in range(99)]
    X.append([100.0, 2.5, 50.0])

    attr = feature_attribution(X, [99])

    assert 99 in attr
    deviations = attr[99]
    magnitudes = [mag for _, mag in deviations]
    assert magnitudes == sorted(
        magnitudes, reverse=True
    ), "Deviations should be sorted descending by magnitude"
    assert deviations[0][0] == 0, "Feature 0 should have largest deviation"


def test_attribution_with_feature_names():
    """format_attribution should use provided feature names."""
    X = [[1.0, 2.0] for _ in range(10)]
    X.append([100.0, 200.0])

    attr = feature_attribution(X, [10])
    formatted = format_attribution(attr, feature_names=["temperature", "pressure"])

    assert "temperature" in formatted
    assert "pressure" in formatted
    assert "Sample 10" in formatted


def test_attribution_empty_flagged_list():
    """Empty flagged list should return empty dict."""
    X = [[1.0, 2.0] for _ in range(10)]

    attr = feature_attribution(X, [])
    assert attr == {}

    formatted = format_attribution({})
    assert formatted == ""
