"""Tests for the main ensemble detector and report generation."""

import json

from poison_detector.detector import detect
from poison_detector.report import export_json


def test_ensemble_majority_vote():
    """Ensemble should flag samples only when >= 2 methods agree."""
    X = [[float(i) * 0.1, float(i) * 0.1] for i in range(95)]
    X.extend([
        [100.0, 100.0],
        [110.0, 110.0],
        [120.0, 120.0],
        [130.0, 130.0],
        [140.0, 140.0],
    ])

    report = detect(X, method="ensemble")

    poisoned_indices = [
        r.sample_idx for r in report.per_sample if r.is_poisoned
    ]
    outlier_range = set(range(95, 100))
    caught = set(poisoned_indices) & outlier_range
    assert len(caught) > 0, "Ensemble should catch at least some extreme outliers"

    assert report.total_samples == 100
    assert report.poisoned_count == len(poisoned_indices)
    assert "zscore" in report.method_scores
    assert "iqr" in report.method_scores
    assert "isolation" in report.method_scores


def test_single_method_zscore():
    """Single-method detection should work correctly."""
    X = [[5.0, 5.0] for _ in range(99)]
    X.append([500.0, 500.0])

    report = detect(X, method="zscore")

    assert report.total_samples == 100
    assert report.poisoned_count >= 1

    outlier_result = report.per_sample[99]
    assert outlier_result.is_poisoned is True
    assert outlier_result.method == "zscore"


def test_report_json_serializable():
    """export_json should produce valid, parseable JSON."""
    X = [[float(i), float(i * 2)] for i in range(50)]
    X.append([999.0, 999.0])

    report = detect(X, method="zscore")
    json_str = export_json(report)

    parsed = json.loads(json_str)

    assert "total_samples" in parsed
    assert "poisoned_count" in parsed
    assert "method_scores" in parsed
    assert "per_sample" in parsed
    assert isinstance(parsed["per_sample"], list)
    assert len(parsed["per_sample"]) == 51
