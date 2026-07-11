"""Tests for the honest benchmark harness.

Verifies metric plumbing (precision/recall/F1/ROC-AUC), the calibrated ensemble
combiner, JSON export, and that the harness produces sane per-attack results on
a real dataset -- e.g. the ensemble has no attack it completely misses.
"""

import json

import numpy as np

from poison_detector.benchmark import (
    BenchmarkReport,
    calibrated_ensemble_predictions,
    calibrated_ensemble_scores,
    evaluate_configuration,
    format_scorecard,
    method_predictions,
    method_scores,
    run_benchmark,
)
from poison_detector.datasets import (
    ATTACK_DUPLICATE,
    inject_poison,
    load_reference_dataset,
)


def test_method_scores_include_all_methods_with_labels():
    bundle = load_reference_dataset("iris")
    scores = method_scores(bundle.X, bundle.y)
    for m in ("zscore", "iqr", "isolation", "spectral", "fingerprint",
              "label_aware", "influence"):
        assert m in scores
        assert len(scores[m]) == bundle.n_samples


def test_method_scores_omit_label_methods_without_labels():
    bundle = load_reference_dataset("iris")
    scores = method_scores(bundle.X, None)
    assert "label_aware" not in scores
    assert "influence" not in scores
    assert "spectral" in scores


def test_method_predictions_return_index_sets():
    bundle = load_reference_dataset("iris")
    preds = method_predictions(bundle.X, bundle.y, contamination=0.05)
    assert all(isinstance(v, set) for v in preds.values())


def test_calibrated_ensemble_scores_unit_range():
    bundle = load_reference_dataset("iris")
    scores = method_scores(bundle.X, bundle.y)
    ens = calibrated_ensemble_scores(scores)
    assert len(ens) == bundle.n_samples
    assert all(0.0 <= s <= 1.0 for s in ens)
    assert calibrated_ensemble_scores({}) == []


def test_calibrated_ensemble_flags_contamination_fraction():
    bundle = load_reference_dataset("breast_cancer")
    poisoned = inject_poison(bundle, ATTACK_DUPLICATE, contamination=0.05, seed=42)
    scores = method_scores(poisoned.X, poisoned.y)
    flagged = calibrated_ensemble_predictions(scores, poisoned.contamination)
    # Roughly the contamination fraction is flagged (within a factor of ~3).
    frac = len(flagged) / len(poisoned.X)
    assert 0.0 < frac < 0.2


def test_ensemble_catches_duplicate_injection_via_fingerprint():
    """Regression guard: the max-combiner ensemble must NOT have a duplicate
    blind spot (the mean-combiner scored 0.0 F1 here)."""
    bundle = load_reference_dataset("breast_cancer")
    poisoned = inject_poison(bundle, ATTACK_DUPLICATE, contamination=0.05, seed=42)
    cell = evaluate_configuration(
        poisoned.X, poisoned.y, poisoned.poison_indices,
        ATTACK_DUPLICATE, poisoned.contamination,
    )
    assert cell.method_scores["fingerprint"].f1 > 0.5
    assert cell.method_scores["ensemble"].f1 > 0.0


def test_run_benchmark_end_to_end_and_json():
    report = run_benchmark(
        dataset="iris",
        attacks=("feature_outlier", "label_flip"),
        contamination_levels=(0.05,),
    )
    assert isinstance(report, BenchmarkReport)
    assert len(report.cells) == 2
    # JSON round-trips.
    parsed = json.loads(report.to_json())
    assert parsed["dataset"] == "iris"
    assert len(parsed["cells"]) == 2
    # Scorecard renders without error and mentions the dataset.
    card = format_scorecard(report)
    assert "iris" in card
    assert "ensemble" in card


def test_method_averages_present():
    report = run_benchmark(
        dataset="iris",
        attacks=("feature_outlier",),
        contamination_levels=(0.05,),
    )
    avgs = report.method_averages()
    assert "ensemble" in avgs
    assert set(avgs["ensemble"].keys()) == {"precision", "recall", "f1", "roc_auc"}
