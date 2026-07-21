"""Tests for tunable ensemble threshold and FP-budget enforcement."""

import pytest

from poison_detector.detector import detect, enforce_fp_budget


def test_ensemble_threshold_is_configurable(monkeypatch):
    X = [[float(i) * 0.1, float(i) * 0.1] for i in range(95)]
    X.extend([[100.0, 100.0], [110.0, 110.0], [120.0, 120.0], [130.0, 130.0], [140.0, 140.0]])

    monkeypatch.setenv("POISONING_DETECTION_THRESHOLD", "0.99")
    strict = detect(X, method="ensemble")

    monkeypatch.setenv("POISONING_DETECTION_THRESHOLD", "0.30")
    lenient = detect(X, method="ensemble")

    assert lenient.poisoned_count >= strict.poisoned_count
    assert strict.method_scores["threshold"] == 0.99
    assert lenient.method_scores["threshold"] == 0.30


def test_fp_budget_requires_explicit_override(monkeypatch):
    monkeypatch.setenv("FP_BUDGET", "0.01")
    monkeypatch.delenv("ALLOW_HIGH_FP", raising=False)

    with pytest.raises(RuntimeError, match="ALLOW_HIGH_FP=true"):
        enforce_fp_budget(0.05)

    monkeypatch.setenv("ALLOW_HIGH_FP", "true")
    enforce_fp_budget(0.05)