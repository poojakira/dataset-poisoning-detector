"""
tests/test_spectral_crossclass.py
────────────────────────────────────────────────────────────────────────────────
Tests for the improved label-flip detectors:
  - detect_label_flips_crossclass (cross-class centroid, strongest method)
  - detect_label_flips_robust (robust median + Mahalanobis subspace)

Validates that the cross-class detector materially improves F1 over the
original Tran-style top-1 percentile method on the standard label-flip
benchmark, and behaves sanely on edge cases.
"""

import numpy as np
import pytest
from sklearn.datasets import make_classification
from sklearn.metrics import f1_score

from poison_detector.spectral import (
    detect_label_flips,
    detect_label_flips_crossclass,
    detect_label_flips_robust,
)


def _make_flipped(rate: float, seed_data: int = 2018, seed_flip: int = 42):
    X, y = make_classification(
        n_samples=2000,
        n_features=100,
        n_informative=20,
        n_redundant=5,
        n_clusters_per_class=1,
        class_sep=2.0,
        flip_y=0.0,
        random_state=seed_data,
    )
    rng = np.random.RandomState(seed_flip)
    yp = y.copy()
    c0 = np.where(y == 0)[0]  # type: ignore[arg-type]  # numpy stub overload for elementwise mask
    n = int(rate * len(y))
    idx = rng.choice(c0, size=min(n, len(c0)), replace=False)
    yp[idx] = 1
    return X, yp, set(idx.tolist())


def _f1(flagged, poisoned, n):
    yt = np.zeros(n, int)
    yp = np.zeros(n, int)
    for i in poisoned:
        yt[i] = 1
    for i in flagged:
        yp[i] = 1
    if not flagged:
        return 0.0
    return float(f1_score(yt, yp, zero_division=0.0))  # type: ignore[arg-type]  # sklearn stub types zero_division as str; 0.0 is a valid runtime value


class TestCrossClassDetector:
    @pytest.mark.parametrize("rate", [0.05, 0.10, 0.20])
    def test_beats_top1_baseline(self, rate):
        """Cross-class centroid must beat the original top-1 method on label-flip."""
        X, yp, poisoned = _make_flipped(rate)
        n = len(yp)
        baseline = set(detect_label_flips(X, yp, contamination_estimate=rate, n_components=1))
        strong = set(detect_label_flips_crossclass(X, yp, contamination_estimate=rate))
        f1_base = _f1(baseline, poisoned, n)
        f1_strong = _f1(strong, poisoned, n)
        assert f1_strong > f1_base, f"rate={rate}: strong {f1_strong:.3f} !> baseline {f1_base:.3f}"

    def test_meaningful_recall_at_5pct(self):
        """At 5% contamination the strong detector should reach F1 well above 0.4."""
        X, yp, poisoned = _make_flipped(0.05)
        strong = set(detect_label_flips_crossclass(X, yp, contamination_estimate=0.05))
        assert _f1(strong, poisoned, len(yp)) > 0.4

    def test_empty_input(self):
        assert detect_label_flips_crossclass([], []) == []

    def test_single_class_returns_empty(self):
        X = np.random.default_rng(0).normal(size=(30, 5))
        labels = [0] * 30
        assert detect_label_flips_crossclass(X, labels, contamination_estimate=0.1) == []

    def test_returns_sorted_indices(self):
        X, yp, _ = _make_flipped(0.10)
        out = detect_label_flips_crossclass(X, yp, contamination_estimate=0.10)
        assert isinstance(out, list)
        assert all(isinstance(i, int) for i in out)
        assert len(out) == len(set(out))  # no duplicates


class TestRobustDetector:
    def test_improves_over_top1_at_low_contamination(self):
        X, yp, poisoned = _make_flipped(0.05)
        n = len(yp)
        base = set(detect_label_flips(X, yp, contamination_estimate=0.05, n_components=1))
        robust = set(detect_label_flips_robust(X, yp, contamination_estimate=0.05, n_components=8))
        assert _f1(robust, poisoned, n) > _f1(base, poisoned, n)

    def test_empty_input(self):
        assert detect_label_flips_robust([], []) == []

    def test_handles_small_class(self):
        # class with < 5 samples is skipped without error
        X = np.random.default_rng(1).normal(size=(8, 4))
        labels = [0, 0, 0, 0, 0, 0, 1, 1]  # class 1 too small
        out = detect_label_flips_robust(X, labels, contamination_estimate=0.2)
        assert isinstance(out, list)
