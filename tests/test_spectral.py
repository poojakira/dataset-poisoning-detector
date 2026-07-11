"""Tests for spectral / SVD-based covariance-aware detection.

The headline property: spectral detection catches correlation-breaking poison
(features individually in-range, jointly impossible) that per-feature z-score
and IQR are structurally blind to.
"""

import numpy as np

from poison_detector.datasets import (
    ATTACK_CORRELATION,
    ATTACK_CLUSTER,
    inject_poison,
    load_reference_dataset,
)
from poison_detector.spectral import (
    covariance_residual_scores,
    spectral_detect,
    spectral_scores,
    spectral_signature_scores,
)


def test_empty_input_returns_empty():
    assert spectral_scores([]) == []
    assert spectral_signature_scores([]) == []
    assert covariance_residual_scores([]) == []
    assert spectral_detect([]) == []


def test_scores_length_matches_samples():
    X = np.random.default_rng(0).normal(size=(50, 8)).tolist()
    scores = spectral_scores(X)
    assert len(scores) == 50
    assert all(0.0 <= s <= 1.0 for s in scores)


def test_covariance_residual_catches_correlation_poison():
    """The core claim: covariance residual ranks correlation poison highly."""
    bundle = load_reference_dataset("breast_cancer")
    poisoned = inject_poison(bundle, ATTACK_CORRELATION, contamination=0.05, seed=42)
    scores = covariance_residual_scores(poisoned.X)

    poison = set(poisoned.poison_indices)
    poison_mean = np.mean([scores[i] for i in poison])
    clean_mean = np.mean([scores[i] for i in range(len(scores)) if i not in poison])
    # Poison should sit well above clean on the covariance-residual axis.
    assert poison_mean > clean_mean * 2


def test_spectral_signature_catches_cluster_injection():
    bundle = load_reference_dataset("breast_cancer")
    poisoned = inject_poison(bundle, ATTACK_CLUSTER, contamination=0.05, seed=42)
    scores = spectral_signature_scores(poisoned.X)
    poison = set(poisoned.poison_indices)
    poison_mean = np.mean([scores[i] for i in poison])
    clean_mean = np.mean([scores[i] for i in range(len(scores)) if i not in poison])
    assert poison_mean > clean_mean


def test_spectral_detect_flags_correlation_poison_recall():
    bundle = load_reference_dataset("breast_cancer")
    poisoned = inject_poison(bundle, ATTACK_CORRELATION, contamination=0.05, seed=42)
    flagged = {i for i, _ in spectral_detect(poisoned.X, quantile=0.9)}
    poison = set(poisoned.poison_indices)
    recall = len(flagged & poison) / len(poison)
    assert recall >= 0.5


def test_degenerate_constant_matrix_is_safe():
    # Zero-variance matrix must not raise and must return finite scores.
    X = [[1.0, 1.0, 1.0] for _ in range(20)]
    scores = spectral_scores(X)
    assert len(scores) == 20
    assert all(np.isfinite(s) for s in scores)
