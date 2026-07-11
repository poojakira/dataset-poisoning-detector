"""Tests for loss/influence-based surrogate scoring.

These are documented as APPROXIMATE supervised signals. The tests check the
contract (shapes, error paths, graceful degeneration) and the directional
property that mislabeled samples incur higher surrogate loss.
"""

import numpy as np
import pytest

from poison_detector.datasets import (
    ATTACK_LABEL_FLIP,
    inject_poison,
    load_reference_dataset,
)
from poison_detector.influence import (
    influence_detect,
    influence_scores,
    loss_scores,
)


def test_empty_input_returns_empty():
    assert loss_scores([], []) == []
    assert influence_scores([], []) == []
    assert influence_detect([], []) == []


def test_mismatched_lengths_raise():
    with pytest.raises(ValueError):
        loss_scores([[1.0], [2.0]], [0])
    with pytest.raises(ValueError):
        influence_scores([[1.0], [2.0]], [0])


def test_single_class_degrades_gracefully():
    X = np.random.default_rng(0).normal(size=(20, 3)).tolist()
    y = [0] * 20  # only one class -> no surrogate can be fit
    assert loss_scores(X, y) == [0.0] * 20
    assert influence_scores(X, y) == [0.0] * 20
    assert influence_detect(X, y) == []


def test_loss_scores_shape_and_nonnegativity():
    bundle = load_reference_dataset("iris")
    scores = loss_scores(bundle.X, bundle.y)
    assert len(scores) == bundle.n_samples
    assert all(s >= 0.0 for s in scores)


def test_flipped_labels_have_higher_loss():
    bundle = load_reference_dataset("breast_cancer")
    poisoned = inject_poison(bundle, ATTACK_LABEL_FLIP, contamination=0.05, seed=42)
    scores = loss_scores(poisoned.X, poisoned.y)
    poison = set(poisoned.poison_indices)
    poison_mean = np.mean([scores[i] for i in poison])
    clean_mean = np.mean([scores[i] for i in range(len(scores)) if i not in poison])
    assert poison_mean > clean_mean


def test_influence_detect_returns_indices():
    bundle = load_reference_dataset("breast_cancer")
    poisoned = inject_poison(bundle, ATTACK_LABEL_FLIP, contamination=0.05, seed=42)
    flagged = influence_detect(poisoned.X, poisoned.y, quantile=0.9)
    assert all(isinstance(i, int) for i, _ in flagged)
