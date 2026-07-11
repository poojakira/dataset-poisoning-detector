"""Tests for label-aware (kNN label-disagreement) detection.

Headline property: label-aware detection catches label-flip poison -- ordinary
feature vectors with a deliberately wrong label -- which every feature-only
detector in the project is blind to.
"""

import numpy as np
import pytest

from poison_detector.datasets import (
    ATTACK_LABEL_FLIP,
    inject_poison,
    load_reference_dataset,
)
from poison_detector.label_aware import (
    label_aware_detect,
    label_disagreement_scores,
)


def test_empty_input_returns_empty():
    assert label_disagreement_scores([], []) == []
    assert label_aware_detect([], []) == []


def test_mismatched_lengths_raise():
    with pytest.raises(ValueError):
        label_disagreement_scores([[1.0], [2.0]], [0])


def test_disagreement_scores_in_unit_range():
    bundle = load_reference_dataset("iris")
    scores = label_disagreement_scores(bundle.X, bundle.y, n_neighbors=5)
    assert len(scores) == bundle.n_samples
    assert all(0.0 <= s <= 1.0 for s in scores)


def test_label_flip_is_caught():
    bundle = load_reference_dataset("breast_cancer")
    poisoned = inject_poison(bundle, ATTACK_LABEL_FLIP, contamination=0.05, seed=42)
    flagged = {i for i, _ in label_aware_detect(poisoned.X, poisoned.y, threshold=0.6)}
    poison = set(poisoned.poison_indices)
    recall = len(flagged & poison) / len(poison)
    # Flipped labels should disagree with their feature-space neighbors.
    assert recall >= 0.5


def test_clean_wellseparated_data_has_low_disagreement():
    # Two tight, far-apart clusters with correct labels -> near-zero disagreement.
    rng = np.random.default_rng(0)
    a = rng.normal(loc=-10.0, scale=0.1, size=(30, 2))
    b = rng.normal(loc=10.0, scale=0.1, size=(30, 2))
    X = np.vstack([a, b]).tolist()
    y = [0] * 30 + [1] * 30
    scores = label_disagreement_scores(X, y, n_neighbors=5)
    assert max(scores) < 0.5


def test_single_sample_is_safe():
    scores = label_disagreement_scores([[1.0, 2.0]], [0])
    assert scores == [0.0]
