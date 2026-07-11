"""Tests for real-dataset loading and controlled poison injection.

Verifies that the bundled scikit-learn datasets load hermetically (no network),
that standardization behaves, and that every attack injects the expected number
of poison rows at known, contiguous indices.
"""

import numpy as np
import pytest

from poison_detector.datasets import (
    ALL_ATTACKS,
    ATTACK_CORRELATION,
    ATTACK_DUPLICATE,
    ATTACK_FEATURE_OUTLIER,
    ATTACK_LABEL_FLIP,
    DatasetBundle,
    PoisonInjector,
    available_datasets,
    inject_poison,
    load_reference_dataset,
)


def test_available_datasets_lists_known_names():
    names = available_datasets()
    assert "breast_cancer" in names
    assert "digits" in names
    assert set(names) == {"breast_cancer", "digits", "iris", "wine"}


def test_load_reference_dataset_standardized():
    bundle = load_reference_dataset("breast_cancer", standardize=True)
    assert isinstance(bundle, DatasetBundle)
    assert bundle.n_samples == 569
    assert bundle.n_features == 30
    assert bundle.n_classes == 2
    assert len(bundle.feature_names) == 30
    # Standardized columns are ~zero-mean, ~unit-variance.
    arr = np.asarray(bundle.X)
    np.testing.assert_allclose(arr.mean(axis=0), 0.0, atol=1e-6)
    np.testing.assert_allclose(arr.std(axis=0), 1.0, atol=1e-6)


def test_load_reference_dataset_unstandardized_and_capped():
    bundle = load_reference_dataset("iris", standardize=False, max_samples=50)
    assert bundle.n_samples == 50
    assert bundle.standardized is False


def test_load_reference_dataset_rejects_unknown():
    with pytest.raises(ValueError):
        load_reference_dataset("not_a_dataset")


def test_inject_poison_contiguous_known_indices():
    bundle = load_reference_dataset("breast_cancer")
    poisoned = inject_poison(bundle, ATTACK_FEATURE_OUTLIER, contamination=0.05, seed=1)
    n_clean = bundle.n_samples
    # Poison indices are contiguous and start right after the clean rows.
    assert poisoned.poison_indices[0] == n_clean
    assert poisoned.poison_indices == list(
        range(n_clean, n_clean + len(poisoned.poison_indices))
    )
    assert len(poisoned.X) == n_clean + len(poisoned.poison_indices)
    # Contamination close to requested.
    assert abs(poisoned.contamination - 0.05) < 0.02
    # Binary labels line up with poison indices.
    binary = poisoned.labels_binary
    assert sum(binary) == len(poisoned.poison_indices)
    assert all(binary[i] == 1 for i in poisoned.poison_indices)


@pytest.mark.parametrize("attack", ALL_ATTACKS)
def test_all_attacks_produce_poison(attack):
    bundle = load_reference_dataset("wine")
    poisoned = inject_poison(bundle, attack, contamination=0.1, seed=7)
    assert len(poisoned.poison_indices) >= 1
    assert poisoned.attack == attack


def test_inject_poison_rejects_bad_contamination():
    bundle = load_reference_dataset("iris")
    with pytest.raises(ValueError):
        inject_poison(bundle, ATTACK_LABEL_FLIP, contamination=0.9)


def test_label_flip_changes_only_labels():
    bundle = load_reference_dataset("iris")
    injector = PoisonInjector(seed=3)
    X = np.asarray(bundle.X)
    y = np.asarray(bundle.y)
    poison_X, poison_y = injector.label_flip(X, y, n=10)
    # Every poison row is an exact copy of some real row (features untouched)...
    for row in poison_X:
        assert np.any(np.all(np.isclose(X, row), axis=1))
    # ...but each label is a valid class.
    assert set(poison_y).issubset(set(y.tolist()))


def test_correlation_poison_keeps_marginals_in_range():
    bundle = load_reference_dataset("breast_cancer")
    injector = PoisonInjector(seed=5)
    X = np.asarray(bundle.X)
    y = np.asarray(bundle.y)
    poison_X, _ = injector.correlation_poison(X, y, n=20)
    # Each feature value must fall within the observed per-column range.
    col_min = X.min(axis=0)
    col_max = X.max(axis=0)
    assert np.all(poison_X >= col_min - 1e-9)
    assert np.all(poison_X <= col_max + 1e-9)


def test_unknown_attack_raises():
    bundle = load_reference_dataset("iris")
    injector = PoisonInjector()
    with pytest.raises(ValueError):
        injector.generate("nonsense", np.asarray(bundle.X), np.asarray(bundle.y), 5)


def test_label_flip_requires_multiple_classes():
    injector = PoisonInjector()
    X = np.zeros((10, 3))
    y = np.zeros(10, dtype=int)  # single class
    with pytest.raises(ValueError):
        injector.label_flip(X, y, n=3)
