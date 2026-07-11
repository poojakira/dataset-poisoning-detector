"""Tests for the dimensionality reduction wrappers used before density scoring."""

import numpy as np
import pytest

from poison_detector.reduction import DimensionalityReducer


def test_invalid_method_rejected():
    with pytest.raises(ValueError):
        DimensionalityReducer(method="tsne")


def test_invalid_components_rejected():
    with pytest.raises(ValueError):
        DimensionalityReducer(n_components=0)


def test_gaussian_projection_reduces_dim():
    rng = np.random.default_rng(0)
    X = rng.normal(size=(100, 256))
    reducer = DimensionalityReducer(method="gaussian", n_components=32)
    reduced = reducer.fit_transform(X)
    assert reduced.shape == (100, 32)
    assert not reducer.is_passthrough


def test_pca_projection_reduces_dim():
    rng = np.random.default_rng(1)
    X = rng.normal(size=(100, 50))
    reducer = DimensionalityReducer(method="pca", n_components=10)
    reduced = reducer.fit_transform(X)
    assert reduced.shape == (100, 10)


def test_passthrough_when_already_low_dim():
    X = np.random.default_rng(2).normal(size=(20, 8))
    reducer = DimensionalityReducer(method="gaussian", n_components=64)
    reduced = reducer.fit_transform(X)
    assert reducer.is_passthrough
    np.testing.assert_allclose(reduced, X)


def test_transform_before_fit_raises():
    reducer = DimensionalityReducer()
    with pytest.raises(RuntimeError):
        reducer.transform([[1.0, 2.0]])


def test_transform_accepts_single_row():
    X = np.random.default_rng(3).normal(size=(50, 128))
    reducer = DimensionalityReducer(method="gaussian", n_components=16).fit(X)
    out = reducer.transform(X[0])
    assert out.shape == (1, 16)


def test_fit_rejects_empty():
    reducer = DimensionalityReducer()
    with pytest.raises(ValueError):
        reducer.fit(np.zeros((0, 5)))
