"""Regression tests for disjoint CIFAR label-flip group assignment."""

import importlib.util
from pathlib import Path

import numpy as np
import pytest


@pytest.fixture(scope="module")
def builder():
    path = Path(__file__).resolve().parents[1] / "scripts" / "make_labelflip_cifar.py"
    spec = importlib.util.spec_from_file_location("make_labelflip_cifar", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_labelflip_groups


@pytest.mark.parametrize("flip_rate", [0.0, 0.25])
def test_source_rows_are_disjoint_across_groups(builder, flip_rate):
    # The first feature value acts as a unique source-row ID.
    labels = np.repeat(np.arange(10, dtype=np.int64), 16)
    features = np.arange(len(labels), dtype=np.float64).reshape(-1, 1)

    groups = builder(features, labels, flip_rate, n_clean_per_class=4, seed=13)

    observed = []
    for group in groups.values():
        observed.extend(group["features"][:, 0].astype(int).tolist())
        assert group["n_clean"] == 4
        assert group["n_poison"] == (0 if flip_rate == 0 else 1)

    assert len(observed) == len(set(observed))
