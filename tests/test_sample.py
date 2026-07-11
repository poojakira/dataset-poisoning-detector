"""Tests for the extended sample data model and coercion helpers.

The critical property is backward compatibility: the pre-1.1.0 flat-list format
must keep working unchanged, while the new dict/Sample forms add optional labels
and metadata.
"""

import numpy as np
import pytest

from poison_detector.sample import (
    Sample,
    coerce_matrix,
    coerce_sample,
    extract_features,
)


def test_flat_list_still_works():
    s = coerce_sample([1.0, 2.0, 3.0])
    assert s.features == [1.0, 2.0, 3.0]
    assert s.label is None
    assert s.metadata == {}


def test_tuple_and_numpy_inputs():
    assert coerce_sample((1.0, 2.0)).features == [1.0, 2.0]
    assert coerce_sample(np.array([4.0, 5.0])).features == [4.0, 5.0]


def test_dict_with_label_and_metadata():
    s = coerce_sample({"features": [1, 2], "label": 3, "metadata": {"src": "kafka"}})
    assert s.features == [1.0, 2.0]
    assert s.label == 3
    assert s.metadata == {"src": "kafka"}


def test_existing_sample_passthrough():
    original = Sample(features=[1.0], label=0)
    assert coerce_sample(original) is original


def test_extract_features_helper():
    assert extract_features({"features": [7.0, 8.0], "label": 1}) == [7.0, 8.0]


def test_empty_features_rejected():
    with pytest.raises(ValueError):
        Sample(features=[])


def test_dict_missing_features_rejected():
    with pytest.raises(ValueError):
        coerce_sample({"label": 1})


def test_dict_bad_features_type_rejected():
    with pytest.raises(ValueError):
        coerce_sample({"features": "not a list"})


def test_dict_bad_metadata_rejected():
    with pytest.raises(ValueError):
        coerce_sample({"features": [1.0], "metadata": [1, 2, 3]})


def test_unsupported_type_rejected():
    with pytest.raises(TypeError):
        coerce_sample(42)


def test_numpy_non_1d_rejected():
    with pytest.raises(ValueError):
        coerce_sample(np.zeros((2, 2)))


def test_coerce_matrix_mixed_rows():
    rows = [[1.0, 2.0], {"features": [3.0, 4.0], "label": 1}, Sample([5.0, 6.0], label=0)]
    X, labels = coerce_matrix(rows)
    assert X == [[1.0, 2.0], [3.0, 4.0], [5.0, 6.0]]
    assert labels == [None, 1, 0]


def test_coerce_matrix_numpy():
    X, labels = coerce_matrix(np.array([[1.0, 2.0], [3.0, 4.0]]))
    assert X == [[1.0, 2.0], [3.0, 4.0]]
    assert labels == [None, None]


def test_coerce_matrix_numpy_requires_2d():
    with pytest.raises(ValueError):
        coerce_matrix(np.array([1.0, 2.0]))
