"""Remote rows must not become misleading clean verdicts."""

import pytest
from poison_detector.dataset_url_scanner import scan_hf_dataset


@pytest.mark.parametrize(
    "rows",
    [
        [{"feature": 1.0}, {"feature": 2.0}],
        [{"feature": 1.0, "label": 0}, {"feature": 2.0}],
        [{"feature": 1.0, "label": None}],
    ],
)
def test_missing_requested_label_is_error(rows):
    result = scan_hf_dataset("owner/dataset", label_column="label", _rows_override=rows)
    assert result.to_dict()["verdict"] == "ERROR"
    assert "label column" in result.errors[0]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_feature_is_error(value):
    result = scan_hf_dataset(
        "owner/dataset",
        _rows_override=[
            {"feature": value, "label": 0},
            {"feature": 1.0, "label": 1},
        ],
    )
    assert result.to_dict()["verdict"] == "ERROR"
    assert "finite" in result.errors[0]
