"""
Tests for scanning a HuggingFace dataset from a URL for label-flip poisoning.

Uses injected rows (_rows_override) so tests are deterministic and need no
network. Exercises the real spectral detection path on the parsed matrix.
"""

import numpy as np
import pytest

from poison_detector.dataset_url_scanner import (
    parse_hf_dataset_reference,
    scan_hf_dataset,
)


class TestParseReference:
    def test_full_url(self):
        assert (
            parse_hf_dataset_reference("https://huggingface.co/datasets/stanfordnlp/imdb")
            == "stanfordnlp/imdb"
        )

    def test_bare_id(self):
        assert parse_hf_dataset_reference("mnist/mnist") == "mnist/mnist"

    def test_non_hf_url_none(self):
        assert parse_hf_dataset_reference("https://example.com/x/y") is None


def _clean_rows(n_per_class=60, dim=8, seed=0):
    """Two well-separated Gaussian classes, correctly labeled."""
    rng = np.random.default_rng(seed)
    rows = []
    for _ in range(n_per_class):
        rows.append(
            {**{f"f{i}": float(v) for i, v in enumerate(rng.normal(0, 1, dim))}, "label": 0}
        )
    for _ in range(n_per_class):
        rows.append(
            {**{f"f{i}": float(v) for i, v in enumerate(rng.normal(6, 1, dim))}, "label": 1}
        )
    return rows


class TestDatasetScanning:
    def test_clean_dataset_low_flags(self):
        rows = _clean_rows()
        res = scan_hf_dataset("org/clean", label_column="label", _rows_override=rows)
        assert res.rows_scanned == len(rows)
        assert res.label_column == "label"
        # Clean data: few or no flags (IQR threshold allows a small tail).
        assert len(res.suspected_poison_rows) <= max(1, int(0.1 * len(rows)))

    def test_label_flip_poison_detected(self):
        rng = np.random.default_rng(1)
        rows = _clean_rows(seed=1)
        # Poison: take 6 class-0 points (features near 0) and relabel them class 1.
        for _ in range(6):
            feats = {f"f{i}": float(v) for i, v in enumerate(rng.normal(0, 1, 8))}
            rows.append({**feats, "label": 1})  # wrong label - lives among class 1
        res = scan_hf_dataset("org/poisoned", label_column="label", _rows_override=rows)
        # Spectral detection should flag at least some of the mislabeled points.
        assert res.poison_suspected, "label-flip poison should be flagged"

    def test_auto_detect_label_column(self):
        rows = _clean_rows()
        res = scan_hf_dataset("org/x", _rows_override=rows)  # no label_column given
        assert res.label_column == "label"

    def test_no_label_column_reports_error(self):
        rows = [{"f0": 1.0, "f1": 2.0} for _ in range(20)]
        res = scan_hf_dataset("org/nolabels", _rows_override=rows)
        assert any("label" in e for e in res.errors)

    def test_invalid_url_raises(self):
        with pytest.raises(ValueError, match="Could not parse"):
            scan_hf_dataset("https://example.com/not/hf", _rows_override=[])

    def test_result_serializes(self):
        rows = _clean_rows()
        res = scan_hf_dataset("org/x", label_column="label", _rows_override=rows)
        d = res.to_dict()
        assert d["verdict"] in ("clean", "POISON_SUSPECTED")
        assert d["rows_scanned"] == len(rows)
