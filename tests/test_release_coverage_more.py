from __future__ import annotations

import io
import urllib.error
import urllib.request
from http.client import HTTPMessage
from types import SimpleNamespace
from typing import Any, cast

import numpy as np
import pytest

import poison_detector.dataset_url_scanner as dus
import poison_detector.detector as det


def test_detector_isolation_and_ensemble_paths_with_controlled_backends(monkeypatch):
    class FakeModel:
        def predict(self, X):
            return [-1, 1, 1]

    class FakeIsolation:
        def __init__(self):
            self._model = FakeModel()

        def fit_predict(self, X):
            return [(0, 0.91)]

    X = [[0.0, 0.0], [1.0, 1.0], [2.0, 2.0]]
    monkeypatch.setattr(det, "IsolationDetector", FakeIsolation)
    monkeypatch.setattr(det, "zscore_detect", lambda _x: [(0, 4.0)])
    monkeypatch.setattr(det, "iqr_detect", lambda _x: [(0, 3.0)])
    monkeypatch.setattr(det, "feature_attribution", lambda _x, idxs: {i: [(1, 1.0)] for i in idxs})

    iso = det.detect(X, method="isolation")
    assert iso.poisoned_count == 1
    assert iso.per_sample[0].is_poisoned is True
    assert iso.per_sample[0].features_flagged == [1]

    ensemble = det.detect(X, method="ensemble")
    assert ensemble.poisoned_count == 1
    assert ensemble.method_scores == {"zscore": 1, "iqr": 1, "isolation": 1}
    assert ensemble.per_sample[0].is_poisoned is True
    assert ensemble.per_sample[1].is_poisoned is False


def test_detector_zscore_iqr_paths_with_attribution(monkeypatch):
    X = [[0.0, 0.0], [9.0, 9.0]]
    monkeypatch.setattr(det, "zscore_detect", lambda _x: [(1, 5.0)])
    monkeypatch.setattr(det, "iqr_detect", lambda _x: [(1, 4.0)])
    monkeypatch.setattr(det, "feature_attribution", lambda _x, idxs: {1: [(0, 2.0), (1, 1.0)]})

    z = det.detect(X, method="zscore")
    q = det.detect(X, method="iqr")
    assert z.poisoned_count == 1 and z.per_sample[1].features_flagged == [0, 1]
    assert q.poisoned_count == 1 and q.per_sample[1].features_flagged == [0, 1]


def test_dataset_reference_and_redirect_validation():
    assert dus.parse_hf_dataset_reference("not-a-dataset") is None
    assert dus.parse_hf_dataset_reference("https://example.com/datasets/a/b") is None
    assert (
        dus.parse_hf_dataset_reference(
            " https://huggingface.co/datasets/org/name/viewer/default/train "
        )
        == "org/name"
    )

    handler = dus._DatasetRedirectHandler()
    req = urllib.request.Request("https://datasets-server.huggingface.co/rows")
    fp = io.BytesIO()
    headers = HTTPMessage()
    redirected = handler.redirect_request(
        req,
        fp,
        302,
        "Found",
        headers,
        "https://datasets-server.huggingface.co/info",
    )
    assert redirected is not None
    assert redirected.full_url == "https://datasets-server.huggingface.co/info"
    with pytest.raises(ValueError):
        handler.redirect_request(
            req,
            io.BytesIO(),
            302,
            "Found",
            HTTPMessage(),
            "https://evil.example/rows",
        )


class _FakeResponse:
    def __init__(self, payload: bytes):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit):
        return self.payload


class _FakeOpener:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.calls = []

    def open(self, req, timeout=30):
        self.calls.append((req, timeout))
        return _FakeResponse(self.payload)


def test_get_json_success_non_object_and_size_limit(monkeypatch):
    opener = _FakeOpener(b'{"rows": []}')
    monkeypatch.setattr(dus.urllib.request, "build_opener", lambda *_a: opener)
    result = dus._get_json("https://datasets-server.huggingface.co/rows?x=1", timeout=7)
    assert result == {"rows": []}
    assert opener.calls[0][1] == 7
    assert opener.calls[0][0].headers["User-agent"] == "poison-detector/0.2"

    opener.payload = b"[]"
    with pytest.raises(ValueError, match="must be an object"):
        dus._get_json("https://datasets-server.huggingface.co/rows")

    opener.payload = b"x" * (10 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="exceeds safety limit"):
        dus._get_json("https://datasets-server.huggingface.co/rows")


def test_fetch_rows_paginates_and_stops_on_short_batch(monkeypatch):
    first = [{"row": {"x": i}} for i in range(100)]
    second = [{"row": {"x": 100}}]
    calls = []

    def fake_get(url, timeout=30):
        calls.append(url)
        return {"rows": first if len(calls) == 1 else second}

    monkeypatch.setattr(dus, "_get_json", fake_get)
    rows = dus._fetch_rows("org/ds", "cfg", "train", 150)
    assert len(rows) == 101
    assert rows[-1] == {"x": 100}
    assert "offset=0" in calls[0]
    assert "offset=100" in calls[1]


def test_fetch_rows_stops_on_empty_batch(monkeypatch):
    monkeypatch.setattr(dus, "_get_json", lambda *_a, **_k: {"rows": []})
    assert dus._fetch_rows("org/ds", "default", "train", 10) == []


def test_numeric_matrix_empty_and_mixed_columns():
    X, labels, cols = dus._numeric_matrix([], None)
    assert X.shape == (0, 0) and labels is None and cols == []

    rows = [
        {"a": 1, "b": 2.0, "flag": True, "text": "x", "label": "dog"},
        {"a": 2, "b": 3.0, "flag": False, "text": "y", "label": "cat"},
    ]
    X, labels, cols = dus._numeric_matrix(rows, "label")
    assert cols == ["a", "b"]
    assert X.shape == (2, 2)
    assert labels is not None
    assert labels.tolist() == [1, 0]


def test_scan_dataset_fetch_error_empty_and_schema_failures(monkeypatch):
    def fail_fetch(*_a, **_k):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(dus, "_fetch_rows", fail_fetch)
    result = dus.scan_hf_dataset("org/ds")
    assert result.errors and "failed to fetch rows" in result.errors[0]

    result = dus.scan_hf_dataset("org/ds", _rows_override=[])
    assert result.errors == ["no rows returned"]

    rows_no_label = [{"x": 1.0}, {"x": 2.0}]
    result = dus.scan_hf_dataset("org/ds", _rows_override=rows_no_label)
    assert "no label column" in result.errors[0]

    rows_no_numeric = [{"text": "a", "label": 0}, {"text": "b", "label": 1}]
    result = dus.scan_hf_dataset("org/ds", _rows_override=rows_no_numeric)
    assert "no numeric feature" in result.errors[0]


def test_scan_dataset_valid_result_and_to_dict(monkeypatch):
    rows = [
        {"x": 0.0, "y": 0.0, "label": 0},
        {"x": 1.0, "y": 1.0, "label": 0},
        {"x": 9.0, "y": 9.0, "label": 1},
    ]
    fake_report = SimpleNamespace(
        results=[
            SimpleNamespace(sample_idx=0, is_poisoned=False),
            SimpleNamespace(sample_idx=1, is_poisoned=True),
            SimpleNamespace(sample_idx=2, is_poisoned=True),
        ],
        per_class_stats={
            0: {"flagged": 1},
            1: {"flagged": 1},
            2: {"flagged": 0, "skipped": True},
        },
    )
    monkeypatch.setattr(dus, "spectral_detect", lambda _x, _labels: fake_report)
    result = dus.scan_hf_dataset("org/ds", _rows_override=rows)
    assert result.poison_suspected is True
    assert result.suspected_poison_rows == [1, 2]
    assert result.per_class_flagged == {0: 1, 1: 1}
    payload = result.to_dict()
    assert payload["verdict"] == "POISON_SUSPECTED"
    assert payload["suspected_poison_count"] == 2


def test_scan_dataset_input_bounds_and_bad_reference():
    with pytest.raises(ValueError, match="Could not parse"):
        dus.scan_hf_dataset("https://example.com/nope")
    for value in (0, 1001, True, 1.5):
        with pytest.raises(ValueError, match="max_rows"):
            dus.scan_hf_dataset("org/ds", max_rows=cast(Any, value))
