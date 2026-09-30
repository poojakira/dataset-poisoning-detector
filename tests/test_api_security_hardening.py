import asyncio
import threading

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

from poison_detector import api
from poison_detector.dataset_url_scanner import _validate_api_url, scan_hf_dataset


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_batch_rejects_nonfinite_features(value):
    with pytest.raises(ValidationError):
        api.BatchRequest(samples=[[value]])


def test_chunked_body_is_bounded(monkeypatch):
    monkeypatch.setattr(api, "_MAX_REQUEST_BYTES", 20)
    monkeypatch.setattr(api, "_EXPECTED_API_KEY", "test-secret")
    response = TestClient(api.app).post(
        "/score", headers={"X-API-Key": "test-secret"}, content=iter([b"x" * 15, b"y" * 15])
    )
    assert response.status_code == 413


def test_validation_does_not_echo_sensitive_features(monkeypatch):
    monkeypatch.setattr(api, "_EXPECTED_API_KEY", "test-secret")
    response = TestClient(api.app).post(
        "/score", headers={"X-API-Key": "test-secret"}, json={"features": ["private-payload"]}
    )
    assert response.status_code == 422
    assert "private-payload" not in response.text


def test_readiness_does_not_disclose_baseline_path(monkeypatch):
    monkeypatch.setattr(api, "_EXPECTED_API_KEY", "test-secret")
    monkeypatch.setattr(api, "_BASELINE_LOAD_ERROR", "/private/baseline-path")
    response = TestClient(api.app).get("/ready")
    assert response.status_code == 503
    assert "/private/baseline-path" not in response.text


def test_failed_dataset_scan_is_not_clean():
    result = scan_hf_dataset("org/model", _rows_override=[])
    assert result.to_dict()["verdict"] == "ERROR"


@pytest.mark.parametrize(
    "url",
    [
        "https://attacker.example/x",
        "http://datasets-server.huggingface.co/x",
        "https://datasets-server.huggingface.co:444/x",
    ],
)
def test_dataset_api_rejects_untrusted_origins(url):
    with pytest.raises(ValueError):
        _validate_api_url(url)


def test_rows_budget_rejects_unbounded_requests():
    with pytest.raises(ValueError):
        scan_hf_dataset("org/model", max_rows=1001)


def test_timed_out_worker_keeps_capacity():
    async def scenario():
        slots = asyncio.Semaphore(1)
        release = threading.Event()

        def slow(_):
            release.wait(2)

        try:
            with pytest.raises(asyncio.TimeoutError):
                await api._run_bounded(slow, None, slots, 0.01)
            assert slots.locked()
            with pytest.raises(HTTPException) as exc:
                await api._run_bounded(slow, None, slots, 0.01)
            assert exc.value.status_code == 503
        finally:
            release.set()
            await asyncio.gather(*api._active_jobs)
        assert not slots.locked()

    asyncio.run(scenario())
