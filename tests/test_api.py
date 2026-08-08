"""Tests for the FastAPI service endpoints.

Verifies health endpoint, single-sample scoring, batch scoring,
WebSocket streaming, and API key authentication using the FastAPI TestClient.

Skipped automatically when the optional FastAPI stack is not installed
(FastAPI is an optional/`realtime` dependency, not part of `[dev]`).
"""

import os
import pytest

pytest.importorskip("fastapi", reason="FastAPI optional dependency not installed")
pytest.importorskip("httpx", reason="httpx (TestClient dependency) not installed")

from fastapi.testclient import TestClient

from poison_detector.api import app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _client_with_key(api_key: str) -> TestClient:
    """Return a TestClient that sends X-API-Key on every request."""
    client = TestClient(app, headers={"X-API-Key": api_key})
    return client


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def test_score_returns_401_when_no_api_key(monkeypatch):
    """POST /score must return 401 when X-API-Key header is absent and API_KEY is set."""
    monkeypatch.setenv("API_KEY", "test-secret")
    # Reimport to pick up the env var (module-level _EXPECTED_API_KEY).
    import importlib
    import poison_detector.api as api_module

    importlib.reload(api_module)
    client = TestClient(api_module.app)  # no X-API-Key header
    response = client.post("/score", json={"features": [1.0, 2.0, 3.0]})
    assert response.status_code == 401


def test_score_returns_401_when_wrong_api_key(monkeypatch):
    """POST /score must return 401 when X-API-Key header contains a wrong value."""
    monkeypatch.setenv("API_KEY", "correct-secret")
    import importlib
    import poison_detector.api as api_module

    importlib.reload(api_module)
    client = TestClient(api_module.app, headers={"X-API-Key": "wrong-key"})
    response = client.post("/score", json={"features": [1.0, 2.0, 3.0]})
    assert response.status_code == 401


def test_health_does_not_require_api_key(monkeypatch):
    """GET /health must return 200 even without an X-API-Key header."""
    monkeypatch.setenv("API_KEY", "test-secret")
    import importlib
    import poison_detector.api as api_module

    importlib.reload(api_module)
    client = TestClient(api_module.app)  # no X-API-Key header
    response = client.get("/health")
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# Functional (authenticated)
# ---------------------------------------------------------------------------


def test_health_endpoint_returns_200_with_status_fields():
    """GET /health returns 200 with all expected status fields.

    The health response must include status, samples_processed, poison_rate,
    avg_latency_ms, baseline_size, queue_depth, and uptime_seconds.
    """
    client = TestClient(app)
    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()

    assert "status" in data
    assert data["status"] in ("healthy", "degraded", "unhealthy")
    assert "samples_processed" in data
    assert "poison_rate" in data
    assert "avg_latency_ms" in data
    assert "baseline_size" in data
    assert "queue_depth" in data
    assert "uptime_seconds" in data
    assert isinstance(data["uptime_seconds"], (int, float))
    assert data["uptime_seconds"] >= 0


def test_score_endpoint_returns_scoring_result(monkeypatch):
    """POST /score returns a valid scoring result with all fields.

    Submits a sample feature vector with a valid API key and verifies the
    response includes score, is_poisoned, method_votes, and latency_ms.
    """
    monkeypatch.setenv("API_KEY", "test-secret")
    import importlib
    import poison_detector.api as api_module

    importlib.reload(api_module)
    client = TestClient(api_module.app, headers={"X-API-Key": "test-secret"})
    payload = {"features": [1.0, 2.0, 3.0, 4.0, 5.0]}
    response = client.post("/score", json=payload)

    assert response.status_code == 200
    data = response.json()

    assert "score" in data
    assert isinstance(data["score"], (int, float))
    assert 0.0 <= data["score"] <= 1.0
    assert "is_poisoned" in data
    assert isinstance(data["is_poisoned"], bool)
    assert "method_votes" in data
    assert isinstance(data["method_votes"], dict)
    assert "latency_ms" in data
    assert data["latency_ms"] >= 0.0


def test_batch_endpoint_handles_multiple_samples(monkeypatch):
    """POST /batch scores multiple samples and returns aggregated results.

    Submits a batch of 3 samples with a valid API key and verifies the
    response structure including per-sample results and batch-level statistics.
    """
    monkeypatch.setenv("API_KEY", "test-secret")
    import importlib
    import poison_detector.api as api_module

    importlib.reload(api_module)
    client = TestClient(api_module.app, headers={"X-API-Key": "test-secret"})
    payload = {
        "samples": [
            [1.0, 2.0, 3.0, 4.0, 5.0],
            [1.1, 2.1, 3.1, 4.1, 5.1],
            [1.2, 2.2, 3.2, 4.2, 5.2],
        ]
    }
    response = client.post("/batch", json=payload)

    assert response.status_code == 200
    data = response.json()

    assert "results" in data
    assert len(data["results"]) == 3
    assert "total_samples" in data
    assert data["total_samples"] == 3
    assert "poisoned_count" in data
    assert isinstance(data["poisoned_count"], int)
    assert "batch_latency_ms" in data
    assert data["batch_latency_ms"] >= 0.0

    # Each result should have the standard scoring fields
    for result in data["results"]:
        assert "score" in result
        assert "is_poisoned" in result
        assert "method_votes" in result
        assert "latency_ms" in result


def test_websocket_stream_receives_events(monkeypatch):
    """WebSocket /stream endpoint accepts connections and echoes ack events.

    Connects via WebSocket with a valid API key, sends a text message, and
    verifies that the server responds with an acknowledgment event.
    """
    monkeypatch.setenv("API_KEY", "test-secret")
    import importlib
    import poison_detector.api as api_module

    importlib.reload(api_module)
    client = TestClient(api_module.app, headers={"X-API-Key": "test-secret"})
    with client.websocket_connect("/stream") as ws:
        # Send a ping message
        ws.send_text("ping")
        # Should receive an ack event
        response = ws.receive_json()
        assert response["event"] == "ack"
        assert response["data"] == "ping"
