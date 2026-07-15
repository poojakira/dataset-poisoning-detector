## Tests for the FastAPI service endpoints.

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from poison_detector.api import app, _detector

API_KEY = "test-api-key"
AUTH_HEADERS = {"X-API-Key": API_KEY}


def test_health_endpoint_returns_200_with_status_fields():
    client = TestClient(app)
    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("healthy", "degraded", "unhealthy")
    assert "samples_processed" in data
    assert "poison_rate" in data
    assert "avg_latency_ms" in data
    assert "baseline_size" in data
    assert "queue_depth" in data
    assert isinstance(data["uptime_seconds"], (int, float))
    assert data["uptime_seconds"] >= 0


def test_score_endpoint_returns_scoring_result(monkeypatch):
    monkeypatch.setenv("POISON_DETECTOR_API_KEY", API_KEY)
    _detector.reset()
    client = TestClient(app)
    payload = {"features": [1.0, 2.0, 3.0, 4.0, 5.0]}
    response = client.post("/score", json=payload, headers=AUTH_HEADERS)

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data["score"], (int, float))
    assert 0.0 <= data["score"] <= 1.0
    assert isinstance(data["is_poisoned"], bool)
    assert isinstance(data["method_votes"], dict)
    assert data["latency_ms"] >= 0.0


def test_batch_endpoint_handles_multiple_samples(monkeypatch):
    monkeypatch.setenv("POISON_DETECTOR_API_KEY", API_KEY)
    _detector.reset()
    client = TestClient(app)
    payload = {
        "samples": [
            [1.0, 2.0, 3.0, 4.0, 5.0],
            [1.1, 2.1, 3.1, 4.1, 5.1],
            [1.2, 2.2, 3.2, 4.2, 5.2],
        ]
    }
    response = client.post("/batch", json=payload, headers=AUTH_HEADERS)

    assert response.status_code == 200
    data = response.json()
    assert len(data["results"]) == 3
    assert data["total_samples"] == 3
    assert isinstance(data["poisoned_count"], int)
    assert data["batch_latency_ms"] >= 0.0
    for result in data["results"]:
        assert "score" in result
        assert "is_poisoned" in result
        assert "method_votes" in result
        assert "latency_ms" in result


def test_batch_endpoint_rejects_excess_total_features(monkeypatch):
    monkeypatch.setenv("POISON_DETECTOR_API_KEY", API_KEY)
    client = TestClient(app)
    payload = {"samples": [[0.0] * 10000 for _ in range(6)]}
    response = client.post("/batch", json=payload, headers=AUTH_HEADERS)

    assert response.status_code == 422
    assert "50000" in response.text


@pytest.mark.parametrize("feature", [float("nan"), float("inf"), float("-inf")])
def test_score_endpoint_rejects_non_finite_features_without_state_mutation(
    monkeypatch, feature
):
    monkeypatch.setenv("POISON_DETECTOR_API_KEY", API_KEY)
    _detector.reset()
    client = TestClient(app)

    response = client.post(
        "/score",
        content=f'{{"features":[1.0,{feature},3.0]}}',
        headers={**AUTH_HEADERS, "Content-Type": "application/json"},
    )

    assert response.status_code == 422
    assert _detector.get_stats().samples_seen == 0


def test_score_endpoint_rejects_wrong_dimension_without_state_mutation(monkeypatch):
    monkeypatch.setenv("POISON_DETECTOR_API_KEY", API_KEY)
    _detector.reset()
    client = TestClient(app)

    first = client.post(
        "/score", json={"features": [1.0, 2.0, 3.0]}, headers=AUTH_HEADERS
    )
    second = client.post("/score", json={"features": [1.0, 2.0]}, headers=AUTH_HEADERS)

    assert first.status_code == 200
    assert second.status_code == 422
    assert _detector.get_stats().samples_seen == 1


def test_batch_endpoint_rejects_mixed_dimensions_without_partial_mutation(monkeypatch):
    monkeypatch.setenv("POISON_DETECTOR_API_KEY", API_KEY)
    _detector.reset()
    client = TestClient(app)

    response = client.post(
        "/batch",
        json={"samples": [[1.0, 2.0, 3.0], [1.0, 2.0]]},
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 422
    assert _detector.get_stats().samples_seen == 0


def test_stats_and_metrics_require_api_key(monkeypatch):
    monkeypatch.setenv("POISON_DETECTOR_API_KEY", API_KEY)
    client = TestClient(app)

    assert client.get("/stats").status_code == 401
    assert client.get("/metrics").status_code == 401
    assert client.get("/stats", headers=AUTH_HEADERS).status_code == 200
    assert client.get("/metrics", headers=AUTH_HEADERS).status_code == 200


def test_websocket_stream_receives_events(monkeypatch):
    monkeypatch.setenv("POISON_DETECTOR_API_KEY", API_KEY)
    client = TestClient(app)
    with client.websocket_connect("/stream", headers=AUTH_HEADERS) as ws:
        ws.send_text("ping")
        response = ws.receive_json()
        assert response["event"] == "ack"
        assert response["data"] == "ping"


def test_websocket_rejects_query_api_key(monkeypatch):
    monkeypatch.setenv("POISON_DETECTOR_API_KEY", API_KEY)
    client = TestClient(app)
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/stream?api_key={API_KEY}"):
            pass


def test_score_endpoint_fails_closed_without_config(monkeypatch):
    monkeypatch.delenv("POISON_DETECTOR_API_KEY", raising=False)
    monkeypatch.delenv("POISON_DETECTOR_ALLOW_ANONYMOUS", raising=False)
    client = TestClient(app)
    response = client.post("/score", json={"features": [1.0]})
    assert response.status_code == 503


def test_score_endpoint_rejects_bad_api_key(monkeypatch):
    monkeypatch.setenv("POISON_DETECTOR_API_KEY", API_KEY)
    client = TestClient(app)
    response = client.post(
        "/score",
        json={"features": [1.0]},
        headers={"X-API-Key": "wrong"},
    )
    assert response.status_code == 401
