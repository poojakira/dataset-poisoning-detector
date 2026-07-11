"""Tests for the FastAPI service endpoints.

Verifies health endpoint, single-sample scoring, batch scoring, and
WebSocket streaming using the FastAPI TestClient.
"""

from fastapi.testclient import TestClient

from poison_detector.api import app


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


def test_score_endpoint_returns_scoring_result():
    """POST /score returns a valid scoring result with all fields.

    Submits a sample feature vector and verifies the response includes
    score, is_poisoned, method_votes, and latency_ms.
    """
    client = TestClient(app)
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


def test_batch_endpoint_handles_multiple_samples():
    """POST /batch scores multiple samples and returns aggregated results.

    Submits a batch of 3 samples and verifies the response structure
    including per-sample results and batch-level statistics.
    """
    client = TestClient(app)
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


def test_websocket_stream_receives_events():
    """WebSocket /stream endpoint accepts connections and echoes ack events.

    Connects via WebSocket, sends a text message, and verifies that the
    server responds with an acknowledgment event.
    """
    client = TestClient(app)
    with client.websocket_connect("/stream") as ws:
        # Send a ping message
        ws.send_text("ping")
        # Should receive an ack event
        response = ws.receive_json()
        assert response["event"] == "ack"
        assert response["data"] == "ping"
