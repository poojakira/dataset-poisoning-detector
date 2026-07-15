"""
FastAPI service for real-time poisoning detection.

Provides HTTP endpoints for single-sample scoring, batch scoring, health
checks, Prometheus-compatible metrics, and a WebSocket feed for real-time
dashboard updates.

Threat Model Assumptions:
    - API clients are partially trusted (internal services, not public internet).
      Rate limiting prevents abuse but does not replace authentication.
    - An attacker who can flood the /score endpoint may attempt to overwhelm
      the detector, causing legitimate samples to be processed in degraded
      (statistical-only) mode. Rate limiting and backpressure mitigate this.
    - Request payloads contain sample data which is untrusted. All inputs are
      validated via Pydantic models before processing.

Honest Limitations:
    - Rate limiting is per-process in-memory. It does not work correctly
      behind a load balancer with multiple replicas without an external
      rate limit store (Redis, etc.).
    - The WebSocket /stream endpoint broadcasts all detection events to all
      connected clients. There is no per-client filtering or access control
      beyond the initial connection.
    - Batch scoring (/batch) processes sequentially within the request. For
      true async processing, submit to the pipeline (Kafka/Redis) and poll
      for results.
    - Health check (/health) reflects local process state only. It does not
      verify downstream dependencies (database, message queue connectivity).

Security Notes:
    - All inputs validated via Pydantic. No raw dict access from request bodies.
    - API key passed via X-API-Key header. Set POISON_DETECTOR_API_KEY for protected scoring endpoints, or set POISON_DETECTOR_ALLOW_ANONYMOUS=true only for local development.
    - No eval(), exec(), or dynamic code execution from request data.
    - WebSocket connections require the same API key via x-api-key header or api_key query parameter.
    - Response bodies never echo raw sample data back to prevent data leakage
      between tenants.
"""

from __future__ import annotations

import os
import time
from collections import defaultdict
from secrets import compare_digest
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, field_validator

from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from .stream import StreamingDetector, ScoringResult
from .config import DetectorConfig


MAX_FEATURES_PER_SAMPLE = 10000
MAX_BATCH_SAMPLES = 128
MAX_BATCH_TOTAL_FEATURES = 50000


# --- Pydantic Request/Response Models ---


class SampleRequest(BaseModel):
    """Request body for single-sample scoring."""

    features: list[float] = Field(
        ...,
        min_length=1,
        max_length=MAX_FEATURES_PER_SAMPLE,
        description="Feature vector for the sample to score (max 10,000 features)",
    )
    source: str = Field(
        default="api",
        max_length=256,
        description="Identifier for the data source",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        max_length=128,
        description="Optional metadata to attach to the scoring result",
    )


class ScoringResponse(BaseModel):
    """Response body for single-sample scoring."""

    score: float = Field(description="Anomaly score in [0, 1]. Higher = more anomalous")
    is_poisoned: bool = Field(
        description="Whether the sample exceeds the poisoning threshold"
    )
    method_votes: dict[str, bool] = Field(description="Per-method poison votes")
    latency_ms: float = Field(description="Scoring latency in milliseconds")


class BatchRequest(BaseModel):
    """Request body for batch scoring."""

    samples: list[list[float]] = Field(
        ...,
        min_length=1,
        max_length=MAX_BATCH_SAMPLES,
        description="List of feature vectors to score (max 128 samples, 50,000 total features)",
    )
    source: str = Field(
        default="api",
        max_length=256,
        description="Identifier for the data source",
    )

    @field_validator("samples")
    @classmethod
    def validate_samples(cls, v: list[list[float]]) -> list[list[float]]:
        """Ensure all samples have at least one feature and stay within bounded work."""
        for i, sample in enumerate(v):
            if len(sample) < 1:
                raise ValueError(f"Sample at index {i} must have at least 1 feature")
            if len(sample) > MAX_FEATURES_PER_SAMPLE:
                raise ValueError(
                    f"Sample at index {i} exceeds {MAX_FEATURES_PER_SAMPLE} features"
                )
        total_features = sum(len(sample) for sample in v)
        if total_features > MAX_BATCH_TOTAL_FEATURES:
            raise ValueError(f"Batch exceeds {MAX_BATCH_TOTAL_FEATURES} total features")
        return v


class BatchResponse(BaseModel):
    """Response body for batch scoring."""

    results: list[ScoringResponse] = Field(
        description="Scoring results for each sample"
    )
    total_samples: int = Field(description="Number of samples scored")
    poisoned_count: int = Field(description="Number of samples flagged as poisoned")
    batch_latency_ms: float = Field(description="Total batch processing time in ms")


class HealthResponse(BaseModel):
    """Response body for health check."""

    status: str = Field(description="Service status: healthy, degraded, or unhealthy")
    samples_processed: int = Field(description="Total samples processed since startup")
    poison_rate: float = Field(description="Rolling poison detection rate")
    avg_latency_ms: float = Field(description="Average scoring latency in ms")
    baseline_size: int = Field(description="Number of samples in the baseline model")
    queue_depth: int = Field(description="Current processing queue depth")
    uptime_seconds: float = Field(description="Seconds since service start")


class StatsResponse(BaseModel):
    """Response body for detector statistics."""

    samples_seen: int
    poison_count: int
    poison_rate: float
    avg_latency_ms: float
    drift_detected: bool
    baseline_size: int
    window_fill: float


# --- Rate Limiting ---


class RateLimiter:
    """Simple in-memory sliding-window rate limiter.

    Tracks request counts per API key within a time window.
    Not suitable for multi-process deployments without external state.
    """

    def __init__(self, max_requests: int = 100, window_seconds: int = 60) -> None:
        """Initialize rate limiter.

        Args:
            max_requests: Maximum requests per window per API key.
            window_seconds: Window size in seconds.
        """
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, api_key: str) -> bool:
        """Check if a request is allowed under the rate limit.

        Args:
            api_key: The API key making the request.

        Returns:
            True if allowed, False if rate limited.
        """
        now = time.time()
        window_start = now - self._window_seconds

        # Clean old entries
        self._requests[api_key] = [
            t for t in self._requests[api_key] if t > window_start
        ]

        if len(self._requests[api_key]) >= self._max_requests:
            return False

        self._requests[api_key].append(now)
        return True


# --- WebSocket Manager ---


class ConnectionManager:
    """Manages WebSocket connections for real-time event streaming."""

    def __init__(self) -> None:
        self._active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new WebSocket connection."""
        await websocket.accept()
        self._active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection."""
        if websocket in self._active_connections:
            self._active_connections.remove(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Broadcast a message to all connected clients.

        Catches all exceptions during send to prevent dead connections
        from accumulating (e.g., ConnectionResetError, OSError).
        """
        disconnected: list[WebSocket] = []
        for connection in self._active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)

        for conn in disconnected:
            self.disconnect(conn)

    @property
    def connection_count(self) -> int:
        """Number of active WebSocket connections."""
        return len(self._active_connections)


# --- Application Setup ---

_start_time = time.time()
_config = DetectorConfig()
_detector = StreamingDetector(
    window_size=_config.streaming.window_size,
    contamination=_config.thresholds.isolation_contamination,
    drift_sensitivity=_config.streaming.drift_sensitivity,
    refit_interval=_config.streaming.refit_interval,
    zscore_threshold=_config.thresholds.zscore_threshold,
    vote_threshold=_config.thresholds.ensemble_vote_threshold,
)
_rate_limiter = RateLimiter(max_requests=100, window_seconds=60)
_PUBLIC_PATHS = {"/health", "/stats", "/metrics"}
_PROTECTED_PATHS = {"/score", "/batch"}


def _allow_anonymous() -> bool:
    return os.environ.get("POISON_DETECTOR_ALLOW_ANONYMOUS", "").lower() in {
        "1",
        "true",
        "yes",
    }


def _configured_api_key() -> str:
    return os.environ.get("POISON_DETECTOR_API_KEY", "")


def _authorized_api_key(provided: str | None) -> bool:
    expected = _configured_api_key()
    if not expected:
        return _allow_anonymous()
    return provided is not None and compare_digest(provided, expected)


_ws_manager = ConnectionManager()

app = FastAPI(
    title="Poison Detector API",
    description="Real-time dataset poisoning detection service",
    version="0.1.0",
)


# --- Middleware ---


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next: Any) -> Any:
    ## Authenticate protected endpoints, then rate limit by API key bucket.
    path = request.url.path
    if path in _PUBLIC_PATHS:
        return await call_next(request)

    provided_key = request.headers.get("X-API-Key")
    if path in _PROTECTED_PATHS and not _authorized_api_key(provided_key):
        status_code = (
            503 if not _configured_api_key() and not _allow_anonymous() else 401
        )
        detail = (
            "POISON_DETECTOR_API_KEY is not configured."
            if status_code == 503
            else "Invalid or missing API key."
        )
        return JSONResponse(status_code=status_code, content={"detail": detail})

    api_key = provided_key or "anonymous"
    if not _rate_limiter.is_allowed(api_key):
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Try again later."},
        )
    return await call_next(request)


# --- Endpoints ---


@app.post("/score", response_model=ScoringResponse)
async def score_sample(request: SampleRequest) -> ScoringResponse:
    """Score a single sample for poisoning indicators.

    Returns anomaly score, poison flag, per-method votes, and latency.
    Target latency: <10ms for statistical-only, <50ms with isolation forest.
    """
    try:
        result: ScoringResult = _detector.score_sample(request.features)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Scoring error: {type(e).__name__}",
        )

    response = ScoringResponse(
        score=result.score,
        is_poisoned=result.is_poisoned,
        method_votes=result.method_votes,
        latency_ms=result.latency_ms,
    )

    # Broadcast to WebSocket clients if poisoned
    if result.is_poisoned:
        await _ws_manager.broadcast(
            {
                "event": "poison_detected",
                "score": result.score,
                "method_votes": result.method_votes,
                "source": request.source,
                "latency_ms": result.latency_ms,
            }
        )

    return response


@app.post("/batch", response_model=BatchResponse)
async def score_batch(request: BatchRequest) -> BatchResponse:
    """Score a bounded batch of samples.

    Processes samples sequentially and returns aggregated results.
    For true async processing, submit to the pipeline queue instead.
    """
    start = time.perf_counter()

    results: list[ScoringResponse] = []
    poisoned_count = 0

    try:
        for sample in request.samples:
            result = _detector.score_sample(sample)
            results.append(
                ScoringResponse(
                    score=result.score,
                    is_poisoned=result.is_poisoned,
                    method_votes=result.method_votes,
                    latency_ms=result.latency_ms,
                )
            )
            if result.is_poisoned:
                poisoned_count += 1
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Batch scoring error at sample {len(results)}: {type(e).__name__}",
        )

    elapsed_ms = (time.perf_counter() - start) * 1000.0

    # Broadcast batch summary to WebSocket clients
    if poisoned_count > 0:
        await _ws_manager.broadcast(
            {
                "event": "batch_scored",
                "total_samples": len(request.samples),
                "poisoned_count": poisoned_count,
                "source": request.source,
                "batch_latency_ms": elapsed_ms,
            }
        )

    return BatchResponse(
        results=results,
        total_samples=len(request.samples),
        poisoned_count=poisoned_count,
        batch_latency_ms=elapsed_ms,
    )


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint.

    Returns service status based on current detection metrics.
    Status logic:
        - healthy: all systems nominal
        - degraded: high poison rate or elevated latency
        - unhealthy: critical failures detected
    """
    stats = _detector.get_stats()
    uptime = time.time() - _start_time

    # Determine status
    status = "healthy"
    if stats.poison_rate > 0.2:
        status = "degraded"
    if stats.avg_latency_ms > 1000:
        status = "unhealthy"

    return HealthResponse(
        status=status,
        samples_processed=stats.samples_seen,
        poison_rate=stats.poison_rate,
        avg_latency_ms=stats.avg_latency_ms,
        baseline_size=stats.baseline_size,
        queue_depth=0,
        uptime_seconds=uptime,
    )


@app.get("/stats", response_model=StatsResponse)
async def get_stats() -> StatsResponse:
    """Get detector statistics.

    Returns current state of the streaming detector including
    sample counts, poison rate, latency, and drift status.
    """
    stats = _detector.get_stats()
    return StatsResponse(
        samples_seen=stats.samples_seen,
        poison_count=stats.poison_count,
        poison_rate=stats.poison_rate,
        avg_latency_ms=stats.avg_latency_ms,
        drift_detected=stats.drift_detected,
        baseline_size=stats.baseline_size,
        window_fill=stats.window_fill,
    )


@app.get("/metrics")
async def prometheus_metrics() -> PlainTextResponse:
    """Prometheus-compatible metrics endpoint.

    Returns all registered Prometheus metrics in the text exposition format.
    Scrape this endpoint from your Prometheus instance.
    """
    return PlainTextResponse(
        content=generate_latest().decode("utf-8"),
        media_type=CONTENT_TYPE_LATEST,
    )


@app.websocket("/stream")
async def websocket_stream(websocket: WebSocket) -> None:
    ## WebSocket endpoint for real-time detection event streaming.
    ## Prefer x-api-key header authentication. The api_key query parameter is
    ## accepted for browser clients, but URLs can leak through logs/history.
    provided_key = websocket.headers.get("x-api-key") or websocket.query_params.get(
        "api_key"
    )
    if not _authorized_api_key(provided_key):
        await websocket.close(code=1008, reason="Invalid or missing API key")
        return

    await _ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive, listen for client messages (ping/pong)
            data = await websocket.receive_text()
            # Echo back as acknowledgment
            await websocket.send_json({"event": "ack", "data": data})
    except WebSocketDisconnect:
        _ws_manager.disconnect(websocket)
