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
    - API key passed via X-API-Key header, validated in api_key_auth_middleware.
      Returns HTTP 401 if the header is absent, empty, or does not match the
      value in os.environ['API_KEY']. The service starts in fail-closed mode
      if API_KEY is not set (all protected endpoints return 401).
    - No eval(), exec(), or dynamic code execution from request data.
    - WebSocket /stream requires the same X-API-Key on the initial upgrade
      request. After authentication, events are broadcast to all connected
      clients; there is no per-client authorization or event filtering.
    - Response bodies never echo raw sample data back to prevent data leakage
      between tenants.
"""

from __future__ import annotations

import asyncio
import hmac
import math
import os
import time
import traceback
from pathlib import Path
from collections import defaultdict
from dataclasses import asdict
from typing import Any

import numpy as np

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, field_validator

from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from .stream import StreamingDetector, ScoringResult
from .config import DetectorConfig


# --- Pydantic Request/Response Models ---


class SampleRequest(BaseModel):
    """Request body for single-sample scoring."""

    features: list[float] = Field(
        ...,
        min_length=1,
        max_length=100000,
        description="Feature vector for the sample to score",
    )

    @field_validator("features")
    @classmethod
    def validate_features(cls, values: list[float]) -> list[float]:
        if not all(math.isfinite(v) for v in values):
            raise ValueError("features must contain only finite numeric values")
        return values
    source: str = Field(
        default="api",
        max_length=256,
        description="Identifier for the data source",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional metadata to attach to the scoring result",
    )


class ScoringResponse(BaseModel):
    """Response body for single-sample scoring."""

    score: float = Field(description="Anomaly score in [0, 1]. Higher = more anomalous")
    is_poisoned: bool = Field(description="Whether the sample exceeds the poisoning threshold")
    method_votes: dict[str, bool] = Field(description="Per-method poison votes")
    latency_ms: float = Field(description="Scoring latency in milliseconds")


class BatchRequest(BaseModel):
    """Request body for batch scoring."""

    samples: list[list[float]] = Field(
        ...,
        min_length=1,
        max_length=1000,
        description="List of feature vectors to score (max 1000)",
    )
    source: str = Field(
        default="api",
        max_length=256,
        description="Identifier for the data source",
    )

    @field_validator("samples")
    @classmethod
    def validate_samples(cls, v: list[list[float]]) -> list[list[float]]:
        """Ensure all samples have at least one feature."""
        total_values = 0
        expected_dim: int | None = None
        for i, sample in enumerate(v):
            if len(sample) < 1:
                raise ValueError(f"Sample at index {i} must have at least 1 feature")
            if len(sample) > 100000:
                raise ValueError(f"Sample at index {i} exceeds 100000 features")
            if expected_dim is None:
                expected_dim = len(sample)
            elif len(sample) != expected_dim:
                raise ValueError(
                    f"All samples must have the same feature dimension; "
                    f"sample 0 has {expected_dim}, sample {i} has {len(sample)}"
                )
            total_values += len(sample)
            if total_values > 200000:
                raise ValueError("Batch exceeds 200000 total feature values")
        return v


class BatchResponse(BaseModel):
    """Response body for batch scoring."""

    results: list[ScoringResponse] = Field(description="Scoring results for each sample")
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
    baseline_ready: bool = Field(description="Whether a known-clean startup baseline is loaded")


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
        self._requests[api_key] = [t for t in self._requests[api_key] if t > window_start]

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
_ws_manager = ConnectionManager()

_MAX_REQUEST_BYTES = int(os.environ.get("POISON_MAX_REQUEST_BYTES", str(2 * 1024 * 1024)))
_MIN_BASELINE_SAMPLES = int(os.environ.get("POISON_MIN_BASELINE_SAMPLES", "50"))
_BASELINE_PATH = os.environ.get("POISON_BASELINE_PATH", "")
_BASELINE_LOAD_ERROR: str | None = None


def _load_startup_baseline() -> None:
    """Load a known-clean baseline from an immutable NPZ artifact.

    The file must contain a numeric 2D array named 'features'. Pickled object
    arrays are rejected. A missing/invalid baseline leaves the process live
    but not ready; scoring endpoints fail closed with HTTP 503.
    """
    global _BASELINE_LOAD_ERROR
    if not _BASELINE_PATH:
        _BASELINE_LOAD_ERROR = "POISON_BASELINE_PATH is not configured"
        return

    path = Path(_BASELINE_PATH)
    try:
        if not path.is_file():
            raise ValueError(f"baseline file does not exist: {path}")
        with np.load(path, allow_pickle=False) as data:
            if "features" not in data:
                raise ValueError("baseline NPZ must contain a 'features' array")
            features = np.asarray(data["features"], dtype=np.float64)
        if features.ndim != 2:
            raise ValueError("baseline features must be a 2D numeric array")
        if features.shape[0] < _MIN_BASELINE_SAMPLES:
            raise ValueError(
                f"baseline requires at least {_MIN_BASELINE_SAMPLES} samples; "
                f"got {features.shape[0]}"
            )
        if features.shape[1] < 1 or features.shape[1] > 100000:
            raise ValueError("baseline feature dimension must be between 1 and 100000")
        if not np.isfinite(features).all():
            raise ValueError("baseline contains NaN or infinity")
        _detector.update_baseline(features)
        _BASELINE_LOAD_ERROR = None
    except (OSError, ValueError) as exc:
        _BASELINE_LOAD_ERROR = str(exc)


def _baseline_ready() -> bool:
    return (
        _BASELINE_LOAD_ERROR is None
        and _detector.get_stats().baseline_size >= _MIN_BASELINE_SAMPLES
    )


_load_startup_baseline()

app = FastAPI(
    title="Poison Detector API",
    description="Real-time dataset poisoning detection service",
    version="0.1.0",
)


# --- Middleware ---

# Endpoints that bypass authentication (monitoring/health checks only).
_UNAUTHENTICATED_PATHS = frozenset({"/health", "/ready"})

# Resolve expected API key at module load time. If API_KEY is not set the
# service starts in fail-closed mode: all authenticated endpoints return 401.
_EXPECTED_API_KEY: str = os.environ.get("API_KEY", "")


def _is_valid_api_key(provided_key: str) -> bool:
    """Return whether a provided API key is configured and valid."""
    return bool(
        _EXPECTED_API_KEY and provided_key and hmac.compare_digest(provided_key, _EXPECTED_API_KEY)
    )


@app.middleware("http")
async def api_key_auth_middleware(request: Request, call_next: Any) -> Any:
    """Enforce X-API-Key authentication on all non-monitoring endpoints.

    Security properties:
        - Reads the expected key from os.environ['API_KEY'] at startup.
          The key is never hardcoded and never logged or echoed in responses.
        - Returns HTTP 401 if API_KEY env var is not set (fail-closed: no
          implicit open access when the secret is missing).
        - Returns HTTP 401 if the X-API-Key header is absent or does not
          match the expected value (constant-time comparison via hmac.compare_digest).
        - Skips auth only for /health so load balancer liveness probes remain
          available. Operational /stats and /metrics data require authentication.
        - WebSocket /stream endpoint requires the X-API-Key header in the
          initial HTTP upgrade request.
    """
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > _MAX_REQUEST_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request body exceeds configured size limit."},
                )
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid Content-Length header."},
            )

    if request.url.path in _UNAUTHENTICATED_PATHS:
        return await call_next(request)

    if not _EXPECTED_API_KEY:
        return JSONResponse(
            status_code=401,
            content={"detail": "API key authentication is not configured. Set API_KEY env var."},
        )

    provided_key = request.headers.get("X-API-Key", "")
    # Use hmac.compare_digest to prevent timing attacks.
    if not _is_valid_api_key(provided_key):
        return JSONResponse(
            status_code=401,
            content={"detail": "Unauthorized. Provide a valid X-API-Key header."},
        )

    return await call_next(request)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next: Any) -> Any:
    """Apply rate limiting based on X-API-Key header.

    Security Note:
        Authentication is handled by api_key_auth_middleware (above).
        This middleware only enforces per-key request rate limits.
        Requests without the header that reach this point (i.e., unauthenticated
        paths that bypass auth) are bucketed as "anonymous".
    """
    # Skip rate limiting for health and metrics endpoints
    if request.url.path in ("/health", "/stats", "/metrics"):
        return await call_next(request)

    api_key = request.headers.get("X-API-Key", "anonymous")
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
    if not _baseline_ready():
        raise HTTPException(
            status_code=503,
            detail="Detector baseline is not ready; load a known-clean startup baseline.",
        )

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
    """Score a batch of up to 1000 samples.

    Processes samples sequentially and returns aggregated results.
    For true async processing, submit to the pipeline queue instead.
    """
    if not _baseline_ready():
        raise HTTPException(
            status_code=503,
            detail="Detector baseline is not ready; load a known-clean startup baseline.",
        )

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

    # Liveness remains 200, but status is degraded until the trusted baseline is ready.
    status = "healthy" if _baseline_ready() else "degraded"
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
        baseline_ready=_baseline_ready(),
    )


@app.get("/ready")
async def readiness_check() -> JSONResponse:
    """Return 200 only when the known-clean baseline has been initialized."""
    if not _baseline_ready():
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "reason": _BASELINE_LOAD_ERROR or "baseline below minimum size",
            },
        )
    stats = _detector.get_stats()
    return JSONResponse(
        status_code=200,
        content={"status": "ready", "baseline_size": stats.baseline_size},
    )


@app.get("/ready")
async def readiness_check() -> dict[str, str]:
    """Readiness is stricter than liveness.

    This process is ready only when authentication is configured and the
    detector can expose its current state. Queue consumers are separate
    processes and must expose their own readiness.
    """
    if not _EXPECTED_API_KEY:
        raise HTTPException(status_code=503, detail="API_KEY is not configured")
    try:
        _detector.get_stats()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="detector is not ready") from exc
    return {"status": "ready"}


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
    """WebSocket endpoint for real-time detection event streaming.

    Clients connect and receive JSON messages for every detection event.
    Useful for real-time dashboards and monitoring UIs.

    Message format:
        {"event": "poison_detected", "score": 0.85, "method_votes": {...}}
        {"event": "batch_scored", "total_samples": 100, "poisoned_count": 5}
    """
    if not _is_valid_api_key(websocket.headers.get("X-API-Key", "")):
        await websocket.close(code=1008, reason="Unauthorized")