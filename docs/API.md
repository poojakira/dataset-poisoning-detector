# API Documentation

## Base URL

```
Production:  https://poison-detector.your-domain.com/
Staging:     https://poison-detector-staging.your-domain.com/
Local:       http://localhost:8000/
```

## Versioning Strategy

The API currently operates at version 1 (implicit). Future versions will use URL path
prefixing:

```
/v1/score    (current, default)
/v2/score    (future)
```

Breaking changes will increment the major version. Non-breaking additions (new optional
fields, new endpoints) are added to the current version.

---

## Authentication

All endpoints except `/health` and `/metrics` require authentication via one of:

### API Key Authentication

```http
X-API-Key: pk_your_api_key_here
```

### JWT Bearer Token

```http
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

### mTLS (Service-to-Service)

Provide a client certificate signed by the configured CA during TLS handshake. No
additional headers are required.

---

## Rate Limiting

All authenticated endpoints are rate limited. Limits are applied per API key or per
JWT subject.

**Default limits**: 100 requests per 60-second window.

**Rate limit headers** (included in all responses):

| Header | Description | Example |
|--------|-------------|---------|
| `X-RateLimit-Limit` | Maximum requests allowed per window | `100` |
| `X-RateLimit-Remaining` | Remaining requests in current window | `87` |
| `X-RateLimit-Reset` | Unix timestamp when the window resets | `1705312800` |
| `Retry-After` | Seconds to wait before retrying (only on 429) | `23` |

---

## Endpoints

### POST /score

Score a single sample for poisoning indicators.

**Required Permission**: `score`

**Request**:

```http
POST /score HTTP/1.1
Content-Type: application/json
X-API-Key: pk_your_api_key_here

{
  "features": [0.5, -1.2, 3.7, 0.1, 2.8, -0.3, 1.5, 0.9, -2.1, 4.0],
  "source": "training-pipeline-v2",
  "metadata": {
    "dataset": "imagenet-subset",
    "batch_id": "batch-2024-01-15-001"
  }
}
```

**Request Fields**:

| Field | Type | Required | Constraints | Description |
|-------|------|----------|-------------|-------------|
| `features` | `float[]` | Yes | 1 to 100,000 elements | Feature vector for the sample |
| `source` | `string` | No | Max 256 chars | Identifier for the data source |
| `metadata` | `object` | No | Max 4096 bytes JSON | Optional metadata for the scoring result |

**Response** (200 OK):

```json
{
  "score": 0.72,
  "is_poisoned": true,
  "method_votes": {
    "zscore": true,
    "isolation_forest": true
  },
  "latency_ms": 3.47
}
```

**Response Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `score` | `float` | Anomaly score in [0, 1]. Higher means more anomalous. |
| `is_poisoned` | `boolean` | Whether the sample exceeds the poisoning threshold |
| `method_votes` | `object` | Per-method poison votes (true = voted poisoned) |
| `latency_ms` | `float` | Scoring latency in milliseconds |

---

### POST /batch

Score a batch of samples (up to 1000) in a single request.

**Required Permission**: `batch_score`

**Request**:

```http
POST /batch HTTP/1.1
Content-Type: application/json
X-API-Key: pk_your_api_key_here

{
  "samples": [
    [0.5, -1.2, 3.7, 0.1, 2.8],
    [1.0, 0.3, -0.5, 2.1, 1.7],
    [15.2, -8.7, 22.1, 0.0, -3.4]
  ],
  "source": "nightly-ingestion"
}
```

**Request Fields**:

| Field | Type | Required | Constraints | Description |
|-------|------|----------|-------------|-------------|
| `samples` | `float[][]` | Yes | 1 to 1000 samples, each with 1+ features | Feature vectors to score |
| `source` | `string` | No | Max 256 chars | Identifier for the data source |

**Response** (200 OK):

```json
{
  "results": [
    {
      "score": 0.12,
      "is_poisoned": false,
      "method_votes": {"zscore": false, "isolation_forest": false},
      "latency_ms": 2.1
    },
    {
      "score": 0.08,
      "is_poisoned": false,
      "method_votes": {"zscore": false, "isolation_forest": false},
      "latency_ms": 1.9
    },
    {
      "score": 0.85,
      "is_poisoned": true,
      "method_votes": {"zscore": true, "isolation_forest": true},
      "latency_ms": 2.3
    }
  ],
  "total_samples": 3,
  "poisoned_count": 1,
  "batch_latency_ms": 6.3
}
```

**Response Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `results` | `ScoringResponse[]` | Per-sample scoring results in order |
| `total_samples` | `int` | Number of samples scored |
| `poisoned_count` | `int` | Number of samples flagged as poisoned |
| `batch_latency_ms` | `float` | Total batch processing time in ms |

---

### GET /health

Health check endpoint. Returns service status and basic statistics.

**Authentication**: Not required.

**Request**:

```http
GET /health HTTP/1.1
```

**Response** (200 OK):

```json
{
  "status": "healthy",
  "samples_processed": 142857,
  "poison_rate": 0.023,
  "avg_latency_ms": 4.7,
  "baseline_size": 10000,
  "queue_depth": 0,
  "uptime_seconds": 86423.5
}
```

**Response Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `status` | `string` | Service status: `healthy`, `degraded`, or `unhealthy` |
| `samples_processed` | `int` | Total samples processed since startup |
| `poison_rate` | `float` | Rolling poison detection rate (0.0 to 1.0) |
| `avg_latency_ms` | `float` | Average scoring latency in milliseconds |
| `baseline_size` | `int` | Number of samples in the baseline model |
| `queue_depth` | `int` | Current processing queue depth |
| `uptime_seconds` | `float` | Seconds since service start |

**Status Logic**:
- `healthy`: All systems nominal
- `degraded`: Poison rate > 20% or circuit breaker open
- `unhealthy`: Average latency > 1000ms or critical failures

---

### GET /stats

Detailed detector statistics for monitoring and debugging.

**Authentication**: Not required (rate limited).

**Request**:

```http
GET /stats HTTP/1.1
```

**Response** (200 OK):

```json
{
  "samples_seen": 142857,
  "poison_count": 3286,
  "poison_rate": 0.023,
  "avg_latency_ms": 4.7,
  "drift_detected": false,
  "baseline_size": 10000,
  "window_fill": 1.0
}
```

**Response Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `samples_seen` | `int` | Total samples scored since startup |
| `poison_count` | `int` | Number of samples flagged as poisoned |
| `poison_rate` | `float` | Fraction of samples flagged (0.0 to 1.0) |
| `avg_latency_ms` | `float` | Average scoring latency in ms |
| `drift_detected` | `boolean` | Whether concept drift is currently detected |
| `baseline_size` | `int` | Number of samples in the IsolationForest baseline |
| `window_fill` | `float` | Fraction of rolling window filled (0.0 to 1.0) |

---

### GET /metrics

Prometheus-compatible metrics endpoint for scraping.

**Authentication**: Not required (should be restricted to internal network).

**Request**:

```http
GET /metrics HTTP/1.1
```

**Response** (200 OK, Content-Type: text/plain):

```
# HELP poison_detector_samples_total Total samples processed
# TYPE poison_detector_samples_total counter
poison_detector_samples_total 142857.0

# HELP poison_detector_poisoned_total Total samples flagged as poisoned
# TYPE poison_detector_poisoned_total counter
poison_detector_poisoned_total 3286.0

# HELP poison_detector_scoring_latency_seconds Scoring latency histogram
# TYPE poison_detector_scoring_latency_seconds histogram
poison_detector_scoring_latency_seconds_bucket{le="0.005"} 98234.0
poison_detector_scoring_latency_seconds_bucket{le="0.01"} 135678.0
poison_detector_scoring_latency_seconds_bucket{le="0.025"} 141234.0
poison_detector_scoring_latency_seconds_bucket{le="0.05"} 142100.0
poison_detector_scoring_latency_seconds_bucket{le="0.1"} 142800.0
poison_detector_scoring_latency_seconds_bucket{le="+Inf"} 142857.0
poison_detector_scoring_latency_seconds_count 142857.0
poison_detector_scoring_latency_seconds_sum 671.234
```

---

### WebSocket /stream

Real-time detection event stream via WebSocket. Receives JSON messages for every
detection event (primarily poison detections and batch summaries).

**Authentication**: Not authenticated in the current implementation. Restrict access
via network policies in production.

**Connection**:

```javascript
const ws = new WebSocket('wss://poison-detector.your-domain.com/stream');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Event:', data.event, 'Score:', data.score);
};
```

**Server-sent Message Types**:

**Poison Detection Event**:
```json
{
  "event": "poison_detected",
  "score": 0.85,
  "method_votes": {"zscore": true, "isolation_forest": true},
  "source": "training-pipeline-v2",
  "latency_ms": 3.47
}
```

**Batch Scored Event**:
```json
{
  "event": "batch_scored",
  "total_samples": 100,
  "poisoned_count": 5,
  "source": "nightly-ingestion",
  "batch_latency_ms": 234.5
}
```

**Acknowledgment** (response to client messages):
```json
{
  "event": "ack",
  "data": "ping"
}
```

**Client messages**: The server echoes any text message sent by the client as an
acknowledgment. This can be used for keep-alive pings.

---

## Error Responses

All error responses follow a consistent format:

```json
{
  "detail": "Human-readable error description"
}
```

### Error Codes

| Status Code | Meaning | Common Causes |
|-------------|---------|---------------|
| 400 | Bad Request | Invalid JSON, missing required fields, validation failure |
| 401 | Unauthorized | Missing or invalid authentication credentials |
| 403 | Forbidden | Valid credentials but insufficient permissions (RBAC denial) |
| 422 | Unprocessable Entity | Request body validation failure (Pydantic) |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Unexpected server error during scoring |

### Error Examples

**400 Bad Request** (missing features field):
```json
{
  "detail": [
    {
      "type": "missing",
      "loc": ["body", "features"],
      "msg": "Field required"
    }
  ]
}
```

**401 Unauthorized** (invalid API key):
```json
{
  "detail": "Invalid API key"
}
```

**403 Forbidden** (insufficient permissions):
```json
{
  "detail": "Role 'service' does not have permission 'modify_config'"
}
```

**422 Unprocessable Entity** (validation error):
```json
{
  "detail": [
    {
      "type": "value_error",
      "loc": ["body", "samples", 2],
      "msg": "Sample at index 2 must have at least 1 feature"
    }
  ]
}
```

**429 Too Many Requests**:
```json
{
  "detail": "Rate limit exceeded. Try again later."
}
```

Response headers on 429:
```http
HTTP/1.1 429 Too Many Requests
Retry-After: 23
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1705312800
```

**500 Internal Server Error**:
```json
{
  "detail": "Scoring error: ValueError"
}
```

---

## SDK Usage Examples

### Python (httpx)

```python
import httpx

client = httpx.Client(
    base_url="https://poison-detector.your-domain.com",
    headers={"X-API-Key": "pk_your_key_here"},
    timeout=30.0,
)

# Single sample scoring
response = client.post("/score", json={
    "features": [0.5, -1.2, 3.7, 0.1, 2.8],
    "source": "my-pipeline",
})
result = response.json()
if result["is_poisoned"]:
    print(f"POISONED! Score: {result['score']}")

# Batch scoring
response = client.post("/batch", json={
    "samples": [[0.5, -1.2, 3.7], [1.0, 0.3, -0.5]],
    "source": "batch-job",
})
batch_result = response.json()
print(f"Poisoned: {batch_result['poisoned_count']}/{batch_result['total_samples']}")
```

### cURL

```bash
# Health check
curl -s https://poison-detector.your-domain.com/health | jq .

# Score a sample
curl -X POST https://poison-detector.your-domain.com/score \
  -H "Content-Type: application/json" \
  -H "X-API-Key: pk_your_key_here" \
  -d '{"features": [0.5, -1.2, 3.7, 0.1, 2.8]}'

# Batch scoring
curl -X POST https://poison-detector.your-domain.com/batch \
  -H "Content-Type: application/json" \
  -H "X-API-Key: pk_your_key_here" \
  -d '{"samples": [[0.5, -1.2, 3.7], [1.0, 0.3, -0.5]], "source": "test"}'
```

### WebSocket (wscat)

```bash
wscat -c wss://poison-detector.your-domain.com/stream
> ping
< {"event": "ack", "data": "ping"}
```
