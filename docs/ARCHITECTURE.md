# Architecture

## Overview

The Dataset Poisoning Detector is a real-time anomaly detection system designed to identify
malicious training samples before they corrupt machine learning models. It combines multiple
detection methods through ensemble voting, maintains streaming statistics using Welford's
algorithm, and provides a production-ready API with full observability.

## High-Level Component Diagram

```
                          +---------------------------+
                          |     External Clients      |
                          |  (ML Pipelines, Analysts) |
                          +-------------+-------------+
                                        |
                               TLS 1.3 / mTLS
                                        |
                          +-------------v-------------+
                          |      Ingress (NGINX)      |
                          |   + Network Policies      |
                          +-------------+-------------+
                                        |
                          +-------------v-------------+
                          |       FastAPI Service      |
                          |                           |
                          |  +---------+  +---------+ |
                          |  |  Auth   |  |  Rate   | |
                          |  | (JWT/   |  | Limiter | |
                          |  |  mTLS/  |  | (Redis) | |
                          |  |  APIKey)|  +---------+ |
                          |  +---------+              |
                          +--+-------+-------+--------+
                             |       |       |
              +--------------+  +----+----+  +---------------+
              |                 |         |                   |
   +----------v----------+ +---v---+ +---v-----------+ +-----v------+
   |  Input Sanitizer    | |RBAC   | | Prometheus    | | WebSocket  |
   |  (Validation/       | |Enforcer| | Metrics      | | Manager    |
   |   Rejection)        | +---+---+ +---+-----------+ +-----+------+
   +----------+----------+     |         |                    |
              |                |         |                    |
   +----------v-------------------------------------------------+
   |                  StreamingDetector                          |
   |                                                            |
   |  +------------------+  +-------------------+  +---------+ |
   |  | Welford          |  | IsolationForest   |  | Concept | |
   |  | Accumulator      |  | (periodic refit)  |  | Drift   | |
   |  | (z-score stats)  |  | (multivariate)    |  | Monitor | |
   |  +--------+---------+  +---------+---------+  +----+----+ |
   |           |                       |                 |      |
   |           +-----------+-----------+-----------------+      |
   |                       |                                    |
   |               Ensemble Voting                              |
   |           (majority vote across methods)                   |
   +--+------------------+--------------------------------------+
      |                  |
      | Clean            | Flagged
      v                  v
+-----+------+   +------+-------+     +------------------+
| Baseline   |   | Quarantine   |     |   Audit Logger   |
| Update     |   | Store        |     | (Hash Chain,     |
| (Window)   |   | (SQLite)     |     |  JSON Lines)     |
+------------+   +------+-------+     +--------+---------+
                        |                       |
                        v                       v
                 +------+-------+     +---------+--------+
                 | Alert        |     | Compliance       |
                 | Dispatcher   |     | Export           |
                 | (Slack/PD/   |     | (SOC2/ISO27001)  |
                 |  Email/WH)   |     +------------------+
                 +--------------+
```

## Data Flow

The system processes samples through a well-defined pipeline:

```
Ingest --> Sanitize --> Authenticate --> Authorize --> Detect --> Decision --> Audit --> Alert
```

### 1. Ingest

Samples arrive through one of three paths:
- **HTTP API**: POST /score (single), POST /batch (up to 1000)
- **WebSocket**: Real-time streaming via /stream
- **Pipeline**: Redis pub/sub or Kafka consumer for async processing

### 2. Sanitize (InputSanitizer)

Every sample passes through input validation before any ML processing:
- Dimension bounds check (reject >100,000 features)
- NaN/Inf detection (sklearn cannot handle non-finite values)
- Value range validation (prevent float64 overflow in accumulators)
- Per-client rate enforcement at the sanitization layer

### 3. Authenticate and Authorize

- **Authentication**: mTLS for service-to-service, JWT RS256 for user identity, API keys for programmatic access
- **Authorization**: RBAC enforcer checks permissions against the static permission matrix

### 4. Detect (StreamingDetector)

The core detection engine runs multiple methods:
- **Z-Score Detection**: Online mean/variance via Welford's algorithm; flags samples exceeding the z-score threshold on any feature
- **Isolation Forest**: Periodic refit on the rolling window; captures multivariate anomalies that per-feature statistics miss
- **Ensemble Voting**: Aggregates votes from all methods; requires vote_threshold votes to flag as poisoned

### 5. Decision

Based on ensemble voting:
- **Clean**: Sample passes, updates baseline window and Welford statistics
- **Poisoned**: Sample is quarantined, does NOT update baseline (prevents baseline corruption)

### 6. Audit (AuditLogger)

Every decision is recorded in a tamper-evident log:
- Append-only JSON Lines format
- SHA-256 hash chain links each entry to its predecessor
- Records: who, what, when, score, decision, sample_hash

### 7. Alert (AlertDispatcher)

Poisoned samples trigger configurable alerts:
- Slack webhooks for team notifications
- PagerDuty for on-call escalation
- Email for compliance notifications
- Generic webhooks for custom integrations
- Alert deduplication prevents notification storms

## Component Descriptions

### StreamingDetector

The central detection engine. Maintains a rolling window of clean samples and online
statistics. Scores each incoming sample against the current baseline using multiple
methods and returns a unified scoring result.

- **Window Size**: Configurable rolling buffer (default 10,000 samples)
- **Contamination**: Expected poison fraction for IsolationForest fitting
- **Refit Interval**: Clean samples between IsolationForest refits (amortizes O(n * trees * depth) cost)

### WelfordAccumulator

Implements Welford's online algorithm for numerically stable running mean and variance:
- O(1) update per sample per feature
- O(features) space
- Numerically stable for large sample counts

### InputSanitizer

First line of defense against adversarial inputs:
- Rejects malformed inputs before they reach ML components
- Prevents OOM via dimension limits
- Blocks NaN/Inf values that crash sklearn estimators
- Per-client rate limiting

### CircuitBreaker

Prevents cascading failures when downstream dependencies are unhealthy:
- **CLOSED**: Normal operation, requests pass through
- **OPEN**: Fail fast, return degraded (statistical-only) results
- **HALF_OPEN**: Allow one test request to check if the dependency has recovered

### AuditLogger

Tamper-evident compliance logging:
- Append-only with file locking for concurrent safety
- SHA-256 hash chain for integrity verification
- Queryable by time range, sample ID, user, and decision
- Exportable in JSON Lines, JSON Array, or CSV for audits

### RBACEnforcer

Coarse-grained access control:
- 4 roles: admin, analyst, readonly, service
- 7 permissions: score, batch_score, view_quarantine, resolve_quarantine, modify_config, view_audit, export_data
- Default-deny policy
- JWT claim-based or local assignment role resolution

### AlertDispatcher

Multi-channel notification system:
- Configurable channels (Slack, PagerDuty, Email, Webhook)
- Alert deduplication to prevent notification storms
- Severity-based routing (critical goes to PagerDuty, warning to Slack)

### RateLimiter (Distributed)

Redis-backed distributed rate limiting:
- Sliding window algorithm using Redis sorted sets
- Token bucket for burst allowance
- Graceful fallback to in-memory limits when Redis is unavailable
- Atomic operations via Redis MULTI/EXEC

---

## Architecture Decision Records

### ADR-001: Ensemble Voting Over Single Detection Method

**Status**: Accepted

**Context**: We need to detect poisoned training samples in real-time with high precision.
Single detection methods each have blind spots: z-score misses multivariate anomalies,
IsolationForest is expensive and only periodically updated, and IQR is sensitive to
distribution shape assumptions.

**Decision**: Use majority voting across multiple detection methods. A sample is flagged
as poisoned only when at least `vote_threshold` methods agree it is anomalous.

**Consequences**:
- Pro: Significantly reduces false positive rate. Each method compensates for the others' weaknesses.
- Pro: Graceful degradation -- if one method fails (e.g., IsolationForest circuit breaker open), the others continue scoring.
- Pro: Extensible -- new detection methods can be added as additional voters without changing the aggregation logic.
- Con: May miss borderline cases where only one method detects the anomaly. This is an intentional trade-off favoring precision over recall.
- Con: Slightly higher latency than a single-method approach due to running all methods per sample.

### ADR-002: Welford's Algorithm for Online Statistics

**Status**: Accepted

**Context**: The streaming detector needs running mean and variance to compute z-scores
on a per-sample basis. Naive computation (sum/count) suffers from catastrophic
cancellation for large sample counts. Batch computation requires storing all samples,
which is infeasible for high-throughput streaming.

**Decision**: Use Welford's online algorithm for numerically stable running mean and
variance with O(1) per-sample update cost.

**Consequences**:
- Pro: O(1) time and O(features) space per update. Suitable for millions of samples without recomputation.
- Pro: Numerically stable even for very large sample counts (avoids the catastrophic cancellation of naive two-pass or one-pass sum-of-squares approaches).
- Pro: Simple to reset or merge accumulators for window-based statistics.
- Con: Computes per-feature statistics independently. Cannot capture feature correlations. The IsolationForest refit handles this gap periodically.
- Con: Susceptible to "boiling frog" attacks where an adversary slowly shifts the mean if poisoned samples are accidentally admitted. Mitigated by only updating with clean (non-flagged) samples.

### ADR-003: Redis for Distributed Rate Limiting

**Status**: Accepted

**Context**: The in-memory rate limiter works for single-process deployments but fails
behind a load balancer with multiple replicas. Each replica independently enforces its
own limit, meaning the effective global limit is N times the configured value. We need
atomic, shared rate limit state across all replicas.

**Decision**: Use Redis as the shared state store for rate limiting. Implement sliding
window counters using Redis sorted sets with ZRANGEBYSCORE for pruning. Use Redis
MULTI/EXEC for atomic check-and-increment operations.

**Consequences**:
- Pro: Atomic operations ensure accurate rate enforcement across all replicas simultaneously.
- Pro: Redis is already in the architecture for caching and pub/sub, so no new dependency for most deployments.
- Pro: Sub-millisecond latency for rate limit checks (Redis is in-memory).
- Pro: Graceful fallback to in-memory limits if Redis is temporarily unavailable.
- Con: Adds Redis as a required dependency for multi-replica deployments. Single-node deployments can skip it.
- Con: Redis failure degrades rate limiting to per-process limits. An attacker who can take down Redis bypasses distributed rate enforcement.
- Con: Clock synchronization between replicas matters for sliding window accuracy (mitigated by using Redis server time via TIME command).

### ADR-004: Append-Only Audit Log with Hash Chain

**Status**: Accepted

**Context**: SOC2 and ISO27001 compliance require complete, tamper-evident audit trails
of all detection decisions. We need to prove that audit records have not been modified,
deleted, or reordered after creation. The audit system must be self-contained and
verifiable without external dependencies.

**Decision**: Implement an append-only JSON Lines audit log where each entry contains a
SHA-256 hash of its contents chained to the hash of the previous entry (blockchain-lite).
Integrity verification traverses the chain and recomputes hashes to detect any modification.

**Consequences**:
- Pro: Tamper-evident -- any modification, deletion, or reordering of entries breaks the hash chain and is immediately detected by verify_integrity().
- Pro: Self-contained -- no external service needed for integrity verification. The log file itself contains all information required to verify its integrity.
- Pro: Simple to implement and audit. Auditors can independently verify the chain with basic SHA-256 tooling.
- Pro: JSON Lines format allows streaming writes and line-by-line processing without loading the entire file.
- Con: Storage grows unbounded. Requires external log rotation and archival (S3 lifecycle policies). Mitigated by using compressed archival tiers.
- Con: Verification is O(n) in the number of entries. For very large logs (millions of entries), verification can take minutes. Mitigated by periodic checkpointing.
- Con: An attacker with filesystem access can delete the entire log. Mitigated by remote log shipping to an immutable store (S3 Object Lock, CloudWatch Logs).

---

## Deployment Topology Options

### Single-Node

Suitable for development, testing, and small-scale deployments (<1,000 samples/sec).

```
+-------------------------------------------+
|              Single Host                   |
|                                            |
|  +-------+  +---------+  +------------+   |
|  |FastAPI|  | SQLite  |  | Audit Log  |   |
|  |Service|  |(Quarant)|  | (local FS) |   |
|  +---+---+  +---------+  +------------+   |
|      |                                     |
|  In-memory rate limiting                   |
|  In-memory state (no Redis)                |
+-------------------------------------------+
```

- No external dependencies beyond the Python process
- SQLite for quarantine storage
- In-memory rate limiting (process-local)
- Local filesystem audit log
- Suitable for: proof-of-concept, CI/CD integration testing, single-pipeline deployments

### Multi-Replica (Recommended for Production)

Suitable for production workloads (1,000 - 50,000 samples/sec).

```
+------------------+     +-------------------+
|   Load Balancer  |     |  Monitoring       |
|   (ALB/NLB)     |     |  (Prometheus +    |
+--------+---------+     |   Grafana)        |
         |               +-------------------+
         |
+--------v--------------------------------------+
|              Kubernetes Cluster                |
|                                               |
|  +----------+  +----------+  +----------+    |
|  | Replica 1|  | Replica 2|  | Replica 3|    |
|  | (FastAPI)|  | (FastAPI)|  | (FastAPI)|    |
|  +-----+----+  +-----+----+  +-----+----+    |
|        |              |              |         |
|  +-----v--------------v--------------v-----+  |
|  |              Redis Cluster               |  |
|  |  (Rate Limiting + State + Pub/Sub)       |  |
|  +------------------------------------------+  |
|                                               |
|  +------------------------------------------+  |
|  |         PostgreSQL / RDS                  |  |
|  |  (Quarantine Store + Audit Archive)       |  |
|  +------------------------------------------+  |
+-----------------------------------------------+
```

- HPA scales from 3 to 20 replicas based on CPU and scoring latency
- Redis for distributed rate limiting and shared state
- PostgreSQL (RDS) for durable quarantine storage
- S3 for audit log archival
- Network policies restrict pod-to-pod communication

### Multi-Region (High Availability)

Suitable for mission-critical deployments requiring geographic redundancy.

```
+---------------------+          +---------------------+
|    Region A (Primary)          |   Region B (DR)     |
|                     |          |                     |
| +---+ +---+ +---+  |          | +---+ +---+ +---+  |
| |R1 | |R2 | |R3 |  |          | |R1 | |R2 | |R3 |  |
| +---+ +---+ +---+  |          | +---+ +---+ +---+  |
|         |           |          |         |           |
| +-------v---------+ |          | +-------v---------+ |
| | Redis Primary   | |          | | Redis Replica   | |
| +-----------------+ |          | +-----------------+ |
|         |           |          |         ^           |
| +-------v---------+ |  Async   | +-------+---------+ |
| | RDS Primary     +------------->| RDS Read Replica | |
| +-----------------+ |  Repl.   | +-----------------+ |
+---------------------+          +---------------------+
```

- Active-passive with automated failover
- Cross-region RDS replication for quarantine data
- Redis replication for rate limit state (eventual consistency acceptable)
- Route 53 health checks with automatic DNS failover
- RPO: <5 minutes, RTO: <15 minutes
