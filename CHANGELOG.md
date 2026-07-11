# Changelog

## 1.1.0 (2025 — "detection hardening")

Deep fixes to the honest limitations of the 1.0.0 detector. The engineering
platform was already mature; this release makes the **detection science real**:
measured on real data, broader in method, and honestly reported. No breaking
changes — the legacy flat-float sample format and `detect(method="ensemble")`
majority vote still work.

### Added — real data & honest benchmarking
- `datasets.py`: loaders for real, **bundled scikit-learn datasets**
  (breast cancer, digits, iris, wine — no network needed) plus a `PoisonInjector`
  that injects five attacks (label-flip, feature-outlier, cluster, duplicate,
  correlation/covariance-breaking) at **known indices** for ground-truth scoring.
- `benchmark.py` + `examples/benchmark.py`: an honest scorecard harness reporting
  **precision/recall/F1/ROC-AUC per method and for the calibrated ensemble**,
  across contamination levels, with a printed table and JSON export.

### Added — new detection methods (the families top labs use)
- `spectral.py`: SVD-based detection combining a top-k **spectral signature**
  (Tran et al. 2018) with a **whitened covariance-residual** score — catches
  correlation poisoning that per-feature z-score/IQR/Welford structurally miss
  (measured F1 ≈ 0.59, ROC-AUC ≈ 0.96 on the correlation attack).
- `label_aware.py`: **kNN label-disagreement** detection for label-flipping
  (F1 up to ~0.90 on the label-flip attack). Requires labels.
- `influence.py`: approximate **surrogate loss / self-influence** scoring
  (documented as approximate, not exact influence functions).

### Added — data model, embeddings, dimensionality reduction
- `sample.py`: optional **label + metadata** on samples, fully backward
  compatible with the flat-float-list format; `SampleRequest`/`ScoringResult`
  gain an optional `label`.
- `reduction.py` + `StreamingDetector(reduce_dim=...)`: PCA / Gaussian random
  projection **before** IsolationForest for high-dimensional embeddings;
  `examples/embedding_demo.py` shows the 20-newsgroups TF-IDF path end-to-end.

### Added — accuracy
- **Calibrated ensemble**: per-method rank-normalization + elementwise-max
  combiner so a lone specialist (e.g. fingerprint for duplicates, spectral for
  correlation) is still heard. Measured **ROC-AUC ≈ 0.94, precision ≈ 0.44** vs
  the old synthetic ~0.18 precision. (Hard-threshold F1 on duplicate/correlation
  remains modest despite high AUC — documented; threshold calibration is future work.)

### Added — enterprise gaps
- `tenancy.py`: **multi-tenant isolation** — per-tenant baselines (one tenant's
  data never updates another's), per-tenant quarantine namespacing, per-tenant
  rate-limit quotas.
- `auth.py`: **JWT revocation** via a TTL-bounded, `jti`-based `TokenDenylist`
  and `JWTAuthenticator.revoke()`.

### Added — throughput
- `StreamingDetector.score_batch_vectorized()`: vectorized batch scoring
  measured at **~1.3M samples/sec** on the statistical path (~25× the per-sample
  path). Load test now asserts a 10k/sec per-sample and 100k/sec vectorized floor
  plus a vectorized-vs-per-sample correctness check.

### Fixed / verified
- Confirmed `examples/kafka_consumer.py` uses `ConceptDriftDetector(delta=...)`
  (the historical `sensitivity=` crash bug) and pinned it with a regression test.

### Testing
- Coverage raised **68% → 94%**; test count **60 → 276**. New tests for every new
  module and for previously thin enterprise modules (pipeline, alerting,
  rate_limiter, auth, config, crypto, audit, input_sanitizer). Runs hermetically
  (Redis/Kafka/mTLS via scripted fakes and runtime-generated certs).

### Changed
- Version bumped to 1.1.0.

## 1.0.0 (2024-01-25)

Production-ready enterprise release with comprehensive security hardening,
infrastructure automation, and operational tooling.

### Security
- mTLS + JWT + API key authentication with key rotation
- Role-based access control (RBAC) with 4 roles (admin, analyst, operator, viewer)
- AES-256-GCM encryption at rest with automatic key rotation
- Immutable, tamper-evident audit trail (SOC2-ready)
- Input validation and sanitization (NaN/Inf/dimension/range checks)
- Distributed sliding window rate limiting
- Circuit breakers with per-dependency isolation

### Infrastructure
- Terraform modules for AWS deployment (EKS, RDS, Redis, S3)
- Production Kubernetes manifests with restricted Pod Security Standards
- Multi-AZ high availability with PodDisruptionBudgets and HPA
- Non-root container with minimal attack surface
- Kustomize overlays for dev/staging/prod environments

### Observability
- Prometheus metrics and alerting rules
- Grafana dashboards for operational monitoring
- OpenTelemetry distributed tracing integration
- Structured logging with correlation IDs

### Testing
- Integration tests for end-to-end, failover, and load scenarios
- Security-focused test suite for auth, crypto, and audit modules
- 60+ tests covering all detection and enterprise modules

### Documentation
- Architecture decision records and system design docs
- Deployment runbooks and operational procedures
- Threat model with STRIDE analysis
- SLA definitions and incident response procedures
- API reference documentation

### CI/CD
- Automated security scanning with pip-audit and bandit
- SBOM generation with CycloneDX
- Semantic versioning release automation
- CODEOWNERS for security-critical module review
- Pre-commit hooks for secrets scanning and code quality

### Changed
- License changed from MIT to Apache 2.0 (enterprise-friendly)
- Version bumped to 1.0.0 (production-ready)

## 0.2.0 (2024-01-20)

### Added
- **Real-time streaming detection** via `StreamingDetector` with O(1) rolling statistics
  using Welford's online algorithm and periodic IsolationForest refitting
- **Concept drift detection** via `ConceptDriftDetector` implementing ADWIN and
  Page-Hinkley algorithms for feature-level distribution shift monitoring
- **Sample fingerprinting** via `SampleFingerprinter` with Bloom filter for O(1)
  duplicate detection and cosine similarity for near-duplicate/cluster injection attacks
- **Quarantine storage** via `QuarantineStore` ABC with `SQLiteStore` implementation
  for development/testing (PostgresStore and S3Store interfaces defined)
- **Multi-channel alerting** via `AlertDispatcher` with Slack, PagerDuty, CloudWatch,
  and generic webhook support, including deduplication and escalation logic
- **FastAPI service** with POST /score, POST /batch, GET /health, GET /stats,
  GET /metrics, and WebSocket /stream endpoints with rate limiting
- **Pipeline consumers** for Redis Streams and Kafka with dead letter queue,
  quarantine routing, and backpressure handling
- **Configuration management** via Pydantic BaseSettings with YAML file + env var
  support and per-environment configs
- **Prometheus metrics** (samples_processed_total, samples_poisoned_total,
  scoring_latency_seconds, drift_score, queue_depth, baseline_size)
- **Production deployment** examples: Docker multi-stage build, docker-compose with
  Redis/Kafka/Prometheus/Grafana, Kafka consumer example, terminal dashboard
- **19 new tests** covering stream, drift, fingerprint, API, and pipeline modules
- `[realtime]` optional dependency group for streaming detection
- `[kafka]` optional dependency group for Kafka pipeline integration

### Changed
- Version bumped to 0.2.0
- `__init__.py` now conditionally imports real-time modules when deps are available

## 0.1.0 (2024-01-15)

### Added
- Z-score anomaly detection (pure Python, no numpy dependency)
- IQR fencing anomaly detection (pure Python)
- Isolation Forest wrapper with normalized 0-1 scoring
- Ensemble detection via majority vote across all three methods
- Feature-level attribution for understanding why samples are flagged
- Report formatting: human-readable, JSON, and CSV export
- 13 unit tests covering all detection methods
- CI pipeline via GitHub Actions
