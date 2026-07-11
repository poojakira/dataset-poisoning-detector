# Changelog

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
