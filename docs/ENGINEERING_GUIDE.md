# Engineering Guide — Dataset Poisoning Detector

> **Audience:** A new engineering team inheriting this project.
> **Purpose:** The single "everything you need to know" reference. It covers
> both the technical system and the non-technical context (product, ownership,
> compliance, risk).
> **Version:** 1.0.0 · **Branch of record:** `feat/enterprise-hardening` ·
> **Repo:** [poojakira/dataset-poisoning-detector](https://github.com/poojakira/dataset-poisoning-detector)
> **License:** Apache-2.0

This document is deliberately honest. Where the project falls short of its
marketing, this guide says so. Read the [Honest Product Maturity Assessment](#12-honest-product-maturity-assessment)
and [Known Limitations & Blind Spots](#22-known-limitations--blind-spots) before
you make any promises to stakeholders.

It cross-links to the deeper reference docs rather than duplicating them:
[ARCHITECTURE.md](ARCHITECTURE.md), [API.md](API.md), [SECURITY.md](SECURITY.md),
[THREAT_MODEL.md](THREAT_MODEL.md), [DEPLOYMENT.md](DEPLOYMENT.md),
[OPERATIONS.md](OPERATIONS.md), [SLA.md](SLA.md).

---

## Table of Contents

**Part I — Non-Technical**
1. [Executive Summary](#1-executive-summary)
2. [Target Users & Real-World Use Cases](#2-target-users--real-world-use-cases)
3. [Team Roles & Responsibilities (RACI)](#3-team-roles--responsibilities-raci)
4. [New-Engineer Onboarding Guide](#4-new-engineer-onboarding-guide)
5. [Operational Ownership & On-Call](#5-operational-ownership--on-call)
6. [SLA / SLO Summary](#6-sla--slo-summary)
7. [Compliance Posture](#7-compliance-posture)
8. [Cost Considerations](#8-cost-considerations)
9. [Risk Register](#9-risk-register)
10. [Decision Log / ADR Summary](#10-decision-log--adr-summary)
11. [FAQ](#11-faq)
12. [Honest Product Maturity Assessment](#12-honest-product-maturity-assessment)
13. [Glossary](#13-glossary)

**Part II — Technical**
14. [System Overview & Architecture](#14-system-overview--architecture)
15. [Detection Methodology](#15-detection-methodology)
16. [Module-by-Module Reference](#16-module-by-module-reference)
17. [Data Model & Assumptions](#17-data-model--assumptions)
18. [API Reference Summary](#18-api-reference-summary)
19. [Configuration Reference](#19-configuration-reference)
20. [Deployment](#20-deployment)
21. [Observability & Metrics](#21-observability--metrics)
22. [Security Architecture](#22-security-architecture)
23. [Testing Strategy & Coverage](#23-testing-strategy--coverage)
24. [Performance Characteristics & Benchmarks](#24-performance-characteristics--benchmarks)
25. [Known Limitations & Blind Spots](#25-known-limitations--blind-spots)
26. [Technical Roadmap to Close Gaps](#26-technical-roadmap-to-close-gaps)

---

# Part I — Non-Technical

## 1. Executive Summary

**The problem.** Machine learning models are only as trustworthy as their
training data. A *data poisoning* attack injects malicious samples into a
training set to degrade accuracy, install a backdoor, or shift a decision
boundary. Because poisoning happens upstream of training, it often goes
unnoticed until the model is already corrupted — the failure is silent and
expensive to unwind.

**What this project does.** The Dataset Poisoning Detector flags anomalous
training samples *before* they reach the training loop. It offers two modes:

- **Batch mode** — score a whole feature matrix at once (`detect()`).
- **Real-time mode** — score samples one at a time as they stream through a
  data pipeline (`StreamingDetector`), with O(1) per-sample statistics.

Detection is an **ensemble** of three unsupervised anomaly detectors (z-score,
IQR, Isolation Forest) combined by **majority vote** (≥2 of 3). Around this core
sit production concerns: concept-drift suppression, duplicate/cluster
fingerprinting, quarantine storage, multi-channel alerting, a FastAPI service,
Kafka/Redis pipeline consumers, and a full security + infrastructure layer.

**Why it matters.** For any organization that ingests third-party or
user-supplied training data (fine-tuning APIs, RLHF pipelines, data-curation
platforms), an automated first-pass filter reduces the blast radius of a
poisoning campaign and creates an auditable record of what was rejected and why.

**The honest caveat.** The engineering scaffolding is genuinely
production-grade (auth, RBAC, crypto, audit, K8s, Terraform). **The detection
accuracy is not yet.** All results to date are on *synthetic* data, and demo
precision is low. Treat this as a strong platform with a research-grade
detector core — see [§12](#12-honest-product-maturity-assessment).

---

## 2. Target Users & Real-World Use Cases

The intended users are **ML platform / trust & safety / data-infrastructure
engineers** at organizations that train models on data they do not fully
control. The README frames four illustrative scenarios (aspirational
integrations, not shipped connectors):

| Framing | Use case | Which components apply |
|---|---|---|
| **OpenAI-style** | Screen customer fine-tuning uploads before the training queue | `StreamingDetector`, quarantine, trust & safety review |
| **Anthropic-style** | Validate RLHF preference pairs; catch coordinated label shifts & ballot-stuffing | `ConceptDriftDetector`, `SampleFingerprinter` |
| **Amazon/SageMaker-style** | Preprocessing step in a Processing job; quarantine to a separate S3 prefix | `StreamingDetector`, `AlertDispatcher` (CloudWatch) |
| **NVIDIA/NeMo-style** | Data-curation stage filtering multi-billion-token corpora; dedup attacks | `StreamingDetector`, `SampleFingerprinter` |

> **Reality check:** These are *narratives* in the README, not delivered
> customer integrations. There are no vendor SDK adapters in the codebase, and
> the accuracy numbers below do not yet justify unattended use at these scales.

**When NOT to use it** (from the README, and correct): static single-dump data
(use batch `detect()` instead), datasets under ~1,000 samples, hard real-time
serving paths under ~10µs budget, fully trusted/audited data sources, or when
every sample is already human-reviewed.

---

## 3. Team Roles & Responsibilities (RACI)

Suggested ownership model for a team inheriting the project. Adapt names to
your org. R = Responsible, A = Accountable, C = Consulted, I = Informed.

| Activity | ML/Detection Eng | Platform/SRE | Security Eng | Eng Manager / PM |
|---|---|---|---|---|
| Detection algorithms (`detector`, `statistical`, `isolation`, `stream`, `drift`, `fingerprint`) | R/A | I | C | I |
| API & pipeline (`api`, `pipeline`, `storage`, `alerting`) | R | C | C | A |
| Security modules (`auth`, `rbac`, `crypto`, `audit`, `input_sanitizer`, `rate_limiter`, `circuit_breaker`) | C | C | R/A | I |
| Infra (`k8s/`, `terraform/`, `Dockerfile`, `docker-compose.yml`) | I | R/A | C | I |
| Observability (`observability/`, `metrics.py`, runbooks) | C | R/A | I | I |
| Compliance evidence (audit trail, SOC2/ISO27001 mapping) | I | C | R | A |
| Release management (`.github/workflows/release.yml`, CHANGELOG) | C | R | C | A |
| Accuracy validation on real data (**biggest gap**) | R/A | I | I | A |

Enforced in-repo today via [`.github/CODEOWNERS`](../.github/CODEOWNERS): security-critical
modules require designated review.

---

## 4. New-Engineer Onboarding Guide

### Day 1 — Get it running locally

```bash
git clone https://github.com/poojakira/dataset-poisoning-detector
cd dataset-poisoning-detector
git checkout feat/enterprise-hardening

# Core + dev + realtime extras (Python >= 3.10)
pip install -e ".[dev,realtime]"

# Run the test suite (should be ~60 passing)
pytest tests/ -v

# See detection in action on synthetic data
python examples/realtime_demo.py
```

Then read, in order: this guide → [ARCHITECTURE.md](ARCHITECTURE.md) →
[`src/poison_detector/detector.py`](../src/poison_detector/detector.py) (the core
entry point) → [`stream.py`](../src/poison_detector/stream.py).

### Day 1 — Try the batch API

```python
from poison_detector import detect, export_json

X = [[0.2, 0.8, 0.1, 0.9], [0.3, 0.7, 0.2, 0.8], [9.9, 0.0, 9.8, 0.1]]
report = detect(X, method="ensemble")
print(f"Flagged {report.poisoned_count}/{report.total_samples}")
print(export_json(report))
```

### Week 1 — Understand the whole system

- Run the FastAPI service and hit every endpoint (see [§18](#18-api-reference-summary)).
  ```bash
  pip install -e ".[realtime,security]"
  uvicorn poison_detector.api:app --reload
  curl -X POST http://localhost:8000/score -H "Content-Type: application/json" \
       -d '{"features": [0.1, 0.2, 0.3, 0.4, 0.5]}'
  curl http://localhost:8000/health
  ```
- Bring up the full stack with `docker compose up -d` (API + Redis + Kafka +
  Prometheus + Grafana). Grafana at `http://localhost:3000` (`admin/detector`).
- Read the three runbooks in [`observability/runbooks/`](../observability/runbooks/):
  `high-poison-rate.md`, `drift-alert.md`, `latency-degradation.md`.
- Skim the security modules and [SECURITY.md](SECURITY.md) / [THREAT_MODEL.md](THREAT_MODEL.md).
- **Recommended first task:** build a real (non-synthetic) evaluation harness —
  this is the project's single most valuable missing piece (see [§26](#26-technical-roadmap-to-close-gaps)).

### Gotchas to know early

- Optional dependencies are **conditionally imported** in `__init__.py`. If you
  `import` a real-time or security symbol without installing the matching extra,
  it silently won't be exported. Install `[realtime]` and `[security]`.
- The FastAPI app instantiates a **single module-level** `StreamingDetector`
  (`api._detector`). It is process-global state, and its in-memory rate limiter
  is per-process (not correct behind a multi-replica load balancer without Redis).
- All data you will see is synthetic. Do not confuse the demo's metrics with
  production accuracy.

---

## 5. Operational Ownership & On-Call

- **Service owner:** Platform/SRE team (API, pipeline, infra).
- **Detection owner:** ML/Detection team (algorithm behavior, thresholds).
- **Security owner:** Security team (auth, crypto, audit, incident response).

On-call responds to the Prometheus alerts defined in
[`observability/prometheus-rules.yaml`](../observability/prometheus-rules.yaml)
using the runbooks in [`observability/runbooks/`](../observability/runbooks/):

| Signal | Runbook | First action |
|---|---|---|
| Poison rate above threshold | `high-poison-rate.md` | Confirm not a legitimate drift event; check `/stats` |
| Drift detected | `drift-alert.md` | Verify source distribution change vs. attack |
| Latency degradation | `latency-degradation.md` | Check IsolationForest refit timing / dimensionality |

Alert delivery is handled by `alerting.py` (`AlertDispatcher`) → Slack /
PagerDuty / CloudWatch / webhook, with dedup + escalation. See
[OPERATIONS.md](OPERATIONS.md) for escalation policy and incident procedures.

---

## 6. SLA / SLO Summary

Targets defined in [SLA.md](SLA.md). **These are stated targets, not measured
production guarantees** — see the caveat below.

| Objective | Target |
|---|---|
| Availability | 99.95% |
| Latency (p99) | < 50 ms |
| Throughput | 10,000 samples/sec |
| Error rate | < 0.1% |
| Error budget | Policy-governed (see SLA.md) |

> **Honest note:** Load testing to date proves only a **~1,000 samples/sec**
> floor, not the 10K target and not 100K+. The 10K/50ms targets are unvalidated
> at scale, and Isolation Forest will not hold a <50ms p99 on high-dimensional
> inputs (e.g., 768-dim embeddings) without dimensionality reduction. Do not
> commit these SLOs to a customer without a real load test.

---

## 7. Compliance Posture

| Framework | How the project addresses it | Status |
|---|---|---|
| **SOC 2 / ISO 27001** | `audit.py` provides an append-only, hash-chained (SHA-256) tamper-evident audit trail with 7-year default retention, and query/export for auditors | Mechanism implemented; **retention enforcement and log shipping are external responsibilities** |
| **OWASP ML Top 10 — ML02 Data Poisoning** | Entire product is a control for ML02; ensemble detection + quarantine + audit | Directly addressed (accuracy caveats apply) |
| **OWASP-recommended crypto** | `crypto.py`: AES-256-GCM, PBKDF2 600k iterations, HMAC-SHA256 | Implemented |
| **Access control** | `auth.py` (JWT RS256, bcrypt API keys, mTLS), `rbac.py` (default-deny, 4 roles) | Implemented as modules; **not yet wired into the API middleware** (see [§22](#22-security-architecture)) |

See [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md) for the
STRIDE analysis and control mapping.

> **Compliance caveat:** The audit hash chain provides tamper *evidence*, not
> tamper *prevention*. An attacker with file access can still delete the log.
> Use append-only filesystem features or remote log shipping for stronger
> guarantees (documented in `audit.py`).

---

## 8. Cost Considerations

The Terraform stack ([`terraform/`](../terraform/)) provisions managed AWS
services; these are the primary cost drivers to budget and monitor:

| Component | Module | Cost driver |
|---|---|---|
| EKS cluster + nodes | `terraform/modules/eks` | Node instance hours; scales with HPA |
| Aurora PostgreSQL | `terraform/modules/rds` | Instance size + storage + I/O (for `PostgresStore`, currently a stub) |
| ElastiCache Redis | `terraform/modules/redis` | Node size (rate limiting + Redis Streams pipeline) |
| S3 | `terraform/modules/s3` | Storage + requests (quarantine `S3Store`, currently a stub) |
| KMS | (referenced) | Key operations for envelope encryption master key |

Cost-control levers: right-size the HPA (`k8s/hpa.yaml`) min/max replicas, use
pure-Python statistical-only mode under backpressure (already automatic in
`pipeline.py`), and tune `refit_interval` to amortize IsolationForest fitting
cost. Note that pure-Python statistical detection is ~100x slower than
vectorized numpy but needs no GPU and scales horizontally cheaply.

---

## 9. Risk Register

| ID | Risk | Likelihood | Impact | Mitigation / Owner |
|---|---|---|---|---|
| R1 | **Detection accuracy is unproven on real data** (synthetic-only, ~18% precision in demo) | High | High | Build real eval harness; ML team; see [§26](#26) |
| R2 | Adaptive adversary evades all 3 ensemble methods | Medium | High | Ensemble assumes non-adaptive attacker; add loss/influence methods |
| R3 | SLO targets (10K/sec, 50ms p99) not validated | High | Medium | Real load test before customer commitments; SRE |
| R4 | Security modules exist but are **not wired into API middleware** | High | High | Integrate auth/RBAC/rate-limit into `api.py`; Security |
| R5 | JWT has no revocation (stateless) | Medium | Medium | Short-lived tokens + refresh rotation |
| R6 | No multi-tenant isolation | Medium | High | Do not deploy shared across untrusted tenants until addressed |
| R7 | `PostgresStore` / `S3Store` are stubs; only SQLite works | High | Medium | Implement before multi-process production use |
| R8 | Audit log deletable by file-access attacker | Low | High | Append-only FS / remote shipping |
| R9 | Correlation poisoning invisible to per-feature stats | Medium | Medium | Add multivariate/spectral detection |
| R10 | Test coverage 68% (below typical 90% bar) | Medium | Medium | Raise coverage on error paths |

---

## 10. Decision Log / ADR Summary

Reconstructed from source comments, [ARCHITECTURE.md](ARCHITECTURE.md), and
`CHANGELOG.md`. No formal ADR files exist yet; consider creating them.

| # | Decision | Rationale | Trade-off |
|---|---|---|---|
| ADR-1 | Ensemble via **majority vote (≥2/3)** | Lower false positives than any single method | Higher false negatives; borderline cases missed |
| ADR-2 | **Pure-Python** z-score & IQR (no numpy) | Full auditability — every arithmetic op visible | ~100x slower than vectorized numpy |
| ADR-3 | Keep sklearn **IsolationForest** despite non-auditable Cython | Battle-tested density-based detection | Black box; paired with auditable stats for defense-in-depth |
| ADR-4 | **Welford's** online algorithm for streaming stats | O(1) per sample, numerically stable | Per-feature independent; misses correlations |
| ADR-5 | Update baseline **only with clean samples** | Anti "boiling frog" — poison can't shift the baseline | If early window is poisoned, baseline is compromised |
| ADR-6 | Drift detection **suppresses** poison alerts | Reduce false positives during legitimate shift | Adaptive "slow drift" attack could hide in it |
| ADR-7 | **JWT RS256 only**, reject HS256 | Prevent key-confusion forgery | Requires asymmetric key management |
| ADR-8 | **Envelope encryption** (DEK per record, KEK from master) | Efficient key rotation; blast-radius limited | Extra complexity |
| ADR-9 | Audit trail = **JSON Lines + SHA-256 hash chain** | Tamper-evident, simple, portable | Evidence not prevention; in-memory query doesn't scale |
| ADR-10 | Backpressure → **statistical-only mode** (never drop) | Attacker can't bypass detection by flooding | Degraded detection quality during load |
| ADR-11 | License **Apache-2.0** (was MIT) | Enterprise-friendly | — |

---

## 11. FAQ

**Q: Is this production-ready?**
The *platform* (security, infra, observability) is mature. The *detector's
accuracy* is not validated on real data. See [§12](#12-honest-product-maturity-assessment).

**Q: What sample format does it expect?**
A flat list of floats per sample: `{"features": [0.1, 0.2, ...]}`. No labels, no
text, no images. See [§17](#17-data-model--assumptions).

**Q: Can it catch label-flipping attacks?**
No. It is feature-space only and label-unaware. Clean-label attacks are invisible to it.

**Q: Why is precision so low in the demo?**
The demo runs on synthetic Gaussians with hand-crafted attacks and a small
window; unsupervised anomaly detection over-flags. Real tuning and real data are needed.

**Q: Is auth enforced on the API?**
Not yet. `auth.py`/`rbac.py`/`rate_limiter.py` exist and are tested, but `api.py`
only applies an in-memory rate limiter for bucketing. Wiring them in is an open task ([R4](#9-risk-register)).

**Q: Which storage backend works?**
Only `SQLiteStore`. `PostgresStore` and `S3Store` raise `NotImplementedError`.

**Q: Known bugs?**
`examples/kafka_consumer.py` previously called `ConceptDriftDetector(sensitivity=...)`
but the constructor takes `delta=`. This was a crash on the Kafka path; it has
been fixed in this change (one-word kwarg correction). See [§16](#drift-py).

---

## 12. Honest Product Maturity Assessment

**Overall rating: 6/10 — a strong production *platform* wrapped around a
research-grade *detector*.**

| Dimension | Rating | Notes |
|---|---|---|
| Engineering / infra maturity | 8/10 | K8s, Terraform, CI/CD, containers, observability all present |
| Security architecture | 7/10 | Excellent modules; **not yet integrated** into the request path |
| Detection accuracy | 3/10 | Synthetic-only; ~78% recall / ~18% precision / 161 FPs in demo |
| Data realism | 2/10 | No real dataset in the repo at all |
| Test coverage | 6/10 | 60 tests, 68% coverage — below the typical 90% enterprise bar |
| Documentation | 9/10 | Thorough and, notably, honest about limitations |
| Scalability (proven) | 4/10 | Load test proves ~1K/sec floor, not the 10K+ SLO |

**Bottom line:** Adopt it as a well-architected foundation. Do not represent its
detection quality as production-grade until it is validated on real, labeled,
adversarial data.

---

## 13. Glossary

- **Data poisoning** — injecting malicious samples into training data to corrupt a model.
- **Clean-label attack** — poisoning where features look normal but labels are wrong; invisible to this tool.
- **Backdoor / trigger** — an input pattern that causes targeted misbehavior at inference.
- **Ensemble majority vote** — flag a sample only if ≥2 of 3 detectors agree.
- **Z-score** — number of standard deviations a value is from the mean.
- **IQR fence** — Tukey outlier bound `[Q1 − k·IQR, Q3 + k·IQR]`, default k=1.5.
- **Isolation Forest** — density-based anomaly detector; anomalies isolate with fewer random splits.
- **Welford's algorithm** — numerically stable O(1) online mean/variance.
- **Concept drift** — legitimate change in the data distribution over time.
- **ADWIN / Page-Hinkley** — drift-detection algorithms (adaptive window / cumulative-sum change point).
- **Bloom filter** — probabilistic set membership; no false negatives, tunable false positives.
- **"Boiling frog" attack** — slowly shifting the baseline with borderline samples before injecting overt poison.
- **Nightshade-style attack** — injecting many similar samples (cluster/duplicate) to bias a model.
- **DEK / KEK** — data encryption key / key encryption key (envelope encryption).
- **DLQ** — dead letter queue for messages that fail processing.
- **Backpressure** — load-shedding behavior; here, downgrade to statistical-only mode.

---

# Part II — Technical

## 14. System Overview & Architecture

The library has a small **core** (batch detection, pure-Python + sklearn) and an
optional **real-time / enterprise layer** (streaming, service, pipeline,
security, infra) gated behind extras. See [ARCHITECTURE.md](ARCHITECTURE.md) for
the full design.

### Data-flow diagram (real-time path)

```
                       Untrusted training data
                                │
                                ▼
                     ┌──────────────────────┐
   Kafka / Redis     │   pipeline.py         │   malformed ─────► Dead Letter Queue
   input queue  ────►│  RedisConsumer /      │
                     │  KafkaConsumer        │   (backpressure ► statistical-only mode)
                     └──────────┬────────────┘
                                │ PipelineMessage {features:[...]}
                                ▼
                     ┌──────────────────────┐
                     │ input_sanitizer.py    │  reject NaN/Inf/oversized/out-of-range
                     └──────────┬────────────┘
                                ▼
        ┌───────────────────────────────────────────────┐
        │              stream.py StreamingDetector        │
        │                                                 │
        │   Welford z-score (O(1))   +   IsolationForest  │  ◄── periodic refit
        │            └────────── vote ≥ 2 ──────────┘     │      (clean window only)
        │                                                 │
        │   drift.py  ── suppress alerts during drift ──► │
        │   fingerprint.py ── dup/cluster injection ────► │
        └───────────────┬───────────────────┬─────────────┘
                        │ clean              │ flagged
                        ▼                    ▼
              pass to training       storage.py QuarantineStore
                                     (SQLite) + alerting.py
                                              │
                                              ▼
                        metrics.py (Prometheus) ─► Grafana / alerts
                        audit.py (hash-chained trail)
```

Batch path is simpler: `detect(X, method)` → `statistical` + `isolation` →
`attribution` → `report`. The `api.py` FastAPI service exposes the streaming
detector over HTTP/WebSocket.

---

## 15. Detection Methodology

Three unsupervised detectors, each with a distinct catch/miss profile, combined
by majority vote. **All are feature-space, unsupervised anomaly detectors — they
detect statistical anomaly, not malicious intent.**

| Method | Module | Catches | Misses |
|---|---|---|---|
| **Z-score** (per-feature, flag if any \|z\| ≥ 3.0) | `statistical.zscore_detect` | Extreme point outliers | Non-Gaussian tails, in-distribution attacks, label flips |
| **IQR fence** (Tukey, k=1.5) | `statistical.iqr_detect` | Robust distributional outliers (not skewed by outliers) | Samples just inside the fence; zero-spread features |
| **Isolation Forest** (sklearn, contamination≈0.05) | `isolation.IsolationDetector` | Density/cluster anomalies | Clean-label, distributed poisoning, backdoor triggers; degrades in high dimensions |
| **Ensemble** (≥2/3 votes) | `detector._ensemble_detect` | Anomalies visible to multiple methods → low FP | Borderline cases only one method catches |

**Streaming variant** (`stream.py`): the z-score uses **Welford's online
algorithm** for O(1) per-sample mean/variance; IsolationForest is **refit
periodically** (`refit_interval`) on the rolling window. Crucially,
`_update_state` updates Welford stats and the window **only with clean
(non-flagged) samples**, which is the anti "boiling frog" defense.

**Drift** (`drift.py`): per-feature ADWIN + a global Page-Hinkley test. When
drift is declared, poison alerts should be **suppressed** because anomalies may
be legitimate distribution shifts. This is a *signal*, not a bypass — quarantine
still applies.

**Fingerprinting** (`fingerprint.py`): Bloom filter (exact/quantized duplicates,
O(1)), a perceptual/LSH hash (sign-of-centered-features), and cosine similarity
against a bounded reference set (cluster injection / Nightshade-style).

**Scores are not comparable across methods.** A z-score of 4.0 and an isolation
score of 0.8 measure different things; do not threshold them on a common scale.

---

## 16. Module-by-Module Reference

All modules live in [`src/poison_detector/`](../src/poison_detector/). There are
22 module files (21 functional + `__init__.py`).

### Core detection

- <a id="detector-py"></a>**`detector.py`** — Public entry point `detect(X, method)`.
  Orchestrates the four methods and returns a `DetectionReport` with
  `PoisonResult` per sample. `method ∈ {"zscore","iqr","isolation","ensemble"}`
  (default `"ensemble"`); invalid method raises `ValueError`.
- **`statistical.py`** — Pure-Python `zscore_detect(X, threshold=3.0)` and
  `iqr_detect(X, k=1.5)`. No numpy; fully auditable. Uses population std
  (N denominator) and linear-interpolation percentiles.
- **`isolation.py`** — `IsolationDetector` wraps sklearn `IsolationForest`
  (`n_estimators=100`, `random_state=42`). `fit_predict` returns min-max
  normalized scores in [0,1] for **all** samples (higher = more anomalous).
- **`attribution.py`** — `feature_attribution(X, flagged_indices)` ranks each
  flagged sample's features by absolute deviation from the dataset mean;
  `format_attribution()` renders it for human review. Post-hoc explanation only.
- **`report.py`** — `format_report()` (human-readable), `export_json()`,
  `export_csv()`. Stdlib only; CSV properly escaped.

### Real-time (`[realtime]` extra)

- **`stream.py`** — `StreamingDetector` (online scoring), `WelfordAccumulator`,
  `ScoringResult`, `StreamStats`. **Not thread-safe**; serialize external access.
  Baseline must be seeded with `update_baseline(clean_samples)`.
- <a id="drift-py"></a>**`drift.py`** — `ConceptDriftDetector`, `ADWINDetector`,
  `PageHinkleyDetector`. **Constructor kwargs:** `n_features`, `delta`,
  `drift_fraction`, `ph_delta`, `ph_lambda` — **there is no `sensitivity`
  kwarg.** `examples/kafka_consumer.py` previously passed `sensitivity=` (a
  crash on that path); fixed to `delta=` in this change.
- **`fingerprint.py`** — `SampleFingerprinter` + `BloomFilter`. `is_duplicate()`
  then `add_sample()` for clean samples.
- **`config.py`** — Pydantic-settings `DetectorConfig` with nested
  `DetectionThresholds`, `StreamingConfig`, `FeatureFlags`, `AlertConfig`.
  Precedence **env > YAML > defaults**; YAML via `yaml.safe_load` only.
- **`metrics.py`** — Prometheus counters/histograms/gauges + `initialize_metrics()`.
  See [§21](#21-observability--metrics).

### Service & data plane

- **`api.py`** — FastAPI app: `POST /score`, `POST /batch` (≤1000),
  `GET /health`, `GET /stats`, `GET /metrics`, WebSocket `/stream`. Pydantic
  request validation (`features` 1–100000 long). Includes an **in-memory**
  rate-limit middleware (bucketing only, not auth) and a WebSocket
  `ConnectionManager`. App `version` string still reads `"0.1.0"`.
- **`pipeline.py`** — `PipelineConsumer` ABC + `RedisConsumer` (Redis Streams,
  consumer groups) and `KafkaConsumer` (aiokafka). DLQ + quarantine routing;
  `update_backpressure()` switches FULL ↔ STATISTICAL_ONLY. JSON deserialization
  only (never pickle/eval).
- **`storage.py`** — `QuarantineStore` ABC; **`SQLiteStore` is implemented**
  (WAL, parameterized SQL, `ResolutionStatus` workflow). **`PostgresStore` and
  `S3Store` raise `NotImplementedError`.**
- **`alerting.py`** — `AlertDispatcher` with `SlackChannel`, `PagerDutyChannel`,
  `CloudWatchChannel`, `WebhookChannel`; dedup (cooldown) + severity escalation
  (WARNING→CRITICAL→PAGE). Best-effort delivery (no infinite retry).

### Security (`[security]` extra) — see [§22](#22-security-architecture)

- **`auth.py`** — `JWTAuthenticator` (RS256/ES only; rejects HS256),
  `APIKeyAuthenticator` (bcrypt rounds=12, rotation), `MTLSValidator`
  (CA chain, CN/SAN allowlist), plus `AuditLog` and `AuthFailureRateLimiter`
  (lockout with exponential backoff). No JWT revocation; no CRL/OCSP.
- **`rbac.py`** — `RBACEnforcer`, `Role` (ADMIN/ANALYST/READONLY/SERVICE),
  `Permission` (7: SCORE, BATCH_SCORE, VIEW_QUARANTINE, RESOLVE_QUARANTINE,
  MODIFY_CONFIG, VIEW_AUDIT, EXPORT_DATA). Static `PERMISSION_MATRIX`,
  default-deny, JWT-claim roles take precedence over local assignment.
- **`crypto.py`** — `DataEncryptor` (AES-256-GCM envelope encryption, PBKDF2
  600k iters or scrypt), `IntegrityVerifier` (HMAC-SHA256, constant-time),
  `KeyDeriver`, key generators. Refuses empty/short keys.
- **`audit.py`** — `AuditLogger`: append-only JSON Lines with SHA-256 hash chain,
  `verify_integrity()`, time/sample/user/decision queries, export
  (JSON Lines/array/CSV), `fcntl` file locking, 7-year default retention.
- **`input_sanitizer.py`** — `InputSanitizer` rejects NaN/Inf/empty,
  dimension bounds, value-range bounds, and applies per-client rate limiting;
  forensic rejection log **without** raw sample data.
- **`circuit_breaker.py`** — `CircuitBreaker` (CLOSED/OPEN/HALF_OPEN) +
  `CircuitBreakerConfig`, Prometheus metrics, `create_breaker_set()` for
  isolation_forest/redis/kafka/external.
- **`rate_limiter.py`** — `SlidingWindowRateLimiter` (Redis sorted-set via an
  **atomic Lua script** to avoid TOCTOU; in-memory fallback),
  `TokenBucketRateLimiter`, `CompositeRateLimiter` (most-restrictive wins).

> **Naming discrepancy to know:** `CHANGELOG.md` (1.0.0) lists RBAC roles as
> "admin, analyst, operator, viewer". The **code** (`rbac.py`) actually defines
> **admin, analyst, readonly, service**. Trust the code.

---

## 17. Data Model & Assumptions

- **Sample format:** a flat list of floats. API: `{"features": [f0, f1, ...]}`.
  Batch: `X` is `list[list[float]]`, all rows equal length.
- **No labels.** The detector is label-unaware; it cannot see label-flipping.
- **No native text/embedding/image/multimodal support.** Embeddings must be
  pre-computed to float vectors by the caller; there is no tokenizer/encoder.
- **Feature scale assumption:** methods assume features are roughly comparable
  in scale; z-score/IsolationForest are scale-sensitive. Normalize upstream.
- **Distributional assumptions:** z-score assumes approximate per-feature
  normality; IQR assumes meaningful order statistics; Welford stats are
  **per-feature independent** → correlation poisoning is invisible.
- **Synthetic data only:** everything validated so far uses `numpy.random`
  Gaussians plus four hand-crafted attack shapes — `outlier`, `cluster`,
  `duplicate`, `feature_flip` (see `examples/realtime_demo.py`). **No real
  dataset exists in the repo.**

---

## 18. API Reference Summary

Full details in [API.md](API.md). Endpoints from `api.py`:

| Method | Path | Purpose |
|---|---|---|
| POST | `/score` | Score one sample |
| POST | `/batch` | Score ≤1000 samples |
| GET | `/health` | Liveness + status (healthy/degraded/unhealthy) |
| GET | `/stats` | Detector statistics |
| GET | `/metrics` | Prometheus exposition |
| WS | `/stream` | Real-time detection event feed |

**Score a sample:**

```python
class SampleRequest(BaseModel):
    features: list[float] = Field(..., min_length=1, max_length=100000)
    source: str = Field(default="api", max_length=256)
    metadata: dict[str, Any] = Field(default_factory=dict)

@app.post("/score", response_model=ScoringResponse)
async def score_sample(request: SampleRequest) -> ScoringResponse:
    result: ScoringResult = _detector.score_sample(request.features)
    ...
```

```bash
curl -X POST http://localhost:8000/score \
  -H "Content-Type: application/json" \
  -d '{"features": [0.1, 0.2, 0.3, 0.4, 0.5]}'
# -> {"score": 0.12, "is_poisoned": false, "method_votes": {...}, "latency_ms": 0.2}
```

**Health status logic** (from `health_check`): `degraded` if `poison_rate > 0.2`;
`unhealthy` if `avg_latency_ms > 1000`; otherwise `healthy`. Note `queue_depth`
is hard-coded to `0` and `/health` does **not** check downstream dependencies.

> **Security note:** The API does not currently enforce authentication — the
> `X-API-Key` header is used only for rate-limit bucketing (documented in
> `api.py`). WebSocket `/stream` is unauthenticated. Wire in `auth.py`/`rbac.py`
> before external exposure (see [R4](#9-risk-register)).

---

## 19. Configuration Reference

Config is managed by `config.py` (Pydantic settings). Precedence:
**environment variables > YAML file > code defaults**. Defaults live in
[`config/realtime.yaml`](../config/realtime.yaml).

| Group (env prefix) | Key | Default | Meaning |
|---|---|---|---|
| thresholds (`POISON_THRESHOLD_`) | `zscore_threshold` | 3.0 | Flag if \|z\| ≥ this |
| | `iqr_multiplier` | 1.5 | Tukey fence multiplier |
| | `isolation_contamination` | 0.05 | Expected poison fraction |
| | `ensemble_vote_threshold` | 2 | Votes to flag |
| | `similarity_threshold` | 0.95 | Cosine dup threshold |
| streaming (`POISON_STREAM_`) | `window_size` | 10000 | Rolling window |
| | `refit_interval` | 1000 | Clean samples between IsoForest refits |
| | `drift_sensitivity` | 0.01 | ADWIN delta |
| | `max_batch_size` | 512 | Max per batch call |
| features (`POISON_FLAG_`) | `enable_*` | mostly true | Kill switches (`enable_alerting` false) |
| alerts (`POISON_ALERT_`) | `slack_webhook_url`, `pagerduty_routing_key`, `cooldown_seconds` (300), `poison_rate_alert_threshold` (0.1) | — | Alert routing |

Load explicitly with `DetectorConfig.from_yaml("config/realtime.yaml")` or set
`POISON_CONFIG_FILE`. Secrets (webhooks, keys) should come from env/secret
stores, not committed YAML.

---

## 20. Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for the authoritative guide. Summary:

- **Local:** `pip install -e ".[dev,realtime]"`, then
  `uvicorn poison_detector.api:app --reload`.
- **Docker:** multi-stage, non-root [`Dockerfile`](../Dockerfile);
  `docker compose up -d` brings up API + Redis + Kafka + Prometheus + Grafana.
- **Kubernetes:** 9 hardened manifests in [`k8s/`](../k8s/) — `deployment.yaml`,
  `service.yaml`, `configmap.yaml`, `secret.yaml`, `serviceaccount.yaml`,
  `hpa.yaml`, `pdb.yaml`, `ingress.yaml`, `networkpolicy.yaml`. Restricted Pod
  Security Standards, HPA autoscaling, PodDisruptionBudget, zero-trust
  NetworkPolicy.
- **Terraform (AWS):** [`terraform/`](../terraform/) with modules
  `eks`, `rds` (Aurora PostgreSQL), `redis` (ElastiCache), `s3`, plus KMS
  references. Entry points `main.tf`, `variables.tf`, `outputs.tf`.

---

## 21. Observability & Metrics

Defined in `metrics.py`, scraped at `GET /metrics`. Assets in
[`observability/`](../observability/): `prometheus-rules.yaml`,
`grafana-dashboard.json`, `otel-collector.yaml`, and three runbooks.

| Type | Metric | Meaning |
|---|---|---|
| Counter | `poison_detector_samples_processed_total` | Samples scored |
| Counter | `poison_detector_samples_poisoned_total` | Flagged (by method) |
| Counter | `poison_detector_drift_events_total` | Drift events |
| Counter | `poison_detector_alerts_sent_total` | Alerts dispatched |
| Counter | `poison_detector_duplicates_detected_total` | Dups found |
| Histogram | `poison_detector_scoring_latency_seconds` | Per-sample latency |
| Histogram | `poison_detector_batch_latency_seconds` | Batch latency |
| Histogram | `poison_detector_refit_latency_seconds` | IsoForest refit time |
| Gauge | `poison_detector_drift_score` | Current drift score |
| Gauge | `poison_detector_poison_rate` | Rolling poison rate |
| Gauge | `poison_detector_baseline_size` | Baseline sample count |
| Gauge | `poison_detector_queue_depth` | Pipeline queue depth |

Counters reset on restart — use `rate()` in PromQL. Keep `/metrics` on an
internal network. See [OPERATIONS.md](OPERATIONS.md).

---

## 22. Security Architecture

Full detail in [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md).
The security layer is implemented as **standalone, tested modules**. The main
integration gap is that `api.py` does not yet call them in middleware.

- **Authentication (`auth.py`):** JWT **RS256/ES only** (HS256 rejected to
  prevent key confusion); API keys stored as **bcrypt** hashes (rounds=12) with
  rotation; **mTLS** with CA-chain verification and CN/SAN allowlists. Auth
  failures feed `AuthFailureRateLimiter` (lockout + exponential backoff) and an
  in-memory `AuditLog`. **Limitations:** no JWT revocation (use short-lived
  tokens), no CRL/OCSP for mTLS.
- **Authorization (`rbac.py`):** Default-deny. 4 roles (admin/analyst/readonly/
  service), 7 permissions, static matrix, JWT-claim roles win over local
  assignment. Coarse-grained RBAC (not ABAC), flat hierarchy.
- **Crypto (`crypto.py`):** AES-256-GCM **envelope encryption** (random DEK per
  record, KEK derived from master key), **PBKDF2 600k** iterations (OWASP 2024)
  or scrypt, **HMAC-SHA256** integrity (constant-time compare). Nonces via
  `os.urandom`; refuses empty/short keys.
- **Audit (`audit.py`):** Append-only JSON Lines with a **SHA-256 hash chain**;
  `verify_integrity()` detects modification/insertion/deletion; SOC2/ISO27001
  oriented with 7-year default retention. Tamper-*evident*, not tamper-*proof*.
- **Input sanitization (`input_sanitizer.py`):** First line of defense —
  rejects NaN/Inf (which crash sklearn), oversized/under-sized dimensions,
  out-of-range values; per-client rate limiting; forensic log excludes raw data.
- **Resilience:** `circuit_breaker.py` (per-dependency isolation, degrades to
  statistical-only) and `rate_limiter.py` (distributed sliding window via atomic
  Lua + token bucket, in-memory fallback).

**No multi-tenant isolation** exists — do not run a single instance across
mutually untrusted tenants.

---

## 23. Testing Strategy & Coverage

- **60 tests passing, 68% coverage** (below the typical 90% enterprise bar).
- **Unit tests** ([`tests/`](../tests/)): one per module — `test_detector.py`,
  `test_statistical.py`, `test_isolation.py`, `test_stream.py`, `test_drift.py`,
  `test_fingerprint.py`, `test_attribution.py`, `test_api.py`,
  `test_pipeline.py`, `test_auth.py`, `test_rbac.py` (implied),
  `test_crypto.py`, `test_audit.py`, `test_input_sanitizer.py`,
  `test_circuit_breaker.py`, `test_rate_limiter.py`.
- **Integration tests** ([`tests/integration/`](../tests/integration/)):
  `test_end_to_end.py`, `test_failover.py`, `test_load.py`. The load test
  currently proves only a ~1K/sec floor.

Run: `pip install -e ".[dev,realtime]" && pytest tests/ -v`.
Priority: raise coverage on error/rejection paths and the security modules, and
build a **real-data accuracy** test suite (currently absent).

---

## 24. Performance Characteristics & Benchmarks

README benchmarks (single core, Intel Xeon Platinum 8375C, 10-dim vectors,
`window_size=10000`) — **synthetic, single-machine, treat as indicative:**

| Metric | Value |
|---|---|
| Throughput | 12,400 samples/sec (single-threaded, ensemble) |
| Latency p50 / p95 / p99 | 0.08 / 0.14 / 0.31 ms |
| Memory (10k / 100k window) | 45 MB / 380 MB (linear in window) |
| Drift overhead | +0.02 ms/sample |
| Fingerprint check | +0.01 ms/sample |
| HTTP `POST /score` | ~8,200 req/sec (4 uvicorn workers) |
| Batch (`/batch`, 512) | ~45,000 samples/sec |

**Caveats:** benchmarks are on 10-dimensional synthetic data. IsolationForest
will not sustain <50ms p99 on high-dimensional inputs (e.g., 768-dim embeddings)
without dimensionality reduction, and the SLO throughput targets are unvalidated
at scale (see [§6](#6-sla--slo-summary)).

---

## 25. Known Limitations & Blind Spots

A senior doc names these plainly:

1. **Synthetic data only** — no real dataset in the repo; four hand-crafted attack shapes.
2. **Low demo accuracy** — ~78% recall, ~18% precision, 161 false positives; not production accuracy.
3. **No label awareness** — cannot detect label-flipping / clean-label attacks.
4. **No text/embedding-native or multimodal detection** — flat float vectors only.
5. **Per-feature independence** (Welford) — cannot catch correlation poisoning.
6. **IsolationForest high-dimensionality** — degrades >100 dims; blows the latency budget without PCA/feature selection.
7. **No influence-function / loss-based / spectral detection** — the methods leading labs actually use are absent.
8. **No multi-tenant isolation.**
9. **JWT has no revocation** (stateless) — mitigate with short TTLs.
10. **Load test proves only ~1K/sec** — not the 10K SLO, not 100K+.
11. **Storage backends** — only `SQLiteStore` works; `PostgresStore`/`S3Store` are stubs.
12. **Security modules not wired into the API request path** yet.
13. **68% test coverage.**
14. **Adaptive adversary** — ensemble assumes a non-adaptive attacker; a defender-aware attacker can evade all three.
15. **Fixed bug (historical):** `examples/kafka_consumer.py` used
    `ConceptDriftDetector(sensitivity=...)` (invalid kwarg → crash); corrected to
    `delta=` in this change.

---

## 26. Technical Roadmap to Close Gaps

Ordered by leverage:

1. **Real evaluation harness** *(highest priority).* Curate real, labeled,
   adversarial datasets; measure precision/recall/F1/ROC per method and for the
   ensemble; publish an honest scorecard. Everything else is secondary until
   accuracy is trustworthy.
2. **Threshold/contamination tuning** driven by (1), per data profile.
3. **Label-aware & clean-label detection** — compare against a trusted held-out set.
4. **Multivariate / correlation-aware detection** — covariance-based or spectral (SVD) methods; add influence-function / loss-based detection.
5. **Embedding-native path** — built-in dimensionality reduction (PCA/random projection) before IsolationForest to hold latency at 768+ dims.
6. **Wire security into the API** — auth/RBAC/distributed rate-limit middleware in `api.py`; authenticate WebSocket `/stream`.
7. **Implement `PostgresStore` and `S3Store`** for multi-process/high-volume and large-sample storage.
8. **JWT revocation** (denylist or short-TTL + refresh rotation) and mTLS CRL/OCSP.
9. **Multi-tenant isolation** (namespacing, per-tenant baselines and quotas).
10. **Real load test to the SLO** (10K+/sec) and fix `/health` to check downstream dependencies; correct the API `version` string (`"0.1.0"` → `1.0.0`).
11. **Raise test coverage to ≥90%**, focused on error paths and security modules.
12. **Author formal ADRs** from the decision log in [§10](#10-decision-log--adr-summary).

---

*Maintained on branch `feat/enterprise-hardening`. When behavior changes, update
this guide and the cross-linked docs together.*
