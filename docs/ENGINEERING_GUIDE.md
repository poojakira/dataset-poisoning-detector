# Engineering Guide — Dataset Poisoning Detector

> **Audience:** A new engineering team inheriting this project.
> **Purpose:** The single "everything you need to know" reference. It covers
> both the technical system and the non-technical context (product, ownership,
> compliance, risk).
> **Version:** 1.1.0 · **Branch of record:** `feat/detection-hardening` (off `feat/enterprise-hardening`) ·
> **Repo:** [poojakira/dataset-poisoning-detector](https://github.com/poojakira/dataset-poisoning-detector)
> **License:** Apache-2.0
>
> **v1.1.0 "detection hardening" — what changed since 1.0.0:** the detector is no
> longer synthetic-only. It now ships a **real-data benchmark harness** (bundled
> scikit-learn datasets + poison injected at known indices) that reports honest
> precision/recall/F1/ROC-AUC; three **new detection methods** top labs actually
> use (spectral/SVD covariance-aware, label-aware kNN, surrogate loss/influence);
> a **calibrated ensemble** (measured ROC-AUC ≈ 0.94, precision ≈ 0.44 vs the old
> synthetic ~0.18); an **optional label + metadata** data model; a
> **dimensionality-reduction path** for high-dim embeddings; **multi-tenant
> isolation**; **JWT revocation**; a **vectorized batch-scoring path** (~1.3M
> samples/sec statistical); and **test coverage raised 68% → 94%**. Numbers in
> this guide are the real measured outputs of `examples/benchmark.py`, not
> aspirational targets.

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

Detection is now an **ensemble of up to seven** detectors — z-score, IQR,
Isolation Forest, spectral/SVD (covariance-aware), label-aware kNN, surrogate
loss/influence, and near-duplicate fingerprinting — combined by a **calibrated,
rank-normalized max-combiner** so a specialist that alone catches a given attack
is still heard. (The batch `detect()` still offers the original ≥2-of-3
majority-vote ensemble for backward compatibility.) Around this core sit
production concerns: concept-drift suppression, quarantine storage, multi-channel
alerting, a FastAPI service, Kafka/Redis pipeline consumers, multi-tenant
isolation, and a full security + infrastructure layer.

**Why it matters.** For any organization that ingests third-party or
user-supplied training data (fine-tuning APIs, RLHF pipelines, data-curation
platforms), an automated first-pass filter reduces the blast radius of a
poisoning campaign and creates an auditable record of what was rejected and why.

**The honest caveat.** The engineering scaffolding is genuinely production-grade
(auth, RBAC, crypto, audit, K8s, Terraform). Detection is now **measured on real
data** (scikit-learn's bundled datasets) rather than synthetic Gaussians only,
and the calibrated ensemble reaches **ROC-AUC ≈ 0.94** with **precision ≈ 0.44**
at a balanced operating point — a large, honest improvement over the old
synthetic ~0.18 precision, but still a **triage signal for human review, not an
automated accept/reject gate.** The bundled datasets are small and clean, so the
*relative* ranking of methods/attacks transfers more reliably than the absolute
percentages; validation on a large, labeled, adversarial production corpus is
still the top open item. See [§12](#12-honest-product-maturity-assessment) and
[§24](#24-performance-characteristics--benchmarks).

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

# Core + dev + realtime + security extras (Python >= 3.10)
pip install -e ".[dev,realtime,security]"

# Run the test suite (should be ~276 passing, 94% coverage)
pytest tests/ -v

# See detection in action on synthetic data...
python examples/realtime_demo.py
# ...and the REAL-data honest benchmark scorecard
python examples/benchmark.py
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
- `realtime_demo.py` is synthetic; `examples/benchmark.py` is the **real** scorecard.
  The bundled datasets are small and clean — the relative ranking of methods and
  attacks transfers better than the absolute percentages.

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

> **Honest note (updated for 1.1.0):** The per-sample streaming path now
> measures ~50k samples/sec and the **vectorized batch path
> (`score_batch_vectorized`) ~1.3M samples/sec** on the statistical path (10-dim,
> single core); CI asserts conservative floors of 10k and 100k respectively. So
> the 10K/sec throughput SLO is comfortably met on the statistical path. Two
> caveats remain: (1) the IsolationForest path is slower and still will not hold
> a <50ms p99 on very high-dimensional inputs without the new
> `reduce_dim` projection ([§17](#17-data-model--assumptions)); (2) 100K+/sec of
> the *full* ensemble under realistic concurrency is still unproven — do not
> commit a full-ensemble 100K SLO without a dedicated load test.

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

| ID | Risk | Likelihood | Impact | Mitigation / Owner / Status |
|---|---|---|---|---|
| R1 | Detection accuracy on **large real-world adversarial** data still unproven (now measured on *small* real sklearn datasets) | Medium | High | **Partially mitigated** in 1.1.0 via the real-data benchmark; validate on a large labeled corpus next; ML team |
| R2 | Adaptive adversary evades the ensemble | Medium | High | Reduced: ensemble now spans 7 diverse methods (incl. spectral/label/influence); a defender-aware attacker can still adapt |
| R3 | Full-ensemble 100K/sec SLO not validated | Medium | Medium | Statistical path now ~1.3M/sec vectorized; full-ensemble load test still needed; SRE |
| R4 | Security modules exist but are **not wired into API middleware** | High | High | **Still open**: integrate auth/RBAC/rate-limit into `api.py`; Security |
| R5 | JWT revocation | — | — | **Addressed** in 1.1.0 (`TokenDenylist`, jti-based, TTL-bounded); back with Redis for multi-replica |
| R6 | Multi-tenant isolation | — | — | **Addressed** in 1.1.0 (`tenancy.py`: per-tenant baselines/quarantine/quotas); in-process only |
| R7 | `PostgresStore` / `S3Store` are stubs; only SQLite works | High | Medium | **Still open**: implement before multi-process production use |
| R8 | Audit log deletable by file-access attacker | Low | High | Append-only FS / remote shipping |
| R9 | Correlation poisoning invisible to per-feature stats | — | — | **Addressed** in 1.1.0 (`spectral.py` covariance-residual; F1≈0.59, AUC≈0.96 on the correlation attack) |
| R10 | Test coverage below 90% | — | — | **Addressed** in 1.1.0 (68% → 94%) |
| R11 | Ensemble hard-threshold precision on duplicate/correlation attacks is modest (~0.25 F1) despite high AUC | Medium | Medium | Per-attack threshold calibration on held-out clean data; documented in [§24](#24-performance-characteristics--benchmarks) |

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
| ADR-12 (1.1.0) | Benchmark on **bundled sklearn datasets** with injected poison | Hermetic, network-free, reproducible real metrics | Small/clean data; not web-scale |
| ADR-13 (1.1.0) | Calibrated ensemble = **rank-normalize → elementwise max** | No attack silently missed; specialists heard | Lower hard-threshold precision than a tuned per-attack cut |
| ADR-14 (1.1.0) | **Spectral covariance-residual** for correlation poison | SVD exposes joint structure per-feature stats miss | Assumes minority contamination |
| ADR-15 (1.1.0) | JWT revocation via **in-memory TTL denylist**; multi-tenancy **in-process** | Simple, dependency-free defaults | Per-process only; back with Redis / separate pods for hostile multi-tenancy |
| ADR-16 (1.1.0) | **Vectorized batch scoring** alongside per-sample path | ~25× throughput for bulk auditing | Scores against current baseline, batch state update |

---

## 11. FAQ

**Q: Is this production-ready?**
The *platform* (security, infra, observability) is mature. The *detector's
accuracy* is not validated on real data. See [§12](#12-honest-product-maturity-assessment).

**Q: What sample format does it expect?**
A flat list of floats per sample: `{"features": [0.1, 0.2, ...]}`. No labels, no
text, no images. See [§17](#17-data-model--assumptions).

**Q: Can it catch label-flipping attacks?**
Yes, as of 1.1.0 — supply labels and the label-aware kNN detector
(`label_aware.py`) flags samples whose label disagrees with their feature-space
neighbors (F1 up to ~0.90 on the benchmark's label-flip attack). Feature-only
methods remain blind to label flips; that is why the label-aware method exists.

**Q: What accuracy does it actually get?**
On the real benchmark (breast cancer, poison at known indices), the calibrated
ensemble averages precision ≈ 0.44, recall ≈ 0.46, ROC-AUC ≈ 0.94 — up from the
old synthetic ~0.18 precision. Datasets are small/clean, so treat it as a triage
signal and validate on your own labeled data. Run `python examples/benchmark.py`.

**Q: Is auth enforced on the API?**
Not yet. `auth.py`/`rbac.py`/`rate_limiter.py` exist and are tested, but `api.py`
only applies an in-memory rate limiter for bucketing. Wiring them in is an open task ([R4](#9-risk-register)).

**Q: Which storage backend works?**
Only `SQLiteStore`. `PostgresStore` and `S3Store` raise `NotImplementedError`.

**Q: Is test coverage adequate?**
Yes — 276 tests, 94% coverage (was 60 tests / 68%). See [§23](#23-testing-strategy--coverage).

**Q: Known bugs?**
The historical `examples/kafka_consumer.py` `ConceptDriftDetector(sensitivity=...)`
crash is fixed (`delta=`) and pinned by `tests/test_kafka_consumer_wiring.py`.
Remaining known gaps are the open items in [§25](#25-known-limitations--blind-spots)
(API auth not wired in; Postgres/S3 storage stubs).

---

## 12. Honest Product Maturity Assessment

**Overall rating: 7/10 (up from 6/10) — a strong production *platform* with a
detector that is now measured on real data and materially broader, but still
awaiting large-scale real-world validation.**

| Dimension | Rating | Notes |
|---|---|---|
| Engineering / infra maturity | 8/10 | K8s, Terraform, CI/CD, containers, observability all present |
| Security architecture | 7/10 | Excellent modules incl. new JWT revocation + multi-tenant isolation; still **not integrated** into the API request path |
| Detection accuracy | 5/10 (was 3/10) | Now measured on real sklearn data: calibrated ensemble ROC-AUC ≈ 0.94, precision ≈ 0.44 (was synthetic ~0.18); still small/clean datasets, hard-threshold precision modest on some attacks |
| Method breadth | 7/10 (new) | 7 methods incl. spectral/SVD, label-aware, influence — the families leading labs use; multimodal still absent |
| Data realism | 5/10 (was 2/10) | Real bundled datasets + injected poison at known indices; still not a large web-scale adversarial corpus |
| Test coverage | 9/10 (was 6/10) | 276 tests, 94% coverage — above the 90% enterprise bar |
| Documentation | 9/10 | Thorough and honest about limitations |
| Scalability (proven) | 6/10 (was 4/10) | Vectorized statistical path ~1.3M/sec; full-ensemble 100K/sec still unproven |

**Bottom line:** Adopt it as a well-architected foundation with a detector that
now earns real (if small-scale) numbers. Use its scores as a human-review triage
signal; validate on a large labeled adversarial dataset before treating any
score as an automated accept/reject gate.

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

As of 1.1.0 there are **seven** detectors spanning unsupervised feature-space,
covariance-aware, supervised, and duplicate-detection families, combined by a
calibrated ensemble. The first four are unsupervised feature-space detectors
(detect statistical anomaly, not intent); the last three add label-awareness,
supervised loss, and near-duplicate detection.

| Method | Module | Catches | Misses |
|---|---|---|---|
| **Z-score** (per-feature, flag if any \|z\| ≥ 3.0) | `statistical.zscore_detect` | Extreme point outliers | Non-Gaussian tails, in-distribution attacks, label flips, correlations |
| **IQR fence** (Tukey, k=1.5) | `statistical.iqr_detect` | Robust distributional outliers | Samples just inside the fence; zero-spread features |
| **Isolation Forest** (sklearn, contamination≈0.05) | `isolation.IsolationDetector` | Density/cluster anomalies | Clean-label, distributed poisoning; degrades in high dimensions |
| **Spectral / SVD** (top-k signature + whitened covariance residual) | `spectral.spectral_detect` | **Correlation poisoning** (in-range features, impossible joint) and off-manifold clusters | Poison that dominates the top singular vectors (heavy contamination) |
| **Label-aware kNN** (label disagreement vs. neighbors) | `label_aware.label_aware_detect` | **Label-flipping / clean-label** attacks | Boundary-ambiguous points; needs labels; O(n²)-ish batch tool |
| **Loss / influence** (surrogate logistic-regression) | `influence.influence_detect` | Mislabeled / hard-to-fit samples | Approximate (not exact influence functions); needs labels |
| **Fingerprint** (Bloom + cosine similarity) | `fingerprint.SampleFingerprinter` | **Duplicate / near-duplicate injection** | Unique samples that collectively bias the model |
| **Calibrated ensemble** (rank-normalize each → elementwise max → contamination-quantile flag) | `benchmark.calibrated_ensemble_*` | Whichever specialist fires; **no attack it completely misses** (ROC-AUC ≈ 0.94) | Precision cost at the hard threshold (a clean top-outlier of one method can be flagged) |

**Why max, not majority vote, for the calibrated ensemble.** Different attacks
are caught by different specialists: only fingerprinting catches duplicate
injection, only the covariance-residual catches correlation poison, only the
label-aware detector catches label flips. A mean/majority combiner dilutes a
lone specialist's strong signal below the flagging threshold — measured at
**0.00 F1 on duplicate injection**. Rank-normalizing each method to [0,1] and
taking the elementwise **max** lets whichever specialist fires be heard, so the
ensemble has no attack it silently misses. The cost is some precision, reported
honestly in [§24](#24-performance-characteristics--benchmarks).

> The original batch `detect(X, method="ensemble")` still uses the simpler
> **≥2-of-3 majority vote** over z-score/IQR/IsolationForest, unchanged, for
> backward compatibility. The calibrated 7-method ensemble is exposed through
> the benchmark harness and `benchmark.calibrated_ensemble_scores/predictions`.

**Real benchmark harness (new).** `benchmark.py` + `examples/benchmark.py` load
a real bundled dataset, inject poison at KNOWN indices (`datasets.py`), run every
method, and print an honest precision/recall/F1/ROC-AUC scorecard plus JSON. This
is how every number in [§24](#24-performance-characteristics--benchmarks) is
produced — reproduce with `python examples/benchmark.py`.

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

### Detection methods & evaluation added in 1.1.0 (core install — sklearn/numpy)

- **`spectral.py`** — SVD-based covariance-aware detection.
  `spectral_signature_scores` (top-k projection), `covariance_residual_scores`
  (whitened Mahalanobis via the same SVD), and `spectral_scores`/`spectral_detect`
  (rank-normalized max of both). Catches correlation poisoning that per-feature
  stats structurally miss.
- **`label_aware.py`** — `label_disagreement_scores` / `label_aware_detect`:
  kNN label-disagreement (confident-learning style) to catch label flipping.
  Requires labels; batch auditing tool.
- **`influence.py`** — `loss_scores` / `influence_scores` / `influence_detect`:
  approximate surrogate-loss/self-influence from a cheap logistic-regression
  surrogate. Documented as approximate (not exact influence functions).
- **`reduction.py`** — `DimensionalityReducer` (PCA or Gaussian random
  projection) to run before IsolationForest on high-dimensional embeddings.
  No-op pass-through when input dim ≤ target dim.
- **`sample.py`** — `Sample` dataclass + `coerce_sample`/`coerce_matrix`:
  the extended data model (optional label + metadata), fully backward compatible
  with the legacy flat-float-list format.
- **`datasets.py`** — real bundled-dataset loaders (`load_reference_dataset`) and
  `PoisonInjector` / `inject_poison` that inject the five attacks at known
  indices for benchmarking.
- **`benchmark.py`** — the honest scorecard harness (`run_benchmark`,
  `format_scorecard`, `calibrated_ensemble_scores/predictions`, `method_scores`,
  `method_predictions`).
- **`tenancy.py`** — `TenantManager` (per-tenant isolated detectors),
  `TenantQuarantine` (namespaced quarantine), per-tenant rate-limit quotas,
  `validate_tenant_id`.

### Real-time (`[realtime]` extra)

- **`stream.py`** — `StreamingDetector` (online scoring), `WelfordAccumulator`,
  `ScoringResult`, `StreamStats`. **Not thread-safe**; serialize external access.
  Baseline must be seeded with `update_baseline(clean_samples)`.
- <a id="drift-py"></a>**`drift.py`** — `ConceptDriftDetector`, `ADWINDetector`,
  `PageHinkleyDetector`. **Constructor kwargs:** `n_features`, `delta`,
  `drift_fraction`, `ph_delta`, `ph_lambda` — **there is no `sensitivity`
  kwarg.** `examples/kafka_consumer.py` correctly calls
  `ConceptDriftDetector(delta=...)`; this is now pinned by
  `tests/test_kafka_consumer_wiring.py` so the historical `sensitivity=` crash
  cannot regress.
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
  (lockout with exponential backoff). **New in 1.1.0:** `TokenDenylist` and
  `JWTAuthenticator.revoke()` provide TTL-bounded, `jti`-based JWT **revocation**
  (a signature-valid but revoked token is denied). Still no CRL/OCSP for mTLS;
  the in-memory denylist should be Redis-backed for multi-replica deployments.
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

- **Sample format (extended, backward compatible):** the legacy flat list of
  floats still works everywhere. As of 1.1.0 a sample may **optionally** carry a
  label and metadata: `{"features": [...], "label": 1, "metadata": {...}}`, or a
  `Sample` object (`sample.py`). `coerce_sample`/`coerce_matrix` normalize any of
  these forms. The API `SampleRequest` gained an optional `label` field
  (passed through to the response; the unsupervised streaming score ignores it).
- **Labels now enable label-aware detection.** With labels present, the
  label-aware kNN and loss/influence methods can catch label-flipping that every
  feature-only method is blind to. Without labels, those methods are simply
  skipped (not silently zeroed).
- **High-dimensional / embedding path:** feed pre-computed float embeddings;
  set `reduce_dim` on `StreamingDetector` (or use `DimensionalityReducer`) to
  project 768-dim-style vectors down before IsolationForest. There is still no
  built-in tokenizer/encoder; `examples/embedding_demo.py` shows the TF-IDF path.
- **Feature scale assumption:** methods assume features are roughly comparable
  in scale; z-score/IsolationForest are scale-sensitive. Normalize upstream
  (the benchmark standardizes features).
- **Distributional assumptions:** z-score assumes approximate per-feature
  normality; IQR assumes meaningful order statistics; Welford streaming stats are
  **per-feature independent** → correlation poisoning is invisible *to them*, but
  the new `spectral.py` covariance-residual now covers that gap in batch mode.
- **Data realism (updated):** the benchmark now runs on **real, bundled
  scikit-learn datasets** (breast cancer, digits, iris, wine) with poison
  injected at known indices — hermetic and network-free. Five attack families
  are modeled: `label_flip`, `feature_outlier`, `cluster_injection`,
  `duplicate_injection`, `correlation_poison`. The legacy synthetic demo
  (`examples/realtime_demo.py`) still exists for illustration. Remaining gap: no
  *large, web-scale, real-world adversarial* corpus is checked in.

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

- **276 tests passing, 94% coverage** (up from 60 tests / 68% — above the
  typical 90% enterprise bar). Per-module highlights: `input_sanitizer` 100%,
  `crypto` 99%, `config`/`audit` 97%, `alerting` 95%, `rate_limiter`/`benchmark`
  94%, `auth` 93%, `pipeline` 92%, `tenancy`/`sample` 100%.
- **Unit tests** ([`tests/`](../tests/)): one-or-more per module, including the
  new `test_datasets.py`, `test_spectral.py`, `test_label_aware.py`,
  `test_influence.py`, `test_benchmark.py`, `test_sample.py`,
  `test_reduction.py`, `test_stream_reduction.py`, `test_tenancy.py`,
  `test_jwt_revocation.py`, `test_kafka_consumer_wiring.py`, plus coverage
  files for the enterprise modules (auth, pipeline, alerting, rate_limiter,
  config, crypto, audit, input_sanitizer).
- **Integration tests** ([`tests/integration/`](../tests/integration/)):
  `test_end_to_end.py`, `test_failover.py`, `test_load.py`. The load test now
  asserts a **10k/sec per-sample** floor and a **100k/sec vectorized** floor
  (measured much higher), plus a correctness check pinning the vectorized path
  to the per-sample decisions.
- Redis/Kafka/mTLS paths are exercised hermetically via scripted fakes and
  runtime-generated certs — no external services required in CI.

Run: `pip install -e ".[dev,realtime,security]" && pytest tests/ -v`.
Coverage: `pytest tests/ --cov=poison_detector --cov-report=term-missing`.
Remaining priority: a **large real-world adversarial** accuracy suite (the small
bundled datasets validate mechanics and relative ranking, not web-scale quality).

---

## 24. Performance Characteristics & Benchmarks

### 24.1 Detection accuracy — real measured scorecard (NEW)

Produced by `python examples/benchmark.py` on scikit-learn's **breast cancer**
dataset (569 samples × 30 features, standardized), poison injected at known
indices, averaged over contamination levels 2% / 5% / 10%. **These are the real
numbers the harness prints — reproduce them yourself; nothing here is
hand-picked.**

Per-method averages across all five attacks and contamination levels:

| Method | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|
| **Calibrated ensemble** | **0.44** | **0.46** | **0.45** | **0.94** |
| fingerprint | 0.60 | 0.59 | 0.60 | 0.60 |
| spectral | 0.30 | 0.59 | 0.40 | 0.76 |
| isolation | 0.39 | 0.39 | 0.39 | 0.65 |
| label_aware | 0.37 | 0.36 | 0.35 | 0.83 |
| zscore | 0.29 | 0.40 | 0.32 | 0.66 |
| influence | 0.22 | 0.43 | 0.29 | 0.71 |
| iqr | 0.11 | 0.55 | 0.18 | 0.68 |

Ensemble performance **per attack** (why breadth matters — each attack is
carried by a different specialist):

| Attack | Ensemble P / R / F1 / AUC | Best single method |
|---|---|---|
| feature_outlier | 0.63 / 0.66 / 0.64 / 0.98 | z-score & isolation (F1 1.00) |
| label_flip | 0.61 / 0.65 / 0.63 / 0.97 | label_aware (F1 up to 0.90) |
| cluster_injection | 0.46 / 0.47 / 0.46 / 0.97 | isolation / fingerprint |
| correlation_poison | 0.26 / 0.26 / 0.26 / 0.89 | **spectral** (F1 ≈ 0.59, AUC ≈ 0.96) |
| duplicate_injection | 0.25 / 0.26 / 0.25 / 0.91 | **fingerprint** (F1 1.00) |

**Before → after (honest).** The pre-1.1.0 synthetic demo reported roughly
**78% recall / 18% precision / 161 false positives**. On the real benchmark the
calibrated ensemble reaches **precision ≈ 0.44 at ROC-AUC ≈ 0.94** — a large
precision improvement with strong ranking quality.

**Honest reading of these numbers:**
- The ensemble's **ROC-AUC (0.94) is strong** — it *ranks* poison well across
  every attack. The lower F1 on `duplicate_injection`/`correlation_poison`
  (~0.25) despite high AUC means the weakness is the **hard threshold**, not the
  ranking: a single global contamination-quantile cut is suboptimal when a
  specialist's score distribution differs. Per-attack threshold calibration on
  held-out clean data is the recommended next step (see [R11](#9-risk-register)).
- Datasets are **small and clean**; treat the *relative* method/attack ranking as
  the transferable signal, not the absolute percentages.
- `label_aware`/`influence` require labels; they are omitted (not zeroed) on
  unlabeled runs.

### 24.2 Throughput (measured, this environment)

| Path | Measured | CI-asserted floor |
|---|---|---|
| Per-sample statistical (`score_sample`) | ~50,000 samples/sec | > 10,000/sec |
| **Vectorized batch (`score_batch_vectorized`)** | **~1,330,000 samples/sec** | > 100,000/sec |

Both are on 10-dim data, single core. The vectorized path evaluates the z-score
check for the whole batch with numpy and calls IsolationForest once per batch
(~25× the per-sample path). Earlier README figures (12.4k/sec ensemble, sub-ms
latency, memory linear in window) remain indicative for the ensemble path.

**Caveats:** the IsolationForest path is heavier and will not sustain <50ms p99
on very high-dimensional inputs without the `reduce_dim` projection
([§17](#17-data-model--assumptions)); full-ensemble 100K+/sec under realistic
concurrency is still unproven (see [§6](#6-sla--slo-summary)).

---

## 25. Known Limitations & Blind Spots

Status legend: ✅ addressed in 1.1.0 · 🟡 partially addressed · ❌ still open.

1. ✅ **Real data added** — the benchmark runs on bundled sklearn datasets with
   poison injected at known indices. 🟡 Still no *large web-scale adversarial*
   corpus; the bundled sets are small and clean.
2. ✅ **Accuracy measured and improved** — calibrated ensemble precision ≈ 0.44,
   ROC-AUC ≈ 0.94 (was synthetic ~0.18 precision). 🟡 Hard-threshold F1 on
   duplicate/correlation attacks is modest (~0.25) despite high AUC — threshold
   calibration is the next step.
3. ✅ **Label awareness added** — `label_aware.py` catches label-flipping when
   labels are supplied.
4. 🟡 **Embedding path added** (`reduction.py` + `examples/embedding_demo.py`),
   but **no native text/image/multimodal modeling** — you still supply float
   vectors.
5. ✅ **Correlation poisoning now covered** in batch by `spectral.py`'s
   covariance-residual score. 🟡 The *streaming* Welford path is still
   per-feature independent; a streaming covariance estimator is future work.
6. 🟡 **High-dimensionality mitigated** via optional `reduce_dim` PCA/random
   projection before IsolationForest; a guaranteed <50ms p99 at 768-dim under
   load is still config- and hardware-dependent.
7. ✅ **Spectral, label-aware, and loss/influence detection added.** 🟡 The
   influence score is an approximation, not exact influence functions; no
   gradient access to a victim model.
8. ✅ **Multi-tenant isolation added** (`tenancy.py`). 🟡 In-process logical
   isolation only — use separate pods for hostile multi-tenancy.
9. ✅ **JWT revocation added** (`TokenDenylist`). 🟡 In-memory/per-process; back
   with Redis for multi-replica.
10. ✅ **Throughput proven far higher** — ~1.3M/sec vectorized statistical path;
    CI floors at 10k (per-sample) / 100k (vectorized). 🟡 Full-ensemble 100K/sec
    under concurrency still unproven.
11. ❌ **Storage backends** — only `SQLiteStore` works; `PostgresStore`/`S3Store`
    remain stubs.
12. ❌ **Security modules still not wired into the API request path** (auth/RBAC
    middleware) — the biggest remaining enterprise gap.
13. ✅ **Test coverage 94%** (was 68%).
14. 🟡 **Adaptive adversary** — the ensemble is now broader (7 methods) but a
    defender-aware attacker can still adapt; this is inherent to unsupervised
    detection.
15. ✅ **Kafka drift-kwarg bug** — `examples/kafka_consumer.py` correctly uses
    `delta=` and is now pinned by a regression test.

---

## 26. Technical Roadmap to Close Gaps

**Delivered in 1.1.0** (was items 1, 3, 4-partial, 5, 8, 9, 11 on the old list):
real benchmark harness; label-aware, spectral, and loss/influence detection;
dimensionality reduction for embeddings; JWT revocation; multi-tenant isolation;
vectorized throughput; test coverage to 94%.

**Still open, ordered by leverage:**

1. **Large real-world adversarial evaluation** — the current harness proves
   mechanics and relative ranking on small clean datasets; validate on a large
   labeled adversarial corpus and re-tune before treating scores as a gate.
2. **Per-attack / adaptive threshold calibration** — convert the ensemble's
   strong ranking (AUC 0.94) into higher hard-threshold precision on
   duplicate/correlation attacks using held-out clean data.
3. **Streaming covariance-aware detection** — bring the batch spectral
   covariance-residual capability to the online path (streaming covariance
   estimate) so correlation poison is caught in real time, not only in batch.
4. **Wire security into the API** — auth/RBAC/distributed rate-limit middleware
   in `api.py`; authenticate WebSocket `/stream`. (Biggest remaining gap.)
5. **Implement `PostgresStore` and `S3Store`** for multi-process/high-volume and
   large-sample storage; back the JWT denylist and per-tenant limiters with Redis.
6. **Native embedding/multimodal modeling** — tokenizer/encoder integration and
   image/text-specific detectors.
7. **mTLS CRL/OCSP** revocation checking.
8. **Real full-ensemble load test to 100K/sec** under concurrency; fix `/health`
   to check downstream dependencies; correct the API `version` string
   (`"0.1.0"` → `1.1.0`).
9. **Author formal ADRs** from the decision log in [§10](#10-decision-log--adr-summary).

---

*Maintained on branch `feat/detection-hardening` (v1.1.0). When behavior changes,
update this guide and the cross-linked docs together.*
