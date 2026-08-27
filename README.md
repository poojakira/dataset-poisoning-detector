# Dataset Poisoning Detector

Statistical screening for training data pipelines. Runs an ensemble of Z-score, IQR, and Isolation Forest detectors on streaming data at ~12,400 samples/sec and flags suspicious samples before they enter your training set.

---

## What This Does

I built this because we kept getting bitten by slow data corruption. A vendor feed drifts, or someone pushes bad features to a shared table, and three retraining cycles later your model's precision has quietly dropped 13 points. Nobody thinks to check the data because the pipeline didn't error out.

This tool sits at the ingestion boundary (MITRE ATLAS AML.T0020) and applies statistical tests to every incoming sample. It won't catch sophisticated targeted attacks, but it catches the dumb stuff fast: corrupted feature vectors, distribution shifts, gross outliers. It produces structured logs so you have an audit trail of what went into training and what got flagged.

It integrates with Kafka for streaming, exports Prometheus metrics, and ships with Docker and Grafana configs. You can deploy it in front of an existing pipeline without changing your training code.

---

## Scope and Limitations

This is a first-pass filter, not a complete defense. It works well for:

- Catching statistical outliers and obvious data corruption
- Making naive poisoning attacks more expensive
- Maintaining provenance records for training data

It does not replace careful data validation, domain-specific checks, or adversarial robustness techniques. The benchmarks in this repo show clearly where these methods fail, particularly against clean-label attacks that stay within normal feature distributions.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         Dataset Poisoning Detector                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌──────────────┐    ┌─────────────────────┐    ┌────────────────────────────┐  │
│  │ Data Sources │    │   Ingestion Layer    │    │     Detection Engine       │  │
│  │              │    │                      │    │                            │  │
│  │  Kafka topic ├───>│  StreamingDetector   ├───>│  Z-score (statistical.py)  │  │
│  │  REST API    │    │  (Welford online     │    │  IQR fencing (statistical) │  │
│  │  Batch file  │    │   statistics)        │    │  IsolationForest (sklearn) │  │
│  │              │    │                      │    │  Spectral signatures       │  │
│  └──────────────┘    └──────────┬───────────┘    └─────────────┬──────────────┘  │
│                                 │                              │                 │
│                                 │         ┌────────────────────┘                 │
│                                 │         │                                      │
│                                 v         v                                      │
│                      ┌─────────────────────────────┐                            │
│                      │     Ensemble Aggregator      │                            │
│                      │  (Majority vote: >=2/3 agree)│                            │
│                      └──────────────┬──────────────┘                            │
│                                     │                                            │
│                    ┌────────────────┼────────────────┐                           │
│                    v                v                v                           │
│          ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐                │
│          │  Quarantine  │  │   Alerting   │  │   Monitoring    │                │
│          │  (Redis/     │  │  (Webhook,   │  │  (Prometheus +  │                │
│          │   SQLite)    │  │   multi-ch)  │  │   Grafana)      │                │
│          └─────────────┘  └──────────────┘  └─────────────────┘                │
│                                                                                 │
│  Supporting modules:                                                            │
│    drift.py - Concept drift detection (ADWIN + Page-Hinkley)                    │
│    fingerprint.py - Sample deduplication (Bloom filter + cosine similarity)      │
│    attribution.py - Feature-level explanation for flagged samples                │
│    report.py - Structured output (JSON, CSV, human-readable)                    │
│    config.py - Pydantic-based runtime configuration                             │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**Component Responsibilities:**

| Module | Role |
|--------|------|
| `detector.py` | Orchestrates methods, runs ensemble, produces `DetectionReport` |
| `statistical.py` | Z-score and IQR detection (pure Python, no sklearn dependency) |
| `isolation.py` | Isolation Forest wrapper around scikit-learn |
| `spectral.py` | Spectral signature analysis for label-flip attacks |
| `stream.py` | Online scoring with Welford's algorithm + periodic IsolationForest refit |
| `drift.py` | Concept drift detection to distinguish poisoning from natural shift |
| `fingerprint.py` | Bloom filter deduplication to detect replay attacks |
| `storage.py` | Quarantine store (Redis for streaming, SQLite for batch) |
| `alerting.py` | Multi-channel alerting with deduplication |
| `metrics.py` | Prometheus counters and histograms |
| `api.py` | FastAPI service (REST + WebSocket endpoints) |
| `config.py` | Pydantic-settings based configuration management |
| `attribution.py` | Per-feature contribution scores for flagged samples |
| `report.py` | Output formatting (JSON, CSV, human-readable text) |
| `pipeline.py` | End-to-end pipeline orchestration |
| `dataset_url_scanner.py` | Scan HuggingFace dataset references for known-bad sources |

---

## End-to-End Workflow

How data moves through the system from ingestion to alert:

**Batch Mode:**
1. Load a feature matrix (list of lists or numpy array) into `detect(X, method="ensemble")`
2. Each detector runs independently: Z-score computes per-feature deviations, IQR computes interquartile bounds, IsolationForest fits and predicts anomaly scores
3. Ensemble aggregator counts votes per sample. A sample is flagged only if 2 or more methods agree
4. `feature_attribution()` identifies which features contributed most to each flagged sample
5. `DetectionReport` returned with per-sample scores, flags, and feature explanations
6. Export via `export_json()` or `export_csv()` for downstream integration

**Streaming Mode:**
1. Initialize `StreamingDetector` with `update_baseline(known_clean_samples)` to establish the statistical baseline
2. Samples arrive one at a time via `score_sample(features)` or in small batches via `score_batch()`
3. Welford's algorithm maintains running mean/variance in O(1) per sample
4. Z-score check runs immediately; IsolationForest check runs against the last fitted model
5. Only clean samples update the rolling window and Welford statistics (prevents baseline corruption)
6. Every `refit_interval` clean samples, IsolationForest refits on the rolling window
7. Flagged samples route to quarantine (Redis) and trigger alerts
8. Prometheus metrics emit continuously; Grafana dashboards show real-time poison rate, latency, drift status

**API Mode (Production):**
1. FastAPI service (`api.py`) exposes REST and WebSocket endpoints
2. Kafka consumer ingests samples from the training data pipeline topic
3. Each sample scored in-process; results written to Redis quarantine if flagged
4. Prometheus scrapes `/metrics` endpoint; Grafana visualizes detection state
5. Alert dispatcher notifies operators via configured channels

---

## Design Decisions and Trade-offs

**Why majority vote instead of weighted ensemble?**
Simplicity and interpretability. A weighted ensemble requires tuning weights per dataset, which means you need labeled poisoning examples to optimize against. Majority vote works without any labeled attack data and is easy to explain to stakeholders: "2 out of 3 independent methods flagged this sample."

**Why Welford's algorithm for streaming?**
It computes running mean and variance in O(1) per update with O(features) space. It is numerically stable even after millions of samples, unlike naive running-sum approaches that accumulate floating-point error.

**Why exclude flagged samples from the baseline?**
If poisoned samples update the rolling statistics, an attacker can slowly shift the baseline ("boiling frog" attack) until overtly poisoned samples appear normal. Excluding flagged samples makes the baseline more robust, at the cost of potentially excluding legitimate rare samples.

**Why periodic IsolationForest refit instead of continuous?**
Fitting IsolationForest is O(n * trees * depth). Fitting on every sample would destroy throughput. Periodic refitting (every 1000 clean samples by default) amortizes this cost while keeping the multivariate model reasonably current.

**Why include spectral signatures as a separate method?**
Feature-space statistical methods fundamentally cannot detect label-flip attacks (where the features are unchanged but the label is wrong). Spectral signatures (Tran et al. 2018) analyze within-class covariance structure and are the only method here that can catch these attacks. It requires labels, so it cannot run in unsupervised streaming mode.

**Why Docker + multi-service compose for a local demo?**
ML teams evaluate tools by running them, not reading docs. The compose stack gives evaluators a working system in one command (`docker compose up -d`) with monitoring already wired up. The security warnings in docker-compose.yml make clear this is not production-hardened.

**What was sacrificed for streaming throughput?**
Feature correlations. Online statistics are computed per-feature independently. Multivariate relationships are only captured during periodic IsolationForest refits, not on every sample.

---

## Tech Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Language | Python | >= 3.10 |
| Core ML | scikit-learn | >= 1.5 |
| Numerics | NumPy | >= 1.26 |
| API | FastAPI + Uvicorn | >= 0.111 |
| Streaming | Kafka (aiokafka) | >= 0.10 |
| Quarantine | Redis | >= 5.0 |
| Configuration | pydantic-settings | >= 2.3 |
| Metrics | prometheus-client | >= 0.20 |
| WebSocket | websockets | >= 12.0 |
| Testing | pytest + pytest-cov | >= 8.2 |
| Linting | Ruff | >= 0.4 |
| Container | Docker (multi-stage) | python:3.12-slim |
| Monitoring | Prometheus + Grafana | v2.51 / 10.4 |

### Installation

```bash
# Clone the repository
git clone https://github.com/poojakira/dataset-poisoning-detector.git
cd dataset-poisoning-detector

# Install core library (detection only, no server dependencies)
pip install -e .

# Install with real-time streaming support (FastAPI, Redis, Kafka, Prometheus)
pip install -e ".[realtime]"

# Install with Kafka consumer support
pip install -e ".[realtime,kafka]"

# Install development dependencies (testing, linting)
pip install -e ".[dev]"
```

### Quick Start

```python
from poison_detector import detect
import random

# Generate normal training data
X = [[random.gauss(0, 1) for _ in range(10)] for _ in range(1000)]

# Inject an obvious outlier (simulating a poisoned sample)
X[999] = [9.9] * 10

# Run ensemble detection
report = detect(X, method="ensemble")
print(f"Flagged {report.poisoned_count}/{report.total_samples} samples")

# Inspect flagged samples
for result in report.per_sample:
    if result.is_poisoned:
        print(f"  Sample {result.sample_idx}: score={result.anomaly_score:.3f}, "
              f"features={result.features_flagged}")
```

### Streaming Usage

```python
from poison_detector import StreamingDetector
import numpy as np

# Initialize detector
detector = StreamingDetector(window_size=10000, contamination=0.05)

# Establish baseline with known-clean data
clean_data = np.random.randn(5000, 20)
detector.update_baseline(clean_data)

# Score incoming samples
for sample in data_stream:
    result = detector.score_sample(sample)
    if result.is_poisoned:
        quarantine(sample)
        print(f"Poisoned! score={result.score:.3f}, "
              f"votes={result.method_votes}, "
              f"latency={result.latency_ms:.2f}ms")

# Check detector health
stats = detector.get_stats()
print(f"Processed: {stats.samples_seen}, Poison rate: {stats.poison_rate:.4f}")
```

### Spectral Detection (for label-flip attacks)

```python
from poison_detector import detect

# When you have labels and suspect label-flip poisoning
report = detect(X, method="spectral", labels=y)
print(f"Spectral detected {report.poisoned_count} mislabeled samples")
```

### Docker Deployment

```bash
# Full stack: API + Redis + Kafka + Prometheus + Grafana
docker compose up -d

# API only
docker build -t poison-detector:latest .
docker run -p 8000:8000 poison-detector:latest

# Check health
curl http://localhost:8000/health

# Score a sample via REST
curl -X POST http://localhost:8000/score \
  -H "Content-Type: application/json" \
  -d '{"features": [1.2, 0.5, -0.3, 2.1, 0.8]}'
```

### Running Tests

```bash
pytest tests/ -v
pytest tests/ -v --cov=poison_detector --cov-report=term-missing
```

---

## Threat Model and Mitigation Strategies

This tool addresses **MITRE ATLAS AML.T0020 (Poison Training Data)**. Here is what it can and cannot handle:

| Attack Type | Detection Capability | Why |
|-------------|---------------------|-----|
| Feature outlier injection | Good | Z-score and IQR catch extreme deviations directly |
| Statistical distribution shift | Moderate | IsolationForest detects density anomalies; drift module flags distribution changes |
| Label-flip poisoning | Poor (ensemble) / Good (spectral) | Feature-space methods cannot see label corruption; spectral signatures can |
| Clean-label poisoning | Poor | Poisoned samples are statistically indistinguishable from normal data by design |
| Slow-drip baseline corruption | Moderate | Excluding flagged samples from baseline resists this, but a patient attacker sending borderline samples can still shift it |
| Replay/duplication attacks | Good | Bloom filter fingerprinting detects exact and near-duplicate samples |
| Backdoor trigger injection | Poor | Small-magnitude triggers (few-pixel patches) fall within normal statistical bounds |

**Mitigations built into the system:**

- **Baseline isolation:** Only clean (non-flagged) samples update rolling statistics, preventing poisoned data from corrupting the detector's own reference distribution
- **Periodic model refit:** IsolationForest retrains on the rolling window, adapting to legitimate distribution evolution
- **Concept drift detection:** ADWIN + Page-Hinkley algorithms distinguish natural distribution shifts from adversarial manipulation
- **Sample fingerprinting:** Bloom filter catches exact duplicates; cosine similarity catches near-duplicates (replay attacks)
- **Quarantine-first architecture:** Flagged samples are quarantined and never enter the training set without human review
- **Non-root container:** Docker image runs as unprivileged user with memory limits to prevent resource exhaustion attacks

**What this tool does NOT protect against:**

- Adaptive adversaries who know the exact detection configuration
- Clean-label attacks (Shafahi et al. 2018) where poisoned samples are indistinguishable in feature space
- Model-level backdoors that require activation analysis to detect
- Supply-chain attacks on the detector's own dependencies

---

## Evaluation Methods, Results, and Limitations

### Benchmark: CIFAR-10 Label-Flip Attack

The repository includes `benchmark/cifar10_label_flip_benchmark.py` which evaluates detection performance on a standard attack scenario: random label flips applied to a fraction of CIFAR-10 training samples.

| Metric | Value |
|--------|-------|
| Detection AUC (feature-space ensemble) | 0.53 - 0.56 |
| Detection AUC (spectral signatures) | Higher (label-aware) |
| Streaming throughput | 12,400 samples/sec |
| Latency p50 | 0.08 ms |
| Latency p99 | 0.31 ms |
| Ensemble strategy | Majority vote (>= 2/3 agree) |

> See `benchmarks/BENCHMARK_METADATA.md` for full methodology. Throughput measured locally on M2/16GB with 20-dimensional features; varies with hardware and configuration.

### Honest Assessment

**The 0.53-0.56 AUC on CIFAR-10 label-flip is near random chance.** This is not a failure of implementation; it is a fundamental limitation of the approach. Feature-space statistical methods cannot detect attacks where the features are unchanged and only labels are corrupted.

Where this tool provides real value:
- Detecting data corruption (broken pipelines, encoding errors, sensor malfunctions)
- Catching naive outlier-injection attacks where poisoned samples have extreme feature values
- Providing continuous monitoring signal at negligible latency cost
- Catching duplicate/replay samples via fingerprinting

Where it does not help:
- Clean-label poisoning (features look normal, only labels are wrong)
- Targeted backdoor attacks (trigger patterns are too small to register as outliers)
- Any attack specifically designed to evade statistical detection

The engineering value of this project is primarily in the streaming infrastructure, monitoring stack, and the framework for composing detection methods. The statistical detection algorithms themselves are a starting point, not a complete solution.

### Limitations

1. **Unsupervised methods cannot distinguish rare-but-legitimate from rare-and-malicious.** A valid outlier and a poisoned sample look identical to these detectors.
2. **Per-feature independence assumption.** Online Z-score and IQR check each feature independently. Correlated poisoning across features (that stays within per-feature bounds) is invisible to these methods.
3. **IsolationForest periodic refit lag.** Between refits, the multivariate model may be stale. The `refit_interval` parameter trades freshness for throughput.
4. **No temporal analysis.** The system scores each sample independently. Patterns that emerge only across sequences of samples (e.g., gradual drift below threshold) require the separate drift module.
5. **Single-threaded scoring.** `score_sample()` is not thread-safe. Production deployments must serialize access or run multiple worker processes.

---

## Production Readiness Assessment

| Criterion | Status | Notes |
|-----------|--------|-------|
| Containerized deployment | Yes | Multi-stage Docker, non-root user, health checks |
| Configuration management | Yes | Pydantic-settings with env var override |
| Monitoring and alerting | Yes | Prometheus metrics, Grafana dashboards, multi-channel alerts |
| Streaming support | Yes | Kafka consumer, 12,400 samples/sec throughput |
| Quarantine storage | Yes | Redis (streaming) + SQLite (batch) |
| Test coverage | Yes | 11 test modules covering all components |
| CI/CD | Yes | GitHub Actions (`.github/` directory) |
| Runbook | Yes | `RUNBOOK.md` with operational procedures |
| Changelog | Yes | `CHANGELOG.md` with version history |
| Security hardening | Partial | Non-root container, memory limits, but no TLS/auth in demo stack |
| Horizontal scaling | Not yet | Single-process design; would need sharding for multi-node |
| Data persistence | Partial | Redis with AOF; no long-term audit storage beyond quarantine |

**What you would need to add for a real production deployment:**

- TLS termination and API authentication
- Secret management (not env vars with defaults)
- Multi-node Kafka consumer group for horizontal scaling
- Long-term audit log storage (S3, database)
- Rate limiting on the API
- Network segmentation between services

---

## Roadmap / Future Improvements

Based on the repository structure and identified limitations:

1. **Weighted ensemble with confidence calibration.** Replace majority vote with method-specific confidence weighting that adapts per data distribution.

2. **Activation clustering integration.** Add a detection method that uses model activations (requires a trained model) to catch clean-label attacks.

3. **Temporal sequence analysis.** Detect slow-drip poisoning patterns across sample sequences, not just individual sample scoring.

4. **Horizontal scaling.** Kafka consumer group support with partitioned state for multi-node deployments.

5. **Feedback loop.** Allow analysts to confirm/reject quarantined samples and feed that signal back to improve detection thresholds.

6. **Pre-trained embeddings.** Score samples in embedding space (e.g., CLIP for images) rather than raw feature space for better semantic anomaly detection.

7. **Supply-chain scanning.** Extend `dataset_url_scanner.py` to verify dataset provenance, checksums, and known-compromised source lists.

8. **GPU-accelerated spectral analysis.** Enable spectral signature detection at streaming speeds for labeled data streams.

---

## References

- **MITRE ATLAS AML.T0020** - Poison Training Data: https://atlas.mitre.org/techniques/AML.T0020
- **Tran, B., Li, J., Madry, A. (2018)** - "Spectral Signatures in Backdoor Attacks." NeurIPS 2018. Foundational work on detecting poisoning via top singular vectors of per-class representations.
- **Shafahi, A., et al. (2018)** - "Poison Frogs! Targeted Clean-Label Poisoning Attacks on Neural Networks." NeurIPS 2018. Demonstrates attacks that are undetectable by feature-space statistical methods.
- **Liu, F.T., Ting, K.M., Zhou, Z.H. (2008)** - "Isolation Forest." ICDM 2008. The anomaly detection algorithm used in the ensemble.
- **Welford, B.P. (1962)** - "Note on a Method for Calculating Corrected Sums of Squares and Products." Technometrics. The online algorithm used for streaming statistics.
- **Goldblum, M., et al. (2022)** - "Dataset Security for Machine Learning: Data Poisoning, Backdoor Attacks, and Defenses." IEEE TPAMI. Comprehensive survey of the threat landscape.
- **MITRE ATLAS Framework** - https://atlas.mitre.org/ - Adversarial Threat Landscape for AI Systems.

---

## License and Author

MIT License. See [LICENSE](LICENSE) for full text.

Author: [poojakira](https://github.com/poojakira)

Project page: https://poojakira.github.io/dataset-poisoning-detector/

---

## Engineering Lessons

Building this taught a few things worth sharing:

**Honest benchmarking matters more than impressive numbers.** Reporting 0.53 AUC is uncomfortable, but it tells users exactly what to expect. A tool that claims 99% detection on synthetic data and fails silently on real attacks is worse than useless.

**The infrastructure is often more valuable than the algorithm.** The streaming pipeline, monitoring, quarantine workflow, and deployment stack are reusable regardless of which detection method you plug in. Algorithms improve; operational patterns persist.

**Defense-in-depth means every layer contributes signal, even imperfect ones.** A screening layer that catches 10% of attacks at zero latency cost is still a net security improvement when combined with downstream defenses. Perfect is the enemy of deployed.
