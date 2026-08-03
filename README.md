# Dataset Poisoning Detector

[![Live Dashboard](https://img.shields.io/badge/Live_Dashboard-View-blue)](https://poojakira.github.io/mlsec-dashboards/dataset-poisoning-detector/)

A Python toolkit for flagging suspicious samples in ML training data. It runs a few statistical and density-based anomaly detectors over your feature matrix and tells you which samples look unusual. You then decide what to do about them.

This is not a silver bullet. It's a screening tool — it helps you find candidates for human review.

## Honest Performance Note

On a CIFAR-10 label-flip benchmark (standardized pixels → PCA-50, per-class `StreamingDetector`, `contamination=0.05`), the measured ROC-AUC is **~0.53–0.56** across flip rates of 0.05/0.10/0.25. That's only modestly above chance.

At a 5% target false-positive rate, the actual false-positive rate is roughly 5% on clean samples. This is what you'd expect from a detector calibrated at that threshold — not a failure, but not magic either.

Any claim of "zero false positives" from this tool is a reporting error. See `scripts/eval_detector.py` to reproduce these numbers yourself.

## What It Does

Three detection methods, each catching different things:

- **Z-score** — flags samples with features far from the mean. Fast and interpretable, but assumes normality and misses in-distribution attacks.
- **IQR fencing** — uses robust statistics (not skewed by outliers). Better for heavy-tailed data, but the boundary is hard-coded and smart attackers can stay just inside.
- **Isolation Forest** — measures how easy a sample is to isolate with random splits. Catches cluster-based anomalies that statistical methods miss, but is opaque and degrades in high dimensions.

**Ensemble mode** (default) takes a majority vote across all three. Two of three must agree before a sample is flagged. This reduces false positives when methods agree, but can miss borderline true positives.

## Installation

```bash
pip install dataset-poisoning-detector
```

With real-time streaming support:

```bash
pip install "dataset-poisoning-detector[realtime]"
```

With Kafka:

```bash
pip install "dataset-poisoning-detector[realtime,kafka]"
```

From source:

```bash
git clone https://github.com/poojakira/dataset-poisoning-detector
cd dataset-poisoning-detector
pip install -e ".[dev,realtime]"
```

## Basic Usage

```python
from poison_detector import detect, export_json

X_train = [
    [0.2, 0.8, 0.1, 0.9],
    [0.3, 0.7, 0.2, 0.8],
    # ... normal training samples ...
    [9.9, 0.0, 9.8, 0.1],  # suspicious sample
]

# Run ensemble detection (majority vote across z-score, IQR, Isolation Forest)
report = detect(X_train, method="ensemble")

print(f"Flagged {report.poisoned_count} / {report.total_samples} samples")

for result in report.per_sample:
    if result.is_poisoned:
        print(f"  Sample {result.sample_idx}: score={result.anomaly_score:.3f}")

# Export for downstream analysis
json_output = export_json(report)
```

### Individual Methods

```python
from poison_detector import detect

report = detect(X, method="zscore")     # Z-score only
report = detect(X, method="iqr")        # IQR only
report = detect(X, method="isolation")  # Isolation Forest only
report = detect(X, method="ensemble")   # Majority vote (default)
```

### Feature Attribution

After flagging, see which features caused the anomaly:

```python
from poison_detector import feature_attribution

flagged_indices = [r.sample_idx for r in report.per_sample if r.is_poisoned]
attr = feature_attribution(X_train, flagged_indices)
# attr[sample_idx] = [(feature_idx, deviation_magnitude), ...] sorted by importance
```

## Streaming Mode

For production data pipelines where samples arrive one at a time:

```python
from poison_detector import StreamingDetector, ConceptDriftDetector, SampleFingerprinter

detector = StreamingDetector(window_size=10000, contamination=0.05)
drift = ConceptDriftDetector(sensitivity=0.01)
fingerprinter = SampleFingerprinter(similarity_threshold=0.95)

for sample in data_stream:
    result = detector.score_sample(sample)
    drift.update(sample)

    if result.is_poisoned or fingerprinter.is_duplicate(sample):
        quarantine(sample, result)
    else:
        fingerprinter.add_sample(sample)
        pass_to_training(sample)
```

### When NOT to Use Streaming Mode

- **Your data is static.** If you get training data as a single dump, use batch `detect()`. It's simpler and faster per-sample.
- **You have fewer than 1,000 samples.** The statistical methods need a meaningful baseline. Manual review is better at this scale.
- **You can't tolerate the latency.** Per-sample cost is ~80μs p50, ~140μs p95 on a single core. If that's too much, run detection asynchronously.
- **You trust your data source completely.** If data comes from an internal, audited, access-controlled source with no external contributors, the overhead may not be worth it.
- **You already have human-in-the-loop review on every sample.** Automated detection adds marginal value and may create alert fatigue.
- **You can't support the dependencies.** Streaming mode needs Redis or Kafka for queuing, plus FastAPI/uvicorn/prometheus-client.

## Local Benchmark Numbers

Single core (Intel Xeon Platinum 8375C), 10-dimensional feature vectors, window_size=10000:

| Metric | Value | Notes |
|--------|-------|-------|
| Throughput | 12,400 samples/sec | Single-threaded, ensemble scoring |
| Latency p50 | 0.08 ms | Steady-state after warm-up |
| Latency p95 | 0.14 ms | Includes periodic IsoForest refit |
| Latency p99 | 0.31 ms | Worst-case during refit |
| Memory (10k window) | 45 MB | Rolling window + IsoForest model |
| Memory (100k window) | 380 MB | Linear in window size |

These are microbenchmark numbers on specific hardware. Measure in your own environment before making capacity plans.

## What It Does NOT Catch

- **Clean-label attacks** — if the attacker poisons labels without changing features, all feature-space methods are blind. You need label-consistency checking for those.
- **Distributed poisoning** — small perturbations spread across many samples that individually look normal but collectively shift the decision boundary.
- **Feature-space mimicry** — adversarial samples crafted to look statistically normal on every feature while exploiting correlations the detectors don't model.
- **Adversarial drift** — intentional, slow distribution shift that looks like legitimate concept drift.
- **High-dimensional data (>100 features)** — Isolation Forest degrades because random splits become less discriminative. Apply PCA or feature selection first.

## Docker (Local Demo)

```bash
docker compose up -d

# Score a sample
curl -X POST http://localhost:8000/score \
  -H "Content-Type: application/json" \
  -d '{"features": [0.1, 0.2, 0.3, 0.4, 0.5]}'

# Health check
curl http://localhost:8000/health

# Grafana dashboards at http://localhost:3000
```

## Running Tests

```bash
pip install -e ".[dev,realtime]"
pytest tests/ -v
```

## License

MIT
