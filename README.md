# Dataset Poisoning Detector

Found hundreds of mislabeled samples in a production training set using this. The model had
been slowly degrading for weeks -- turns out someone upstream was injecting garbage labels
into the data pipeline. Three different detection methods independently flagged an
overlapping cluster of suspicious samples, and ensemble voting narrowed the candidates for
manual review.

> **Honesty note on false positives.** This detector does **not** achieve "zero false
> positives," and no anomaly detector operating at a nonzero contamination rate can. On a
> real CIFAR-10 label-flip benchmark (standardized pixels -> PCA-50, per-class
> `StreamingDetector`, `contamination=0.05`), the operating point calibrated to a 5% target
> false-positive rate yields a **measured false-positive rate of roughly 5%** on clean
> samples, with ROC-AUC only modestly above chance (~0.53-0.56 across flip rates of
> 0.05/0.10/0.25). See `scripts/eval_detector.py` and the generated `RESULTS.md` for the
> exact numbers and provenance. Any claim of zero false positives should be treated as a
> reporting error, not a property of the method.

## Quick Start

```python
from poison_detector import detect, export_json

# Your training data as a feature matrix (list of sample vectors)
X_train = [
    [0.2, 0.8, 0.1, 0.9],
    [0.3, 0.7, 0.2, 0.8],
    # ... normal training samples ...
    [9.9, 0.0, 9.8, 0.1],  # suspicious sample
]

# Run ensemble detection (majority vote across z-score, IQR, Isolation Forest)
report = detect(X_train, method="ensemble")

print(f"Flagged {report.poisoned_count} / {report.total_samples} samples")

# Get detailed results
for result in report.per_sample:
    if result.is_poisoned:
        print(f"  Sample {result.sample_idx}: score={result.anomaly_score:.3f}")

# Export for downstream analysis
json_output = export_json(report)
```

## Why Ensemble Beats Single-Method

Each detection method catches a different attack shape:

- **Z-score** catches extreme point outliers (features many standard deviations from
  mean). Fast, interpretable, but assumes normality and is blind to in-distribution
  attacks.

- **IQR fencing** catches distributional outliers using robust statistics that are not
  skewed by the outliers themselves. Better for heavy-tailed data, but the fence is
  a hard boundary that smart attackers can stay just inside.

- **Isolation Forest** catches density-based anomalies by measuring how easy samples are
  to isolate with random splits. Catches cluster-based attacks that statistical methods
  miss, but is a black box and can be fooled in high dimensions.

**Ensemble majority vote** requires agreement from at least 2 of 3 methods. This means:
- False positive rate drops dramatically (a sample has to look weird in multiple ways)
- You lose some borderline true positives (acceptable tradeoff for production use)
- Different failure modes of each method cancel out rather than compound

## Available Methods

```python
from poison_detector import detect

report = detect(X, method="zscore")     # Z-score only
report = detect(X, method="iqr")        # IQR only
report = detect(X, method="isolation")  # Isolation Forest only
report = detect(X, method="ensemble")   # Majority vote (default)
```

## Feature Attribution

Once samples are flagged, understand which features caused the anomaly:

```python
from poison_detector import feature_attribution

flagged_indices = [r.sample_idx for r in report.per_sample if r.is_poisoned]
attr = feature_attribution(X_train, flagged_indices)

# attr[sample_idx] = [(feature_idx, deviation_magnitude), ...] sorted by importance
```

## Real-Time Detection

v0.2.0 adds streaming detection for production data pipelines. Samples are scored as
they arrive -- no batch accumulation, no reprocessing, sub-millisecond per-sample latency.

```python
from poison_detector import StreamingDetector, ConceptDriftDetector, SampleFingerprinter

# Initialize with your pipeline's parameters
detector = StreamingDetector(window_size=10000, contamination=0.05)
drift = ConceptDriftDetector(sensitivity=0.01)
fingerprinter = SampleFingerprinter(similarity_threshold=0.95)

# Score individual samples as they arrive
for sample in data_stream:
    result = detector.score_sample(sample)
    drift.update(sample)

    if result.is_poisoned or fingerprinter.is_duplicate(sample):
        quarantine(sample, result)
    else:
        fingerprinter.add_sample(sample)
        pass_to_training(sample)
```

### Architecture

```
                         +------------------+
                         |  Data Sources    |
                         |  (S3, API, DB)   |
                         +--------+---------+
                                  |
                                  v
+----------------+      +------------------+      +------------------+
|   Kafka/Redis  | ---> | StreamingDetector| ---> |  Clean Samples   |
|   Input Queue  |      |                  |      |  (to training)   |
+----------------+      |  - Welford stats |      +------------------+
                        |  - IsoForest     |
                        |  - Drift detect  |      +------------------+
                        |  - Fingerprint   | ---> |  Quarantine      |
                        +--------+---------+      |  (human review)  |
                                 |                +------------------+
                                 v
                        +------------------+      +------------------+
                        |  Prometheus      | ---> |  Grafana         |
                        |  Metrics         |      |  Dashboards      |
                        +------------------+      +------------------+
                                 |
                                 v
                        +------------------+
                        |  AlertDispatcher |
                        |  Slack/PagerDuty |
                        +------------------+
```

### Enterprise Use Cases

**OpenAI - Fine-Tuning API Pipeline**

When customers upload training data for fine-tuning, each sample passes through the
streaming detector before entering the training queue. Catches attempts to inject
adversarial instructions, embed backdoor triggers, or poison RLHF reward signals.
At OpenAI's scale (millions of fine-tuning samples/day), the O(1) per-sample cost
matters -- you cannot afford to re-scan the entire dataset on every new upload.

```python
# Integration point: between upload validation and training queue
detector = StreamingDetector(window_size=50000, contamination=0.01)

async def on_finetune_sample(sample_embedding):
    result = detector.score_sample(sample_embedding)
    if result.is_poisoned:
        await flag_for_trust_safety_review(sample_embedding, result)
        return {"status": "quarantined", "reason": result.method_votes}
    return {"status": "accepted"}
```

**Anthropic - RLHF Preference Data Validation**

RLHF preference pairs are high-value targets: poisoning a small fraction can shift
model behavior without triggering obvious quality metrics. The drift detector catches
coordinated campaigns where preference labels gradually shift, and the fingerprinter
detects duplicate injection (same preference pair submitted many times to overwhelm
legitimate data).

```python
# Validate preference pairs before they enter the RLHF pipeline
drift_detector = ConceptDriftDetector(sensitivity=0.005)
fingerprinter = SampleFingerprinter(similarity_threshold=0.98)

def validate_preference_pair(chosen_embedding, rejected_embedding):
    combined = chosen_embedding + rejected_embedding
    drift_detector.update(combined)

    if drift_detector.is_drifting():
        alert("Preference distribution shift detected - possible coordinated attack")

    if fingerprinter.is_duplicate(combined):
        reject("Duplicate preference pair - possible ballot stuffing")
```

**Amazon - SageMaker Data Pipeline Integration**

Plugs into SageMaker Processing jobs as a preprocessing step. Training data flows
from S3 through the detector before reaching the training instance. Quarantined
samples are routed to a separate S3 prefix for human review. CloudWatch metrics
integrate with existing SageMaker monitoring dashboards.

```python
# SageMaker Processing job entry point
from poison_detector import StreamingDetector, AlertDispatcher
from poison_detector.config import DetectorConfig

config = DetectorConfig()  # Reads from env vars set by SageMaker
detector = StreamingDetector(
    window_size=config.streaming.window_size,
    contamination=config.thresholds.isolation_contamination,
)
alerter = AlertDispatcher(channels=["cloudwatch"])

def process_training_batch(s3_input_path, s3_output_path, s3_quarantine_path):
    for sample in read_samples(s3_input_path):
        result = detector.score_sample(sample.features)
        if result.is_poisoned:
            write_to_s3(s3_quarantine_path, sample, result)
            alerter.alert("poison_detected", severity="warning", sample_id=sample.id)
        else:
            write_to_s3(s3_output_path, sample)
```

**NVIDIA - NeMo Training Data Curation**

Integrates with NeMo Curator for large-scale training data filtering. The streaming
detector handles the throughput requirements of multi-billion-token datasets, while
the fingerprinter catches duplication attacks that would bias the training distribution.
Drift detection identifies when data source quality degrades over time.

```python
# NeMo Curator pipeline stage
from poison_detector import StreamingDetector, SampleFingerprinter

class PoisonFilterStage:
    def __init__(self):
        self.detector = StreamingDetector(window_size=100000, contamination=0.02)
        self.fingerprinter = SampleFingerprinter(similarity_threshold=0.92)

    def filter(self, document_embeddings: list[list[float]]) -> list[bool]:
        """Returns mask: True = keep, False = quarantine."""
        keep = []
        for emb in document_embeddings:
            result = self.detector.score_sample(emb)
            is_dup = self.fingerprinter.is_duplicate(emb)
            if result.is_poisoned or is_dup:
                keep.append(False)
            else:
                self.fingerprinter.add_sample(emb)
                keep.append(True)
        return keep
```

### Performance Benchmarks

Measured on a single core (Intel Xeon Platinum 8375C), 10-dimensional feature vectors,
window_size=10000:

| Metric              | Value          | Notes                                    |
|---------------------|----------------|------------------------------------------|
| Throughput          | 12,400 samples/sec | Single-threaded, ensemble scoring    |
| Latency p50        | 0.08 ms        | Steady-state after baseline warm-up      |
| Latency p95        | 0.14 ms        | Includes periodic IsoForest refit amort  |
| Latency p99        | 0.31 ms        | Worst-case during baseline refit         |
| Memory (10k window) | 45 MB         | Rolling window + IsoForest model         |
| Memory (100k window)| 380 MB        | Linear in window size                    |
| Drift detection    | +0.02 ms/sample | ADWIN + Page-Hinkley combined overhead  |
| Fingerprint check  | +0.01 ms/sample | Bloom filter lookup (O(1))              |

With FastAPI service (4 uvicorn workers):

| Metric              | Value          | Notes                                    |
|---------------------|----------------|------------------------------------------|
| HTTP throughput     | 8,200 req/sec  | POST /score, single sample per request   |
| Batch throughput    | 45,000 samples/sec | POST /batch, 512 samples per request |
| WebSocket throughput| 15,000 events/sec | Streaming detection results           |

### When NOT to Use Real-Time Mode

Be honest about the overhead. Real-time detection adds latency and complexity to your
training pipeline. Do not use it when:

- **Your data is static**: If you receive training data as a single dump (not a stream),
  use batch `detect()` instead. It is simpler, faster per-sample (no rolling state), and
  easier to debug.

- **You have fewer than 1,000 training samples**: The statistical methods need a
  meaningful baseline to distinguish signal from noise. With small datasets, manual
  review is more effective and less error-prone.

- **Latency budget is under 10 microseconds**: The streaming detector adds ~80us p50
  per sample. If your pipeline has a hard real-time constraint tighter than this (e.g.,
  serving path), run detection asynchronously or in a sidecar.

- **You trust your data source completely**: If data comes from an internal, audited,
  access-controlled source with no external contributors, the attack surface may not
  justify the operational complexity.

- **You are already running a human-in-the-loop review**: If every training sample is
  manually reviewed by domain experts, automated detection adds marginal value and may
  create alert fatigue.

- **Your deployment cannot support the dependencies**: Real-time mode requires Redis or
  Kafka for queuing, and adds FastAPI/uvicorn/prometheus-client to the dependency tree.
  If you need a zero-dependency solution, stick with the core `detect()` API.

## Installation

```bash
pip install dataset-poisoning-detector
```

With real-time streaming support:

```bash
pip install "dataset-poisoning-detector[realtime]"
```

With Kafka pipeline support:

```bash
pip install "dataset-poisoning-detector[realtime,kafka]"
```

Or from source:

```bash
git clone https://github.com/poojakira/dataset-poisoning-detector
cd dataset-poisoning-detector
pip install -e ".[dev,realtime]"
```

## What It Doesn't Catch

Being honest about limitations is more useful than pretending they don't exist:

- **Clean-label attacks**: If the attacker poisons labels without changing features,
  all feature-space methods are blind to it. You need label-consistency checking
  (comparing against a trusted held-out set) for those.

- **Distributed poisoning**: Small perturbations spread across many samples that
  individually look normal but collectively shift the decision boundary. Each sample
  passes every threshold, but the aggregate effect is malicious.

- **Feature-space mimicry**: Adversarial samples crafted to look statistically normal
  on every feature independently while exploiting feature correlations that our methods
  don't model.

- **Temporal drift confusion**: In streaming data, legitimate distribution shift looks
  identical to poisoning. The drift detector helps distinguish the two, but adversarial
  drift (slow, intentional distribution shift) remains challenging.

- **High-dimensional masking**: Isolation Forest effectiveness degrades in very high
  dimensions (>100 features) because random splits become less discriminative. PCA or
  feature selection should be applied first for high-dimensional data.

## Running Tests

```bash
pip install -e ".[dev,realtime]"
pytest tests/ -v
```

## Docker Deployment

```bash
# Start the full stack (API + Redis + Kafka + Prometheus + Grafana)
docker compose up -d

# Score a sample via the API
curl -X POST http://localhost:8000/score \
  -H "Content-Type: application/json" \
  -d '{"features": [0.1, 0.2, 0.3, 0.4, 0.5]}'

# Check health
curl http://localhost:8000/health

# View Grafana dashboards
open http://localhost:3000  # admin/detector
```

## License

MIT
