# dataset-poisoning-detector

Statistical anomaly detection for training data integrity — ensemble of Z-score, IQR, and Isolation Forest methods with streaming support at 12,400 samples/sec.

## Key Metrics

| Metric | Value |
|--------|-------|
| Detection AUC (CIFAR-10 label-flip) | 0.53–0.56 |
| Streaming throughput | 12,400 samples/sec |
| Latency p50 / p99 | 0.08ms / 0.31ms |
| Methods | Z-score, IQR fencing, Isolation Forest |
| Ensemble strategy | Majority vote (≥2/3 agree) |
| Threat mapping | MITRE ATLAS AML.T0020 |
| Deployment | Docker + Grafana monitoring |

## Architecture

```
┌─────────────────┐     ┌──────────────────────┐     ┌───────────────┐
│  Data Ingestion │────▶│  Detector Ensemble   │────▶│  Alert/Report │
│  Stream / Batch │     │  Z│IQR│IsoForest     │     │  Grafana dash │
└─────────────────┘     └──────────────────────┘     └───────────────┘
        │                         │                          │
        ▼                         ▼                          ▼
  12,400 samples/sec       Majority vote on           Flagged samples
  continuous intake        3 independent detectors    for human review
```

**Detection Methods:**

| Method | Approach | Strength | Weakness |
|--------|----------|----------|----------|
| Z-score | Statistical deviation from feature means | Fast, interpretable | Assumes normality |
| IQR fencing | Interquartile range outlier bounds | Distribution-free | Only catches univariate outliers |
| Isolation Forest | Random partition depth scoring | Non-linear anomalies | Opaque decision boundary |

**Pipeline:**
1. Ingest training data (streaming or batch mode)
2. Compute per-sample feature statistics
3. Run all three detectors independently
4. Ensemble via majority vote — flag if ≥2 methods agree
5. Route flagged samples for human review
6. Emit metrics to Grafana for continuous monitoring

## Honest Assessment

The 0.53–0.56 AUC on CIFAR-10 label-flip attacks is near random chance. Feature-space statistical methods cannot catch clean-label poisoning attacks where poisoned samples are indistinguishable from normal data in feature space.

This tool functions as a **screening layer**:
- Catches gross statistical outliers and data corruption
- Raises cost for attackers using naive poisoning strategies
- Does not replace spectral signatures (Tran et al. 2018) or activation clustering for targeted attacks

The engineering value is in the streaming infrastructure, not the detection algorithm.

## Quick Start

```bash
# Install from source (not published to PyPI)
pip install -e .

# Batch detection — detect() takes a list-of-lists feature matrix
python -c "
from poison_detector import detect
import random
X = [[random.gauss(0, 1) for _ in range(10)] for _ in range(1000)]
X[999] = [9.9] * 10  # inject obvious outlier
report = detect(X, method='ensemble')
print(f'Flagged {report.poisoned_count}/{report.total_samples}')
"

# Run tests
pytest tests/ -v
```

## Relevance to AI Security

Data poisoning (MITRE ATLAS AML.T0020) targets the training pipeline — the phase where models are most vulnerable and least monitored. Production ML systems ingest data continuously from sources with varying trust levels. Even imperfect statistical detection at streaming throughput provides a continuous monitoring signal that:

- Detects data corruption and pipeline failures immediately
- Raises the cost for naive poisoning attacks
- Produces audit trails for training data provenance
- Integrates into existing MLOps infrastructure (Docker, Grafana, alerting)

Defense-in-depth means every layer contributes signal. A screening layer that catches 10% of attacks at zero latency cost is still a net security improvement when combined with downstream defenses.

## License

MIT
