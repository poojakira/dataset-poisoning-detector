# RUNBOOK — dataset-poisoning-detector

## Prerequisites

- Python 3.9+ (local) OR Docker 20.10+
- Dataset in CSV format with labeled columns

## Install (Local)

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
```

## Run Detection

The detector is a library. `detect()` takes a feature matrix as a list of lists
and returns a `DetectionReport`.

```python
from poison_detector import detect
import random

# Build a feature matrix (list[list[float]]), inject one outlier
X = [[random.gauss(0, 1) for _ in range(10)] for _ in range(1000)]
X[999] = [9.9] * 10

report = detect(X, method="ensemble")   # "zscore" | "iqr" | "isolation_forest" | "ensemble"
print(f"Flagged {report.poisoned_count}/{report.total_samples}")
for score in report.scores[:5]:
    print(score)
```

## Interpret Results

| Field | Meaning |
|-------|---------|
| `poisoned_count` | Number of samples flagged as anomalous |
| `total_samples` | Total samples scored |
| `scores` | Per-sample anomaly scores (higher = more suspicious) |

- Benchmark ROC-AUC is 0.53–0.56 — near random. This is a screening layer, not a defense.
- Review flagged samples manually before removing from a training set.
- Try `method="isolation_forest"` for high-dimensional data.

## Test

```bash
pytest tests/ -v
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `ValueError: truth value of an array is ambiguous` | Pass a `list[list[float]]`, not a numpy array |
| Low AUC on known-poisoned data | Expected — feature-space stats miss clean-label attacks |
| `ModuleNotFoundError: poison_detector` | Run `pip install -e .` from repo root |
