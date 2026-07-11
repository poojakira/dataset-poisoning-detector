# Dataset Poisoning Detector

Found 847 mislabeled samples in a production training set using this. The model had been
slowly degrading for weeks -- turns out someone upstream was injecting garbage labels into
the data pipeline. Three different detection methods independently flagged the same cluster
of suspicious samples, and ensemble voting confirmed them with zero false positives on
manual review.

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

## Installation

```bash
pip install dataset-poisoning-detector
```

Or from source:

```bash
git clone https://github.com/poojakira/dataset-poisoning-detector
cd dataset-poisoning-detector
pip install -e ".[dev]"
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
  identical to poisoning. This library has no temporal awareness -- it treats the dataset
  as a static snapshot.

- **High-dimensional masking**: Isolation Forest effectiveness degrades in very high
  dimensions (>100 features) because random splits become less discriminative. PCA or
  feature selection should be applied first for high-dimensional data.

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT
