# RUNBOOK — dataset-poisoning-detector

Every command below was run end-to-end on Windows (PowerShell) with Python 3.12
against a fresh clone. Numbers quoted are measured on this machine, not
estimated.

## Prerequisites

- Python 3.10+ (verified on 3.12) OR Docker 20.10+
- Feature matrix as `list[list[float]]` (see below)

## Install (Local)

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Core library only:
pip install -e .
# To run the test suite (pytest, PyYAML, etc.) install the dev extras:
pip install -e ".[dev]"
```

## Pick the right method for the attack

This is the single most important decision. The methods are **not**
interchangeable:

| Attack you care about | Use | Why |
|-----------------------|-----|-----|
| **Label-flip** (features fine, label wrong) | `method="spectral"` (needs `labels`) | Verified: catches **20/20** injected label-flips on separable classes (2 false positives). Feature-space methods are blind to label-only corruption. |
| **Point-outlier / feature-space** poison | `method="ensemble"` / `"zscore"` / `"iqr"` / `"isolation"` | Flags samples that are statistical outliers in feature space. |
| Subtle / clean-label / image-domain backdoors | *(screening only)* | Feature-space ensemble is **near-random (~0.54 AUC)** here — treat as a first-pass filter, not a defense. |

## Run Detection (feature-space ensemble)

The detector is a library. `detect()` takes a feature matrix and returns a
`DetectionReport`.

```python
from poison_detector import detect
import random

random.seed(0)
X = [[random.gauss(0, 1) for _ in range(10)] for _ in range(1000)]
X[999] = [9.9] * 10  # inject one obvious outlier

report = detect(X, method="ensemble")  # "zscore" | "iqr" | "isolation" | "ensemble"
print(f"Flagged {report.poisoned_count}/{report.total_samples}")
for result in report.per_sample[:3]:
    print(result)
```

Verified output: `Flagged 20/1000`. Note that only one sample was a planted
outlier — the other ~19 are natural Gaussian-tail samples. **That is the point:**
on feature-space statistics alone the ensemble sits near ~0.54 AUC, so it
screens, it does not decide. Review flagged samples manually.

## Run Detection (spectral, label-aware — the method that actually works for label-flips)

```python
import numpy as np
from poison_detector import detect

rng = np.random.default_rng(0)
X = np.vstack([rng.normal(0, 1, (200, 8)), rng.normal(6, 1, (200, 8))])
labels = [0] * 200 + [1] * 200
for i in range(200, 220):  # flip 20 class-1 samples to label 0
    labels[i] = 0

report = detect([row.tolist() for row in X], method="spectral", labels=labels)
flagged = {r.sample_idx for r in report.per_sample if r.is_poisoned}
print(f"spectral flagged {len(flagged)} (caught {len(flagged & set(range(200, 220)))}/20 flips)")
```

Verified output: `spectral flagged 22 (caught 20/20 flips)`.

## Input validation (hardened)

`detect()` and the streaming scorer **fail loud** on malformed input instead of
silently returning "0 flagged":

- empty matrix, ragged rows, or zero-feature rows → `ValueError`
- `NaN`/`inf` values → `ValueError` (they would otherwise hide real anomalies)
- non-numeric / bool values → `TypeError`
- single sample with `ensemble`/`isolation`/`spectral` → `ValueError` (no
  distribution to be an outlier of; use `zscore`/`iqr` for tiny inputs)
- `spectral` with mismatched `labels` length → `ValueError`
- `StreamingDetector.score_sample`: empty vector, `NaN`/`inf`, wrong ndim, or a
  feature-count change mid-stream → `ValueError`

## Streaming benchmark

`benchmarks/throughput_tracker.py` imports the shipped `poison_detector.StreamingDetector` directly. It has no stub fallback.

```bash
python benchmarks/throughput_tracker.py --output benchmark-results.json
```

The streaming number is a **no-refit microbenchmark**. It excludes periodic IsolationForest refits, network I/O, serialization, Kafka, Redis, and API overhead. Treat the JSON artifact and its recorded environment as the evidence; do not quote a hardware-independent throughput guarantee.

## Interpret Results

| Field | Meaning |
|-------|---------|
| `poisoned_count` | Number of samples flagged as anomalous |
| `total_samples` | Total samples scored |
| `per_sample` | Per-sample `PoisonResult` (higher `anomaly_score` = more suspicious) |

## Test

```bash
pytest -q
```

Current GitHub Actions baseline (Python 3.12, 2026-09-21): **122 passed, 1 skipped** at **50.94% statement coverage**. Re-check the current CI run before copying these numbers into external material.

## Lint / Format / Security

```bash
ruff check src tests            # ruff 0.8.4 -> "All checks passed!"
ruff format --check src tests   # -> "32 files already formatted"
python -m pip install --upgrade pip
pip-audit                       # -> "No known vulnerabilities found"
```

(pip-audit skips the local editable `dataset-poisoning-detector` package
itself, which is expected — it isn't published to PyPI.)

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `ValueError: non-finite value (NaN/inf)` | Clean/impute NaN/inf before scanning |
| `ValueError: needs at least 2 samples` | Use `zscore`/`iqr`, or provide >= 2 samples |
| Low recall on label-flip with `ensemble` | Expected — use `method="spectral"` with labels |
| Many flags on clean-ish data with `ensemble` | Expected — ~0.54 AUC; screen, then review manually |
| `ModuleNotFoundError: poison_detector` | Run `pip install -e .` from repo root |
| Streaming throughput differs from a prior run | Expected across hardware/configuration. Check whether refits are enabled and compare only like-for-like benchmark artifacts. |
