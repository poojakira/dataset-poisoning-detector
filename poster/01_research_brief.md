# Research Brief - Poster 04

> Evidence status: Current main code snapshot `45740923aa16539909a7ae993104a80ecfe85e0b`; [Python 3.12 CI run 38502623976](https://github.com/poojakira/dataset-poisoning-detector/actions/runs/38502623976) (2026-10-14 UTC) passed **226 tests** (186 production-facing plus 40 legacy stub-only tests) at **91.75% statement coverage**, with a 90% CI floor. Historical October 4 poster snapshot (200 tests / 91.20%) remains separately archived.

## Repository

`github.com/poojakira/dataset-poisoning-detector` - public, default branch `main`.

## Academic Project Title

**Statistical Screening for Poisoned Machine-Learning Training Data**

### Subtitle

Detection and Quarantine of Suspicious Samples at the Data-Ingestion Boundary

## One-Sentence Contribution

An ingestion-boundary screening pipeline combining statistical outlier methods with a label-aware cross-class centroid detector that improves the committed synthetic label-flip benchmark from the old top-1 spectral baseline **0.08 / 0.23 / 0.3675 F1** to **0.55 / 0.595 / 0.6975 F1** at 5% / 10% / 20% contamination.

## Method

1. Validate incoming feature batches and streaming samples.
2. Apply z-score, IQR, Isolation Forest, and spectral/label-aware detectors.
3. Combine detector signals for screening and quarantine workflows.
4. Maintain streaming state and deduplication metadata.
5. Benchmark label-flip behavior with committed reproducible artifacts.

## Verified Current CI and Separately Pinned Benchmark Evidence

Current-main Python 3.12 CI run 38502623976 reports:

- **226 tests passed**, 0 skipped (186 production-facing and 40 legacy demonstration/stub tests).
- **91.75% statement coverage**; CI gate is 90%.
- Ruff check/format and Pyright pass on the final branch; GitHub currently reports 0 open Code Scanning, Dependabot, and secret-scanning alerts.
- Committed `results/spectral_benchmark.json` records cross-class centroid F1:
  - **0.55** at 5% contamination
  - **0.595** at 10%
  - **0.6975** at 20%
- The same artifact retains the weaker top-1 baseline **0.08 / 0.23 / 0.3675**.
- Cross-class spectral detection beats the feature-space ensemble on **3/3** tested contamination rates.

## Honest Boundaries

- The benchmark is synthetic and separable; it is not proof of production detection rate.
- Clean-label, subtle backdoor, and very-low-rate poisoning remain difficult.
- Throughput is hardware/environment dependent; no fixed product SLA is claimed.
- Stateful streaming behavior requires deliberate partitioning/external state for horizontal scaling.

## Reproducibility

```bash
git clone https://github.com/poojakira/dataset-poisoning-detector.git
cd dataset-poisoning-detector
git checkout 43313ee7dab746a27999e22796074e4a0d941322
python -m pip install -e ".[dev,realtime,kafka]"
pytest tests/ -q --cov=poison_detector --cov-report=term
python benchmark/cifar10_label_flip_benchmark.py
```

Expected current CI evidence: **226 passed**, **91.75% coverage** (includes 40 legacy stub tests).
