# Research Brief - Poster 04

> Evidence status: Refreshed against final main code snapshot `43313ee7dab746a27999e22796074e4a0d941322`. GitHub Actions Python 3.12 verification on 2026-10-04 reproduced 200 passing tests at 91.20% statement coverage; CI now enforces a 90% floor.

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

## Verified Evidence at Cited Snapshot

Cited snapshot Python 3.12 verification reports:

- **200 tests passed**, 0 skipped.
- **91.20% statement coverage**; CI gate is 90%.
Cited CI lint/format and type-check jobs passed; current open Code Scanning, Dependabot and secret-scanning alert totals were not queried by this audit.
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

Expected current evidence: **200 passed**, **91.20% coverage**.


## Claim audit and rendered-source boundary, October 13, 2026 UTC

The reviewed printed claims, source and test commit anchors, CI dates and benchmark limitations are in `verified_claims.json`. The PDF is generated from that manifest and the PNG is rasterized from the same page by `render_poster.py`. Source inventory, dated CI and separate reported experiments must not be combined into one result. Earlier artifact versions remain in Git history; these corrections do not assert production readiness.

Offline poster rendering: `python -m pip install reportlab==4.4.9 PyMuPDF==1.26.6`, then `python poster/render_poster.py`. The font is bundled with the pinned ReportLab package; no browser or network fetch is used during rendering.
