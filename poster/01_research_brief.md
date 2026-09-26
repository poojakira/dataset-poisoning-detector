# Research Brief — Poster 04

## Repository
`github.com/poojakira/dataset-poisoning-detector` (public, default branch `main`, primary language Python). MIT • Python 3.12 • HEAD b45d662 • verified 2026-09-26

## Academic Project Title
**Statistical Screening for Poisoned Machine-Learning Training Data**

### Subtitle
Detection and Quarantine of Suspicious Samples at the Data-Ingestion Boundary

## One-Sentence Contribution
An ingestion-boundary statistical screening ensemble with a reproducible efficacy benchmark that quantifies its own weakness: feature-space methods cannot reliably detect label-only corruption, and spectral analysis only partially recovers it. Honesty is the contribution.

## Problem Statement
Poisoned or corrupted samples enter training silently. A vendor feed drifts or a shared table gets bad rows, and precision quietly drops over retraining cycles — the pipeline never errors, so nobody checks the data. A screening layer at ingestion (MITRE ATLAS AML.T0020) can catch gross corruption — but not subtle attacks.

## Threat Model
Chain: POISONED SAMPLES -> INGESTION BOUNDARY -> TRAINING PIPELINE -> SCREENING BOUNDARY -> PASS or QUARANTINE.
Adversary capability: injects corrupted or mislabeled samples; Assumptions: clean baseline loaded; flagged rows excluded; Out of scope: subtle clean-label / image backdoors; adversarial robustness; Residual risk: low recall on label-flip; feature-space blind spots.

## Research / Engineering Question
> How effectively can statistical screening identify poisoned or corrupted training samples before they enter the training pipeline?

## Objective
Determine how well an unsupervised statistical ensemble screens ingestion data — and measure explicitly where it fails.

## Engineering Sub-Objectives
O1 — Z-score + IQR + IsolationForest
O2 — Spectral signatures (label-aware)
O3 — Majority-vote ensemble + quarantine
O4 — Streaming (Welford) + drift

## Methodology
1 Synth data (make_classification) -> 2 Inject (label-flip) -> 3 Score (4 methods) -> 4 Vote (ensemble) -> 5 Measure (P/R/F1) -> 6·7 Compare (spectral vs ens)

## Current Verified Evidence + Claim Ledger
- **VERIFIED_CURRENT** — Spectral label-flip F1 = 0.08 / 0.23 / 0.37 at 5/10/20% poison — results/spectral_benchmark.json (committed), read directly. Negative result shown prominently.
- **VERIFIED_CURRENT** — Spectral beats ensemble on 2/3 contamination rates — spectral_benchmark.json comparison block; both remain weak on label-flip.
- **VERIFIED_CURRENT** — 4 methods: z-score, IQR, IsolationForest, spectral; majority vote >=2/3 — README architecture + module table.
- **PARTIAL** — Streaming throughput — BENCHMARK_METADATA.md: environment-scoped microbenchmark; prior '~12,400/s' note demoted to historical (no SHA). Not shown as current.
- **UNSUPPORTED (disclaimed)** — High recall on label-flip / clean-label detection — README + benchmark explicitly document these as failure modes.

## Important Negative / Honest Results
See RESULTS panel: Spectral beats ensemble on 2/3 rates; both remain weak on label-flip. spectral_benchmark.json.

## Limitations
1. Low recall on label-flip (F1 0.08–0.37 measured).
2. Feature-space methods blind to clean-label attacks.
3. Streaming stats are per-feature; correlations lost.
4. Synthetic benchmark ≠ real pipeline data.
5. First-pass filter, not adversarial robustness.

## Future Work
• Evaluate on representative real pipeline data.
• Label-aware detectors beyond spectral.
• Multivariate streaming statistics.
• Clean-label attack detection research.
• Calibrated thresholds per dataset.

## Reproducibility
```
pytest tests/
python benchmark/cifar10_label_flip_benchmark.py
```
Evidence: results/spectral_benchmark.json, benchmarks/BENCHMARK_METADATA.md

## References
[1] Tran, Li, Madry (2018) Spectral Signatures, NeurIPS · [2] MITRE ATLAS AML.T0020 · [3] Steinhardt et al. (2017) · [4] scikit-learn IsolationForest · [5] Welford (1962) · [6] NIST AI RMF 1.0
