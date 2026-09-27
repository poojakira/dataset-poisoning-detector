# Detection Efficacy — Honest, Reproducible Assessment

This document reports **only** numbers that are reproducible from committed
benchmark scripts in this repository. Where a capability is weak or unmeasured,
that is stated plainly. No AUC or F1 value appears here unless a committed
script produces it.

> **How every number here is backed.** Run `python benchmark/cifar10_label_flip_benchmark.py`.
> It writes `results/spectral_benchmark.json` (committed). The tables below are
> transcribed from that artifact. If a number is not in that artifact or another
> committed result file, it is not claimed as measured.

---

## Summary — what this tool actually does

| Method | Implemented? | What it targets | Measured result | Verdict |
|--------|:---:|-----------------|-----------------|---------|
| Feature-space (z-score / IQR) | ✅ `statistical.py` | Feature-space outliers | See ensemble F1 below | Weak on label-flip (features unchanged) |
| Isolation Forest | ✅ `isolation.py` | Multivariate outliers | Part of ensemble | Weak on label-flip |
| Ensemble (z-score + IQR + IsolationForest) | ✅ `detector.py` | Mixed | F1 0.08 / 0.14 / 0.23 @ 5/10/20% | Weak on label-flip |
| Spectral signature (top-1) | ✅ `spectral.py` | Label-flip baseline | F1 0.08 / 0.23 / 0.37 @ 5/10/20% | Baseline; kept for comparison |
| Cross-class centroid | ✅ `spectral.py` | Label-flip (label-aware) | F1 0.55 / 0.60 / 0.70 @ 5/10/20% | Best implemented method |
| Streaming ensemble | ✅ `stream.py` | Real-time screening | Throughput only (see caveat) | Screening, not a detector of subtle attacks |

**Bottom line (honest):** On the standard label-flip benchmark (Tran et al. 2018
setup, synthetic separable data), the label-aware **cross-class centroid** method
reaches **F1 ≈ 0.70 at a 20% poison rate** and **0.55 at 5%**, a large improvement
over the top-1 spectral baseline (0.08 / 0.23 / 0.37) and the feature-space
ensemble (0.08 / 0.14 / 0.23). It still misses roughly 30–45% of flips, so this
remains a **screening aid** used as one layer of defense-in-depth, not a sole
high-recall control.

---

## Measured baseline — label-flip detection

Source: `results/spectral_benchmark.json`, produced by
`benchmark/cifar10_label_flip_benchmark.py`.

**Dataset:** `sklearn.make_classification` (2000 samples, 100 features,
`n_informative=20`, `class_sep=2.0`, `random_state=2018`) — a synthetic stand-in
for a trained model's penultimate-layer embeddings with well-separated classes.
**This is not real CIFAR-10 image data** (see limitation below).
**Attack:** random label flip, class 0 → class 1.
**Metric:** precision / recall / F1 vs. ground-truth flipped indices.

| Poison rate | Cross-class F1 | Top-1 baseline F1 | Ensemble F1 | Winner |
|:---:|:---:|:---:|:---:|:---:|
| 5%  | 0.55 | 0.08 | 0.08 | cross-class |
| 10% | 0.60 | 0.23 | 0.14 | cross-class |
| 20% | 0.70 | 0.37 | 0.23 | cross-class |

Averages across the three rates: **cross-class F1 ≈ 0.61, top-1 baseline ≈ 0.23,
ensemble F1 ≈ 0.15.** The label-aware cross-class centroid method wins at every
tested rate.

**Interpretation:** Label-flip attacks do not change a sample's features, so
feature-space methods (z-score, IQR, Isolation Forest) are fundamentally limited
against them. The cross-class centroid method compares each sample's distance to
its assigned-class centroid versus the nearest other-class centroid, which
directly captures the flip signature — a large gain over within-class top-1
spectral scoring. Absolute recall is still imperfect (it misses ~30–45% of
flips), so this remains a screening aid, not a complete control.

---

## Measured baseline — real CIFAR-10 (raw pixels)

Source: `benchmarks/BENCHMARK_METADATA.md`.

- **Dataset:** CIFAR-10 training set, 10% random label flip.
- **Features:** raw flattened pixels (3072 dims).
- **Method:** feature-space ensemble.
- **Result:** AUC ≈ **0.53–0.56** (near random).

Feature-space methods on raw pixels cannot detect label-only corruption. This is
expected and is documented as a known limitation, not a capability.

---

## Streaming throughput (not a detection-quality claim)

Source: `benchmarks/BENCHMARK_METADATA.md` + `benchmarks/throughput_tracker.py`.

- The z-score / IQR streaming path scores roughly **~12,000 samples/sec** (20-dim
  features, Isolation Forest refit excluded), on the reference machine documented
  in `BENCHMARK_METADATA.md`.
- **Caveat:** with the default periodic Isolation Forest refit enabled, sustained
  throughput is far lower because the refit dominates. `throughput_tracker.py`
  imports the shipped `StreamingDetector` directly and does **not** fall back to
  a test stub. Throughput is a performance figure, **not** a detection-quality figure.

---

## What this tool does NOT do

1. **Activation clustering** — *not implemented.* (An earlier version of this doc
   listed activation-clustering AUCs. There is no activation-clustering module in
   `src/poison_detector/`; those numbers were removed as unbacked.)
2. **High-recall label-flip detection** — recall is low, especially < 10% poison.
3. **Clean-label attacks** — statistically indistinguishable from clean data
   without model training.
4. **Low-rate attacks (< ~5%)** — signal-to-noise too low for these statistical
   methods.
5. **Image-domain backdoors on raw pixels** — near-random (AUC ~0.54).
6. **Adaptive attacks** — an attacker aware of these methods can evade them.

---

## Recommended use (defense-in-depth)

This tool is a **screening layer**, best combined with data provenance controls,
batch audits on trusted representations, and post-training model behavior
monitoring. Do not rely on it as a sole poisoning control. For label-flip
screening, spectral analysis on **model embeddings** (not raw pixels) and higher
assumed poison budgets (≥ 10%) give the best of the currently-implemented results.

---

## How to reproduce every number in this document

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .

# Label-flip benchmark (writes results/spectral_benchmark.json):
python benchmark/cifar10_label_flip_benchmark.py

# Streaming throughput (writes/report to stdout):
python benchmarks/throughput_tracker.py
```

The label-flip F1 table above is a direct transcription of
`results/spectral_benchmark.json`. If your run differs, the artifact — not this
prose — is the source of truth.

---

## References

- Tran, B., Li, J., Madry, A. (2018). "Spectral Signatures in Backdoor Attacks." NeurIPS.
- Chen, B., et al. (2019). "Detecting Backdoor Attacks on Deep Neural Networks by Activation Clustering." *(method referenced for context; not implemented here)*
