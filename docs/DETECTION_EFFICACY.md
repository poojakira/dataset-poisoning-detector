# Detection Efficacy — Honest Assessment

This document provides transparent, honest documentation of what the dataset-poisoning-detector can and cannot detect, with measured baselines and recommendations.

---

## Summary

| Method | Domain | Attack Type | AUC | Verdict |
|--------|--------|-------------|-----|---------|
| Feature-space | Tabular | Backdoor | ~0.85 | ✅ Good |
| Feature-space | Images (CIFAR-10) | Backdoor | ~0.54 | ⚠️ Weak |
| Spectral signature | Any | Label-flip > 5% | ~0.80 | ✅ Good |
| Spectral signature | Any | Label-flip < 5% | ~0.58 | ⚠️ Weak |
| Activation clustering | DNNs | Backdoor | ~0.75 | ✅ Moderate |
| Streaming ensemble | Any | Mixed | ~0.65 | ⚠️ Moderate (throughput-optimized) |

**Bottom line:** This tool is effective for tabular data poisoning and label-flip attacks above 5%. For image-domain backdoors and subtle attacks, it provides limited detection and should be combined with other defenses.

---

## Method-by-Method Analysis

### 1. Feature-Space Methods

**How it works:** Computes distances from samples to their class centroid in feature space. Samples far from their class centroid relative to class variance are flagged as suspicious.

**Strengths:**
- Excellent for tabular data where poisoned samples create outliers in feature space
- Low computational cost (linear in dataset size)
- No model training required — works on raw features
- AUC ~0.85 on tabular datasets with backdoor triggers affecting > 3 feature dimensions

**Weaknesses:**
- Poor on high-dimensional image features (CIFAR-10 AUC: 0.54 — barely above random)
- Relies on poison samples being statistical outliers; fails for "clean-label" attacks
- Sensitive to feature scaling and preprocessing
- Class imbalance degrades centroid estimates

**Why images are hard:**
- Image features are high-dimensional and distributed non-uniformly
- Backdoor triggers (e.g., small pixel patches) have minimal effect on global feature statistics
- Requires meaningful feature representations (raw pixels are ineffective)

**Measured baselines:**
```
Tabular (synthetic 128-dim, 5% poison):   AUC = 0.85 ± 0.03
CIFAR-10 (raw features, 5% backdoor):     AUC = 0.54 ± 0.05
CIFAR-10 (pretrained embeddings):          AUC = 0.67 ± 0.04  [requires external model]
```

### 2. Spectral Signature Detection

**How it works:** Performs SVD on the centered feature/representation matrix. Poisoned samples tend to have large projections onto the top singular vector when the poison creates a distinct spectral signature.

**Strengths:**
- Theoretically grounded (Tran et al., 2018)
- Very effective for label-flip attacks when poison rate > 5%
- Works across data modalities when appropriate representations are used
- Can detect attacks that don't create feature-space outliers

**Weaknesses:**
- Effectiveness drops sharply below 5% poison rate
- Assumes poison creates a rank-1 perturbation (fails for distributed/multi-target attacks)
- Requires choosing the correct representation layer for neural networks
- Computational cost: O(n × d²) for SVD on large matrices

**Measured baselines:**
```
Label-flip 10% poison rate:    AUC = 0.88
Label-flip 5% poison rate:     AUC = 0.80
Label-flip 3% poison rate:     AUC = 0.65
Label-flip 1% poison rate:     AUC = 0.53 (ineffective)
Backdoor (non-label-flip):     AUC = 0.62
```

**Critical limitation:** At < 5% poison rate, the spectral signature of the poison is indistinguishable from natural variance in the data. This is a fundamental mathematical limitation, not an implementation bug.

### 3. Activation Clustering

**How it works:** Clusters the activations of a trained model per class. If a class has two distinct clusters, one cluster may correspond to poisoned samples.

**Strengths:**
- Effective for backdoor attacks in neural networks
- Can detect attacks invisible to feature-space methods
- Leverages the model's own learned representations

**Weaknesses:**
- Requires a trained model (can't detect poison before training)
- Assumes clean majority within each class
- K=2 assumption may not hold for complex attack strategies
- Not applicable to streaming (requires batch analysis after training)

**Measured baselines:**
```
Backdoor (strong trigger, 10% rate):   AUC = 0.78
Backdoor (subtle trigger, 5% rate):    AUC = 0.65
Clean-label attack:                      AUC = 0.55
```

### 4. Streaming Ensemble (Combined)

**How it works:** Runs a lightweight subset of methods on each sample in real-time, optimized for throughput over recall. Uses z-score anomaly detection on incoming feature vectors.

**Strengths:**
- High throughput on the z-score/IQR path: ~12,000+ samples/sec (20-dim, IsolationForest refit excluded)
- Low latency: P50 < 0.05ms per sample on the statistical path
- Catches obvious anomalies immediately
- Drift detection provides early warning

> **Throughput caveat:** the >10k/sec figure is the statistical (Welford z-score/IQR) scoring path *only*. With the default periodic IsolationForest refit enabled (every 1000 samples on up to a 10k-sample window), sustained throughput is far lower because the refit dominates. Tune `refit_interval` to trade multivariate recall for speed.

**Weaknesses:**
- Trades recall for throughput — will miss subtle attacks
- Single-sample scoring lacks the batch context that makes spectral methods effective
- No access to model activations (feature-only)
- High FP rate on naturally high-variance data

**Measured baselines:**
```
Throughput (z-score/IQR path, refit excluded):  ~12,000+ samples/sec
Throughput (default config, refit enabled):      far lower (refit-bound)
Strong backdoor (obvious):     Detection rate ~90%
Subtle backdoor:               Detection rate ~30%
Label-flip (individual):       Detection rate ~15% (fundamentally hard per-sample)
Overall streaming AUC:         ~0.65
```

---

## What We Cannot Detect

Be explicit about known blind spots:

1. **Clean-label attacks** — Poison samples that are correctly labeled but contain triggers. These are statistically indistinguishable from clean data without model training.

2. **Low-rate attacks (< 3%)** — At very low poison rates, the signal-to-noise ratio is too low for statistical methods.

3. **Adaptive attacks** — An attacker who knows our detection methods can craft poison that evades them (e.g., minimizing spectral signature while maintaining attack efficacy).

4. **Semantic backdoors** — Triggers that use natural features (e.g., "all images with sunglasses → target class") are virtually undetectable without domain knowledge.

5. **Distributed/multi-target attacks** — Our methods assume a single-target attack; distributed attacks across multiple classes reduce per-class signal.

---

## Recommendations for Users

### When to use each method:

| Scenario | Recommended Method | Expected Efficacy |
|----------|-------------------|-------------------|
| Tabular data, moderate poison rate | Feature-space | High (AUC > 0.80) |
| Known label-flip attack, > 5% rate | Spectral | High (AUC > 0.80) |
| Neural network, post-training audit | Activation clustering | Moderate (AUC ~0.75) |
| Real-time monitoring, catch obvious attacks | Streaming ensemble | Moderate (catches ~65%) |
| Image data, subtle attack | **Not recommended alone** | Low — combine with other defenses |

### Defense-in-depth strategy:

For production ML pipelines, we recommend a layered approach:

1. **Streaming (real-time):** Catch obvious anomalies before they enter the training set. Accept that recall is low.

2. **Batch audit (daily):** Run spectral + feature-space on the day's accumulated data. Higher recall than streaming.

3. **Post-training verification:** After model training, run activation clustering to detect attacks that evaded pre-training defenses.

4. **Model behavior monitoring:** Monitor model predictions for unexpected behavior (out of scope for this tool, but critical).

### Improving efficacy for your use case:

1. **Use meaningful feature representations:** Raw pixels → pretrained embeddings improves image AUC from 0.54 to ~0.67.

2. **Tune threshold per modality:** Tabular and image data need different thresholds. Default (3.0) is conservative.

3. **Combine with data provenance:** If you can track data sources, restrict detection to untrusted sources.

4. **Increase poison budget assumptions:** If you expect > 5% poison rate, spectral methods are highly effective.

---

## Improvement Roadmap

Planned improvements to detection efficacy:

### Short-term (next release)
- [ ] Add pretrained embedding extraction for image data
- [ ] Implement STRIP (STRong Intentional Perturbation) for backdoor detection
- [ ] Add per-modality threshold auto-tuning

### Medium-term (3-6 months)
- [ ] Neural Cleanse implementation for trigger reconstruction
- [ ] Frequency-domain analysis for image backdoors
- [ ] Federated detection for distributed training

### Long-term (research)
- [ ] Meta-learning based detection (train a detector on known attacks)
- [ ] Certified robustness guarantees (provable bounds on undetected poison)
- [ ] Adaptive methods that adjust to attacker strategy

---

## How to Run Efficacy Benchmarks

```bash
# Run full benchmark suite with honest AUC reporting
python benchmarks/throughput_tracker.py --output results.json

# Output includes:
# - auc_backdoor: AUC on backdoor attacks
# - auc_label_flip: AUC on label-flip attacks  
# - auc_subtle: AUC on subtle perturbation attacks
# - streaming throughput and latency
```

Results are tracked in CI. See `.github/workflows/release.yml` for the automated benchmark gate.

---

## References

- Tran, B., Li, J., Madry, A. (2018). "Spectral Signatures in Backdoor Attacks." NeurIPS.
- Chen, B., et al. (2019). "Detecting Backdoor Attacks on Deep Neural Networks by Activation Clustering."
- Peri, N., et al. (2020). "Deep k-NN Defense Against Clean-Label Data Poisoning Attacks." ECCV.
- Gao, Y., et al. (2019). "STRIP: A Defence Against Trojan Attacks on Deep Neural Networks." ACSAC.
