# Threat Model: Dataset Poisoning Attacks

## Document Purpose

This threat model identifies, classifies, and assesses data poisoning attacks
against machine learning training pipelines. It maps attack vectors to
detection capabilities implemented in `dataset-poisoning-detector`, documents
known limitations, and considers adaptive adversaries who may attempt to
evade detection.

MITRE ATLAS Reference: **AML.T0020 — Poison Training Data**

---

## 1. Attack Taxonomy

### 1.1 Label Flipping

**Description:** Adversary modifies labels of existing training samples without
altering features. A "cat" image is relabeled as "dog." The model learns
incorrect decision boundaries.

**Attacker Capability:** Write access to label storage (database, annotation
files, or labeling pipeline).

**Impact:** Targeted degradation of specific class accuracy. Random flipping
degrades overall accuracy; strategic flipping (e.g., flipping only samples near
decision boundaries) causes maximum damage with minimum detectable signal.

**Detection Approach:**
- Spectral signatures (Tran et al., 2018): Flipped samples cluster along the
  top singular vector of the within-class covariance matrix.
- Cross-validation consistency: Samples whose label disagrees with k-NN
  predictions from held-out clean data.

**Detection Limitations:**
- Low flip rates (<5%) produce weak spectral signal.
- Strategic flipping near decision boundaries may not produce outlier
  projections.

---

### 1.2 Clean-Label Attacks

**Description:** Adversary adds samples with CORRECT labels but perturbed
features designed to shift the decision boundary. The training data appears
legitimate under manual inspection.

**Key Variants:**
- **Poison Frogs** (Shafahi et al., 2018): Feature collision attack where
  poisoned samples are optimized to collide with a target in feature space
  while maintaining their original (correct) label.
- **Bullseye Polytope** (Aghakhani et al., 2021): Multi-point attack creating
  a convex polytope around the target representation.

**Attacker Capability:** Ability to craft and inject training samples. May
require knowledge of the model architecture or a surrogate model for
transfer attacks.

**Impact:** Targeted misclassification of specific test inputs without
degrading overall model accuracy. Extremely difficult to detect because
labels are correct and features appear plausible.

**Detection Approach:**
- Activation clustering: Poisoned samples may form a sub-cluster within their
  labeled class in representation space.
- Gradient-based influence functions: Poisoned samples have outsized influence
  on specific test predictions.

**Detection Limitations:**
- **This is the primary weakness of our detector.** Statistical outlier
  detection (z-score, IQR, Isolation Forest) fundamentally cannot catch
  clean-label attacks because the features are designed to be in-distribution.
- Spectral methods require substantial poison rates to detect.
- Feature collision attacks with strong perturbation budgets can evade
  activation clustering.

---

### 1.3 Backdoor Triggers (Trojan Attacks)

**Description:** Adversary inserts a trigger pattern (e.g., a small patch,
specific pixel pattern, or semantic transformation) into a subset of training
samples and assigns them a target label. At inference time, any input with the
trigger is misclassified to the target label.

**Key Variants:**
- **Patch-based** (BadNets, Gu et al., 2017): Fixed pixel patch in corner.
- **Blended** (Chen et al., 2017): Trigger blended across entire image.
- **Warping-based** (Nguyen & Tran, 2021): Spatial transformations as triggers.
- **Semantic** (Bagdasaryan et al., 2020): Natural features as triggers
  (e.g., "green cars" → target class).

**Attacker Capability:** Ability to inject crafted samples into training data.
Trigger must be reproducible at inference time.

**Impact:** Model performs normally on clean inputs but misclassifies any input
containing the trigger. Attack success rates >95% are common with <1% poison
rate.

**Detection Approach:**
- Neural Cleanse (Wang et al., 2019): Reverse-engineers minimal trigger
  patterns for each class.
- Spectral signatures: Triggered samples often separate along top singular
  vectors.
- STRIP (Gao et al., 2019): Runtime detection via entropy of predictions
  under input perturbation.
- Activation clustering: Triggered samples form a distinct cluster in
  representation space.

**Detection Limitations:**
- Semantic triggers are undetectable by pattern-based methods.
- Blended triggers with low opacity evade spectral methods.
- Distributed triggers (different sub-patterns in different samples) evade
  per-sample analysis.
- Our statistical methods only detect triggers that create feature-space
  outliers; subtle triggers do not.

---

### 1.4 Feature Collision

**Description:** A specific clean-label technique where the adversary optimizes
poison samples to have similar feature representations to a target sample while
maintaining a different (correct) label.

**Mechanism:** Minimizes distance in feature space between poison and target:
```
min_x ||φ(x) - φ(target)||² s.t. label(x) = attacker_chosen_class
```

**Attacker Capability:** Access to model or surrogate model for gradient
computation. Ability to inject crafted samples.

**Impact:** After training on poisoned data, the target sample is classified as
the attacker's chosen class because the model has learned to associate the
target's representation region with that class.

**Detection Approach:**
- Influence function analysis: Identify samples with outsized influence on
  specific predictions.
- Representation distance monitoring: Flag samples whose feature
  representation is unusually close to samples of other classes.

**Detection Limitations:**
- Requires access to a trained (potentially compromised) model.
- Transfer attacks using surrogate models may not produce detectable
  signatures in the victim model's representation space.
- Computationally expensive: O(n²) pairwise distance computation.

---

### 1.5 Witches' Brew (Gradient Matching)

**Description:** Advanced clean-label attack that optimizes poison samples to
align their gradient contribution with a desired adversarial gradient direction.
The training process naturally moves the model toward misclassifying the target.

**Mechanism (Geiping et al., 2021):**
```
max_p cos(∇L(p, θ), ∇_adv)
```
Where `∇_adv` is the gradient direction that would cause target misclassification.

**Attacker Capability:** Knowledge of training algorithm, loss function, and
either the model architecture or a transferable surrogate. Does NOT require
control over training hyperparameters.

**Impact:** Achieves >50% attack success with as few as 1% poison samples on
CIFAR-10. Works on transfer learning and fine-tuning scenarios.

**Detection Approach:**
- Gradient clustering: Poisoned samples may have correlated gradient
  directions distinct from clean samples.
- Training loss trajectory: Poisoned samples may exhibit unusual loss
  curves during training.
- Meta-classification: Train a binary classifier to distinguish poisoned
  vs. clean datasets based on model behavior features.

**Detection Limitations:**
- Gradient analysis requires full training pipeline access.
- Witches' Brew explicitly optimizes for stealth — poison samples are
  crafted to appear in-distribution.
- Single-epoch gradient analysis misses the cumulative effect.
- Computational cost scales with model size × dataset size.

---

### 1.6 Gradient Matching (General)

**Description:** Broader class of attacks where poison samples are optimized so
their gradient signal during training matches a desired adversarial objective.

**Relationship to other attacks:** Witches' Brew is a specific instance.
MetaPoison (Huang et al., 2020) and Bullseye Polytope also use gradient
alignment as part of their optimization.

**Detection Approach:**
- Gradient norm monitoring: Poisoned samples may have unusually large
  gradient norms.
- Fisher Information analysis: Detect samples that disproportionately
  influence model parameters.

---

## 2. MITRE ATLAS Mapping

| ATLAS ID    | Technique                | Covered Attacks           | Our Detection   |
|-------------|--------------------------|---------------------------|-----------------|
| AML.T0020   | Poison Training Data     | All above                 | Partial         |
| AML.T0020.000 | Label Poisoning        | Label flipping            | Spectral ✓      |
| AML.T0020.001 | Insert Backdoor        | Backdoor triggers         | Spectral ✓      |
| AML.T0020.002 | Clean-label Attack     | Feature collision, Brew   | Weak ✗          |

### Attack Lifecycle (ATLAS Kill Chain)

1. **Reconnaissance (AML.T0016):** Adversary identifies training data sources,
   annotation pipelines, and data collection endpoints.
2. **Resource Development:** Adversary crafts poison samples using surrogate
   models or knowledge of target architecture.
3. **Initial Access (AML.T0020):** Poison samples injected via:
   - Compromised data sources (web scraping, public datasets)
   - Malicious crowd-sourced annotations
   - Supply chain compromise of data preprocessing
4. **Persistence:** Poison samples remain in training data across retraining
   cycles unless detected and removed.
5. **Impact (AML.T0034):** Model evasion at inference time, targeted
   misclassification, or general accuracy degradation.

---

## 3. Detection Capability Matrix

| Attack Type         | Z-Score | IQR   | IsoForest | Spectral | Ensemble |
|---------------------|---------|-------|-----------|----------|----------|
| Label Flip (random) | Low     | Low   | Low       | High     | Medium   |
| Label Flip (strategic) | None | None  | None      | Medium   | Low      |
| Clean-Label         | None    | None  | None      | Low      | None     |
| Backdoor (patch)    | Medium  | Medium| Medium    | High     | High     |
| Backdoor (blended)  | Low     | Low   | Low       | Medium   | Low      |
| Backdoor (semantic) | None    | None  | None      | None     | None     |
| Feature Collision   | None    | None  | Low       | Low      | None     |
| Witches' Brew       | None    | None  | None      | Low      | None     |

**Legend:** None = undetectable, Low = <30% recall, Medium = 30-70%, High = >70%

---

## 4. Adversarial Adaptive Attackers

### 4.1 Threat: Attacker Knows Detection Method

If the adversary knows we use spectral signature detection, they can:

1. **Minimize spectral projection:** Add a regularization term to the poison
   optimization that minimizes correlation with top singular vectors.
2. **Distribute across directions:** Spread poison signal across many singular
   vectors rather than concentrating on the top-k.
3. **Match clean distribution:** Constrain poison to have similar spectral
   properties to clean samples within the same class.

### 4.2 Threat: Attacker Knows Ensemble Configuration

If the adversary knows we use z-score + IQR + Isolation Forest majority vote:

1. **Stay within thresholds:** Craft samples that individually pass each
   method's threshold while still achieving the attack objective.
2. **Exploit method independence:** Each method has blind spots. Samples
   designed to be non-outliers in z-score AND IQR AND isolation score are
   achievable with moderate perturbation budgets.
3. **Slow-drip poisoning:** Insert samples that are individually clean but
   collectively shift the data distribution over time.

### 4.3 Mitigation Against Adaptive Attackers

- **Method diversity:** Periodically change detection methods without
  announcing which are active.
- **Randomized thresholds:** Add noise to detection thresholds to prevent
  precise boundary crafting.
- **Human-in-the-loop:** Flag borderline cases for expert review.
- **Provenance tracking:** Monitor data source integrity independent of
  content analysis.
- **Differential privacy:** Training with DP limits the influence of any
  single sample, reducing poison effectiveness regardless of detection.

---

## 5. Assumptions and Scope

### In Scope
- Poisoning of tabular and image feature datasets
- Attacks detectable via statistical properties of features/labels
- Batch and streaming ingestion scenarios
- Pre-training detection (before model sees data)

### Out of Scope
- Model-level defenses (robust training, DP-SGD, certified defenses)
- Inference-time attacks (adversarial examples, model extraction)
- Supply chain attacks on code/dependencies (covered by separate tooling)
- Federated learning poisoning (gradient aggregation attacks)

### Key Assumptions
1. Defender has access to raw features before training.
2. The majority of training data is clean (poison rate < 50%).
3. Attacker cannot modify detection system itself.
4. Feature representations are available for spectral analysis.

---

## 6. Risk Assessment

| Attack            | Likelihood | Impact | Detectability | Risk Score |
|-------------------|-----------|--------|---------------|------------|
| Label Flipping    | High      | Medium | High          | Medium     |
| Clean-Label       | Medium    | High   | Low           | High       |
| Backdoor (patch)  | High      | High   | High          | Medium     |
| Backdoor (blend)  | Medium    | High   | Medium        | High       |
| Backdoor (semantic) | Low     | High   | None          | Critical   |
| Feature Collision | Low       | High   | Low           | High       |
| Witches' Brew     | Low       | High   | Low           | High       |

---

## 7. Recommendations

### Immediate (this tool provides)
1. Run spectral signature detection on every training batch.
2. Use ensemble statistical detection as a first-pass filter.
3. Monitor detection metrics over time for distribution shift.

### Short-term (requires additional tooling)
4. Implement Neural Cleanse for backdoor-specific detection.
5. Add influence function computation for clean-label detection.
6. Deploy data provenance tracking.

### Long-term (architectural changes)
7. Train with differential privacy (ε ≤ 8) to bound poison influence.
8. Implement certified defenses (DPA, randomized smoothing for training).
9. Red-team detection pipeline with adaptive attack simulations.

---

## 8. References

1. Tran, B., Li, J., & Madry, A. (2018). Spectral Signatures in Backdoor
   Attacks. NeurIPS 2018.
2. Shafahi, A., et al. (2018). Poison Frogs! Targeted Clean-Label Poisoning
   Attacks on Neural Networks. NeurIPS 2018.
3. Gu, T., Dolan-Gavitt, B., & Garg, S. (2017). BadNets: Identifying
   Vulnerabilities in the Machine Learning Model Supply Chain. arXiv:1708.06733.
4. Geiping, J., et al. (2021). Witches' Brew: Industrial Scale Data Poisoning
   via Gradient Matching. ICLR 2021.
5. Wang, B., et al. (2019). Neural Cleanse: Identifying and Mitigating Backdoor
   Attacks in Neural Networks. IEEE S&P 2019.
6. Gao, Y., et al. (2019). STRIP: A Defence Against Trojan Attacks on Deep
   Neural Networks. ACSAC 2019.
7. Huang, W. R., et al. (2020). MetaPoison: Practical General-purpose
   Clean-label Data Poisoning. NeurIPS 2020.
8. MITRE ATLAS. AML.T0020 - Poison Training Data.
   https://atlas.mitre.org/techniques/AML.T0020

---

## Document History

| Date       | Version | Author      | Changes                     |
|------------|---------|-------------|-----------------------------|
| 2026-08-24 | 1.0     | Pooja Kiran | Initial threat model        |
