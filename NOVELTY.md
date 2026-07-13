# Novelty, Data & Production-Readiness — honest, skeptical assessment

## Genuinely useful here

- **Ensemble streaming detection** (per-class z-score + IQR fences + Isolation
  Forest) with per-sample anomaly attribution, a real-time API, Prometheus
  metrics, and backpressure. The ensemble-voting idea (a sample must look
  anomalous in multiple ways) is a reasonable false-positive reducer.
- **Now hardened**: optional API-key auth (`POISON_API_KEYS`), rate limiting,
  and Redis TLS enforcement for the pipeline.

## Be skeptical about these claims

- **Evaluation is on synthetic/statistical anomalies, not real poisoning.**
  Detecting Gaussian-ish outliers is not the same as detecting a *backdoor
  trigger* embedded in otherwise-normal samples, or a **clean-label** attack
  where labels are correct but features are subtly poisoned. Those are the hard
  cases and are not demonstrated here.
- **"Zero false positives" is not a property.** It was a single-dataset
  observation (already corrected in the README). Isolation Forest has a
  non-trivial FP rate on real high-dimensional data. Report ROC/AUC on labeled
  data and pick the operating point from the curve.
- **No published-benchmark results.** There is no evidence against a recognized
  poisoning benchmark, so cross-tool comparison is impossible.

## Data required before honest production claims

| Need | Why | Source | Scale |
|------|-----|--------|-------|
| Real backdoor triggers | Find actual triggers, not just noise outliers | IARPA **TrojAI**, BadNets, vision/NLP trojans | 10k+ across trigger types |
| Label-flip ground truth | Known poison ratios / distribution shift | CIFAR-10/100 with 0/1/5/10/25% flips | 500k+ labeled |
| Clean training dynamics | Baseline loss/gradient distributions | many clean training runs | 1000 runs |
| Clean-label vs dirty-label | Different detectors needed for each | synthesized both ways | 20k each |
| Real-world attack datasets | Evaluate against published attacks | poisoning benchmarks / TrojLLM | 10 datasets |

**Honest shipping recommendation:** prove the detector against the **TrojAI**
evaluation and report ROC/AUC before claiming "poisoning detection." Until then,
describe it accurately as **statistical anomaly + ensemble outlier detection**
for training data, which is useful but narrower than "backdoor detection."

## Known gaps

- WebSocket `/stream` is unauthenticated (HTTP auth middleware does not cover
  it); add token validation before exposing it.
- In-memory rate limiter is per-process; use the Redis-backed path behind a
  load balancer.
