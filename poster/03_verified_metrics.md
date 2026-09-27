# Verified Metrics — Poster 04

MIT • Python 3.12 • HEAD b45d662 • verified 2026-09-26. Verified for this poster on Windows / CPython 3.12.10.

## Headline cards
- 0.70 — BEST F1 (cross-class)
- 0.55 — F1 @5% poison
Notes: Label-flip benchmark, seed 2018, 2000×100 synthetic. Cross-class centroid detector; top-1 baseline kept for honesty.

## Verified surface
| Item | Value |
|---|---|
| @ 5% poison | 0.55 |
| @ 10% poison | 0.60 |
| @ 20% poison | 0.70 |

## Chart values
| Series | Value |
|---|---|
| Cross-class F1 (x100) | 70 |
| Top-1 baseline (x100) | 37 |
| Ensemble (x100) | 23 |
Note: Cross-class centroid beats top-1 spectral and the feature-space ensemble on 3/3 rates. spectral_benchmark.json.

## Historical / provenance
results/spectral_benchmark.json (committed). Tran et al. 2018 setup. Top-1 baseline (0.08/0.23/0.37) retained in the JSON for transparent comparison.

## Not established by this repository
High recall on label-flip attacks. Detection of subtle clean-label / image backdoors. Robustness guarantee.
