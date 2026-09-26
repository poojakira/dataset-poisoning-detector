# Verified Metrics — Poster 04

MIT • Python 3.12 • HEAD b45d662 • verified 2026-09-26. Verified for this poster on Windows / CPython 3.12.10.

## Headline cards
- 0.37 — BEST F1 (spectral)
- 0.08 — WORST F1 @5%
Notes: Label-flip benchmark, seed 2018, 2000×100 synthetic. F1 rises with contamination but stays low — by design honest.

## Verified surface
| Item | Value |
|---|---|
| @ 5% poison | 0.08 |
| @ 10% poison | 0.23 |
| @ 20% poison | 0.37 |

## Chart values
| Series | Value |
|---|---|
| Spectral F1 (x100) | 37 |
| Ensemble F1 (x100) | 23 |
| Spectral wins | 67 |
Note: Spectral beats ensemble on 2/3 rates; both remain weak on label-flip. spectral_benchmark.json.

## Historical / provenance
results/spectral_benchmark.json (committed). Tran et al. 2018 setup. Throughput = environment- scoped microbenchmark; no production SLA claimed.

## Not established by this repository
High recall on label-flip attacks. Detection of subtle clean-label / image backdoors. Robustness guarantee.
