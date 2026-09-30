# Claim Ledger - Poster 04

> Verified code snapshot: `ed38ad039a60a648c38a247e4136b34bbe287bda`; successful CI run `36783091096`, 2026-09-30.

| # | Claim | Classification | Evidence |
|---|---|---|---|
| 1 | 162 tests pass | VERIFIED_AT_SNAPSHOT | Current-main Python 3.12 CI. |
| 2 | 70.77% statement coverage | VERIFIED_AT_SNAPSHOT | Current-main Python 3.12 CI. |
| 3 | Cross-class centroid F1 = 0.55 / 0.595 / 0.6975 at 5% / 10% / 20% poison | VERIFIED_AT_SNAPSHOT | `results/spectral_benchmark.json`. |
| 4 | Old top-1 spectral baseline = 0.08 / 0.23 / 0.3675 | VERIFIED_AT_SNAPSHOT | Same committed benchmark artifact. |
| 5 | Cross-class spectral beats feature-space ensemble on 3/3 tested rates | VERIFIED_AT_SNAPSHOT | Benchmark comparison block; ensemble F1 0.0841 / 0.1421 / 0.2331. |
| 6 | Streaming throughput as a fixed product number | UNSUPPORTED | Hardware-scoped microbenchmark only; no fixed SLA is published. |
| 7 | High recall for clean-label/subtle backdoor attacks | UNSUPPORTED | Explicit repository limitation. |

Synthetic benchmark results must not be restated as real-pipeline efficacy.
