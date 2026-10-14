# Claim Ledger - Poster 04

> Verified code snapshot: `45740923aa16539909a7ae993104a80ecfe85e0b`; GitHub Actions Python 3.12 verification on 2026-10-14, CI run `38502623976`; coverage floor 90%.

| # | Claim | Classification | Evidence |
|---|---|---|---|
| 1 | 226 total tests pass (186 production-facing, 40 legacy stub-only demonstrations) | VERIFIED_AT_SNAPSHOT | Python 3.12 CI run 38502623976; do not count the legacy stub tests as production-facing. |
| 2 | 91.75% statement coverage | VERIFIED_AT_SNAPSHOT | Python 3.12 main CI run 38502623976; CI minimum is 90%. |
| 3 | Cross-class centroid F1 = 0.55 / 0.595 / 0.6975 at 5% / 10% / 20% poison | VERIFIED_AT_SNAPSHOT | `results/spectral_benchmark.json` (committed synthetic benchmark, separate from latest CI test count). |
| 4 | Old top-1 spectral baseline = 0.08 / 0.23 / 0.3675 | VERIFIED_AT_SNAPSHOT | Same committed benchmark artifact. |
| 5 | Cross-class spectral beats feature-space ensemble on 3/3 tested rates | VERIFIED_AT_SNAPSHOT | Benchmark comparison block; ensemble F1 0.0841 / 0.1421 / 0.2331. |
| 6 | Streaming throughput as a fixed product number | UNSUPPORTED | Hardware-scoped microbenchmark only; no fixed SLA is published. |
| 7 | High recall for clean-label/subtle backdoor attacks | UNSUPPORTED | Explicit repository limitation. |

Synthetic benchmark results must not be restated as real-pipeline efficacy.
