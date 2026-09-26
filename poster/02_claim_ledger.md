# Claim Ledger — Poster 04 (04-dataset-poisoning-detector)

MIT • Python 3.12 • HEAD b45d662 • verified 2026-09-26. Classification: VERIFIED_CURRENT / VERIFIED_HISTORICAL / PARTIAL / UNVERIFIED / UNSUPPORTED.

| # | Claim | Classification | Evidence |
|---|---|---|---|
| 1 | Spectral label-flip F1 = 0.08 / 0.23 / 0.37 at 5/10/20% poison | VERIFIED_CURRENT | results/spectral_benchmark.json (committed), read directly. Negative result shown prominently. |
| 2 | Spectral beats ensemble on 2/3 contamination rates | VERIFIED_CURRENT | spectral_benchmark.json comparison block; both remain weak on label-flip. |
| 3 | 4 methods: z-score, IQR, IsolationForest, spectral; majority vote >=2/3 | VERIFIED_CURRENT | README architecture + module table. |
| 4 | Streaming throughput | PARTIAL | BENCHMARK_METADATA.md: environment-scoped microbenchmark; prior '~12,400/s' note demoted to historical (no SHA). Not shown as current. |
| 5 | High recall on label-flip / clean-label detection | UNSUPPORTED (disclaimed) | README + benchmark explicitly document these as failure modes. |

## Policy applied
- Only VERIFIED_CURRENT figures appear as prominent current results.
- Historical/projected values are labeled (dashed box / explicit note).
- Unsupported production/accuracy claims are omitted or shown in the red "NOT ESTABLISHED" box.
