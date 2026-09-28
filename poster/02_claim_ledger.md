# Claim Ledger — Poster 04 (04-dataset-poisoning-detector)

> Evidence status: This is a dated repository snapshot at the commit identified below. `VERIFIED_AT_SNAPSHOT` means verified for that commit and environment; it does not assert the same result on the latest `main`. Compare newer claims with the repository evidence before reuse.

MIT • Python 3.12 • HEAD 0688274 • verified 2026-09-26. Classification: VERIFIED_AT_SNAPSHOT / VERIFIED_HISTORICAL / PARTIAL / UNVERIFIED / UNSUPPORTED.

| # | Claim | Classification | Evidence |
|---|---|---|---|
| 1 | Spectral label-flip F1 = 0.08 / 0.23 / 0.37 at 5/10/20% poison | VERIFIED_AT_SNAPSHOT | results/spectral_benchmark.json (committed), read directly. Negative result shown prominently. |
| 2 | Spectral beats ensemble on 2/3 contamination rates | VERIFIED_AT_SNAPSHOT | spectral_benchmark.json comparison block; both remain weak on label-flip. |
| 3 | 4 methods: z-score, IQR, IsolationForest, spectral; majority vote >=2/3 | VERIFIED_AT_SNAPSHOT | README architecture + module table. |
| 4 | Streaming throughput | PARTIAL | BENCHMARK_METADATA.md: environment-scoped microbenchmark; prior '~12,400/s' note demoted to historical (no SHA). Not shown as current. |
| 5 | High recall on label-flip / clean-label detection | UNSUPPORTED (disclaimed) | README + benchmark explicitly document these as failure modes. |

## Policy applied
- Only VERIFIED_AT_SNAPSHOT figures appear as prominent current results.
- Historical/projected values are labeled (dashed box / explicit note).
- Unsupported production/accuracy claims are omitted or shown in the red "NOT ESTABLISHED" box.
