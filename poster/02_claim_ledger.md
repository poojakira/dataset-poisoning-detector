# Claim Ledger - Poster 04

> Verified code snapshot: `43313ee7dab746a27999e22796074e4a0d941322`; GitHub Actions Python 3.12 verification on 2026-10-04, CI run `37169444656`; coverage floor 90%.

| # | Claim | Classification | Evidence |
|---|---|---|---|
| 1 | 200 tests pass | VERIFIED_AT_SNAPSHOT | Cited snapshot Python 3.12 verification; CI enforces the same 90% floor. |
| 2 | 91.20% statement coverage | VERIFIED_AT_SNAPSHOT | Cited snapshot Python 3.12 verification; CI enforces the same 90% floor. |
| 3 | Cross-class centroid F1 = 0.55 / 0.595 / 0.6975 at 5% / 10% / 20% poison | VERIFIED_AT_SNAPSHOT | `results/spectral_benchmark.json`. |
| 4 | Old top-1 spectral baseline = 0.08 / 0.23 / 0.3675 | VERIFIED_AT_SNAPSHOT | Same committed benchmark artifact. |
| 5 | Cross-class spectral beats feature-space ensemble on 3/3 tested rates | VERIFIED_AT_SNAPSHOT | Benchmark comparison block; ensemble F1 0.0841 / 0.1421 / 0.2331. |
| 6 | Streaming throughput as a fixed product number | UNSUPPORTED | Hardware-scoped microbenchmark only; no fixed SLA is published. |
| 7 | High recall for clean-label/subtle backdoor attacks | UNSUPPORTED | Explicit repository limitation. |

Synthetic benchmark results must not be restated as real-pipeline efficacy.


## Claim audit and rendered-source boundary, October 13, 2026 UTC

The reviewed printed claims, source and test commit anchors, CI dates and benchmark limitations are in `verified_claims.json`. The PDF is generated from that manifest and the PNG is rasterized from the same page by `render_poster.py`. Source inventory, dated CI and separate reported experiments must not be combined into one result. Earlier artifact versions remain in Git history; these corrections do not assert production readiness.

Offline poster rendering: `python -m pip install reportlab==4.4.9 PyMuPDF==1.26.6`, then `python poster/render_poster.py`. The font is bundled with the pinned ReportLab package; no browser or network fetch is used during rendering.
