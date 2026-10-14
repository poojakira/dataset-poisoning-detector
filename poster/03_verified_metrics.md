# Verified Metrics - Poster 04

**Code snapshot:** `45740923aa16539909a7ae993104a80ecfe85e0b`
**Verification:** GitHub Actions Python 3.12 verification on 2026-10-14 UTC, run `38502623976`; CI coverage floor is 90%.

| Metric | Oct 14, 2026 main CI or separately scoped benchmark |
|---|---:|
| Tests passed (includes 40 legacy stub-only tests) | **226** |
| Production-facing tests passed | **186** |
| Statement coverage | **91.75%** |
| Cross-class F1 @ 5% poison | **0.55** |
| Cross-class F1 @ 10% poison | **0.595** |
| Cross-class F1 @ 20% poison | **0.6975** |
| Old top-1 spectral F1 | **0.08 / 0.23 / 0.3675** |
| Feature-space ensemble F1 | **0.0841 / 0.1421 / 0.2331** |

The F1 efficacy values are from the separately committed synthetic label-flip benchmark, not measurements rerun in this test CI or evidence of production detection accuracy. The archived October 4 code/CI snapshot reported **200 passing tests** and **91.20% statement coverage**, and remains a dated historical result.
