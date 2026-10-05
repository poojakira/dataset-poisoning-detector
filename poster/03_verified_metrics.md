# Verified Metrics - Poster 04

**Code snapshot:** `43313ee7dab746a27999e22796074e4a0d941322`
**Verification:** GitHub Actions Python 3.12 verification on 2026-10-04, run `37169444656`; CI coverage floor is 90%.

| Metric | Current value |
|---|---:|
| Tests passed | **200** |
| Statement coverage | **91.20%** |
| Cross-class F1 @ 5% poison | **0.55** |
| Cross-class F1 @ 10% poison | **0.595** |
| Cross-class F1 @ 20% poison | **0.6975** |
| Old top-1 spectral F1 | **0.08 / 0.23 / 0.3675** |
| Feature-space ensemble F1 | **0.0841 / 0.1421 / 0.2331** |

The efficacy values are from the committed synthetic label-flip benchmark, not production data.
