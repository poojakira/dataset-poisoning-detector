# Verified Metrics - Poster 04

**Code snapshot:** `258a4646abcc66bed2c9ccb538fa2f593140e750`
**Verification:** Local Python 3.12 reproduction on 2026-10-01; CI coverage floor is 90%.

| Metric | Current value |
|---|---:|
| Tests passed | **199** |
| Statement coverage | **90.88%** |
| Cross-class F1 @ 5% poison | **0.55** |
| Cross-class F1 @ 10% poison | **0.595** |
| Cross-class F1 @ 20% poison | **0.6975** |
| Old top-1 spectral F1 | **0.08 / 0.23 / 0.3675** |
| Feature-space ensemble F1 | **0.0841 / 0.1421 / 0.2331** |

The efficacy values are from the committed synthetic label-flip benchmark, not production data.
