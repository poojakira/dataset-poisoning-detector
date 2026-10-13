# Verified Metrics - Poster 04

**Code snapshot:** `43313ee7dab746a27999e22796074e4a0d941322`
**Verification:** GitHub Actions Python 3.12 verification on 2026-10-04, run `37169444656`; CI coverage floor is 90%.

| Metric | Cited snapshot value |
|---|---:|
| Tests passed | **200** |
| Statement coverage | **91.20%** |
| Cross-class F1 @ 5% poison | **0.55** |
| Cross-class F1 @ 10% poison | **0.595** |
| Cross-class F1 @ 20% poison | **0.6975** |
| Old top-1 spectral F1 | **0.08 / 0.23 / 0.3675** |
| Feature-space ensemble F1 | **0.0841 / 0.1421 / 0.2331** |

The efficacy values are from the committed synthetic label-flip benchmark, not production data.


## Claim audit and rendered-source boundary, October 13, 2026 UTC

The reviewed printed claims, source and test commit anchors, CI dates and benchmark limitations are in `verified_claims.json`. The PDF is generated from that manifest and the PNG is rasterized from the same page by `render_poster.py`. Source inventory, dated CI and separate reported experiments must not be combined into one result. Earlier artifact versions remain in Git history; these corrections do not assert production readiness.

Offline poster rendering: `python -m pip install reportlab==4.4.9 PyMuPDF==1.26.6`, then `python poster/render_poster.py`. The font is bundled with the pinned ReportLab package; no browser or network fetch is used during rendering.
