# Reproduce the Work - Poster 04

**Repository:** `github.com/poojakira/dataset-poisoning-detector`
**Verified code snapshot:** `43313ee7dab746a27999e22796074e4a0d941322`
**Verification:** GitHub Actions Python 3.12 verification on 2026-10-04, run `37169444656`; CI coverage floor is 90%.

```bash
git clone https://github.com/poojakira/dataset-poisoning-detector.git
cd dataset-poisoning-detector
git checkout 43313ee7dab746a27999e22796074e4a0d941322
python -m pip install -e ".[dev,realtime,kafka]"
pytest tests/ -q --cov=poison_detector --cov-report=term
python benchmark/cifar10_label_flip_benchmark.py
```

Expected current evidence: **200 passed**, **91.20% statement coverage**.

Expected committed benchmark cross-class F1: **0.55 / 0.595 / 0.6975** at 5% / 10% / 20% poison.


## Claim audit and rendered-source boundary, October 13, 2026 UTC

The reviewed printed claims, source and test commit anchors, CI dates and benchmark limitations are in `verified_claims.json`. The PDF is generated from that manifest and the PNG is rasterized from the same page by `render_poster.py`. Source inventory, dated CI and separate reported experiments must not be combined into one result. Earlier artifact versions remain in Git history; these corrections do not assert production readiness.

Offline poster rendering: `python -m pip install reportlab==4.4.9 PyMuPDF==1.26.6`, then `python poster/render_poster.py`. The font is bundled with the pinned ReportLab package; no browser or network fetch is used during rendering.
