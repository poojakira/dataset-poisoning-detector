# Reproduce the Work - Poster 04

**Repository:** `github.com/poojakira/dataset-poisoning-detector`
**Verified code snapshot:** `258a4646abcc66bed2c9ccb538fa2f593140e750`
**Verification:** Local Python 3.12 reproduction on 2026-10-01; CI coverage floor is 90%.

```bash
git clone https://github.com/poojakira/dataset-poisoning-detector.git
cd dataset-poisoning-detector
git checkout 258a4646abcc66bed2c9ccb538fa2f593140e750
python -m pip install -e ".[dev,realtime,kafka]"
pytest tests/ -q --cov=poison_detector --cov-report=term
python benchmark/cifar10_label_flip_benchmark.py
```

Expected current evidence: **200 passed**, **91.20% statement coverage**.

Expected committed benchmark cross-class F1: **0.55 / 0.595 / 0.6975** at 5% / 10% / 20% poison.
