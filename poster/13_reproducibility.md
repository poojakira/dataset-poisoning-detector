# Reproduce the Work - Poster 04

**Repository:** `github.com/poojakira/dataset-poisoning-detector`  
**Verified code snapshot:** `ed38ad039a60a648c38a247e4136b34bbe287bda`  
**CI run:** `36783091096`

```bash
git clone https://github.com/poojakira/dataset-poisoning-detector.git
cd dataset-poisoning-detector
git checkout ed38ad039a60a648c38a247e4136b34bbe287bda
python -m pip install -e ".[dev,realtime,kafka]"
pytest tests/ -q --cov=poison_detector --cov-report=term
python benchmark/cifar10_label_flip_benchmark.py
```

Expected CI evidence: **162 passed**, **70.77% statement coverage**.

Expected committed benchmark cross-class F1: **0.55 / 0.595 / 0.6975** at 5% / 10% / 20% poison.
