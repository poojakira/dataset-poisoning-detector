# Reproduce the Work — Dataset Poisoning Detector Poster 04

**Current code snapshot:** `45740923aa16539909a7ae993104a80ecfe85e0b`  
**Successful Python 3.12 main CI:** [run 38502623976](https://github.com/poojakira/dataset-poisoning-detector/actions/runs/38502623976) (October 14, 2026 UTC)

```bash
git clone https://github.com/poojakira/dataset-poisoning-detector.git
cd dataset-poisoning-detector
git checkout 45740923aa16539909a7ae993104a80ecfe85e0b
python -m pip install -e ".[dev,realtime,kafka]"
pytest tests/ -q --cov=poison_detector --cov-report=term
```

Expected **226 passed, 91.75% statement coverage**, including 186 production-facing tests and 40 legacy stub/demo tests. CI requires 90% coverage.

Synthetic label-flip F1 at contamination 5%, 10%, 20% was **0.55 / 0.595 / 0.6975** in the separately committed benchmark artifact; it was not rerun as part of that test job and does not establish field performance. The original October 4 historical snapshot was 200 passed, 91.20% coverage.
