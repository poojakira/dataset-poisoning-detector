# Runbook — Dataset Poisoning Detector

## Prerequisites

- Python 3.10+
- pip or uv

## Setup

```bash
git clone https://github.com/poojakira/dataset-poisoning-detector.git
cd dataset-poisoning-detector
python -m venv .venv

# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

pip install -e ".[dev]"
```

## Run Tests

```bash
pytest tests/ -v
```

## Basic Usage

```python
from poison_detector import detect

# Pass your training data as a numpy array or list of feature vectors
results = detect(training_data, contamination=0.05)
print(results.flagged_indices)
print(results.scores)
```

## Run the Evaluation Script

This reproduces the CIFAR-10 label-flip benchmark (ROC-AUC ~0.53-0.56):

```bash
python scripts/eval_detector.py
```

Note: Requires CIFAR-10 data. First run will download it (~170MB).

## Run the Streaming API

```bash
python -m poison_detector.api
# Runs on http://localhost:8000
# Docs at http://localhost:8000/docs
```

## Docker

```bash
docker compose up -d
# API available at http://localhost:8000
```

## View the Dashboard

The dashboard shows simulated data (not live detections):

```bash
python -m http.server 8080 --directory dashboard
# Open http://localhost:8080
```

Or view hosted: https://poojakira.github.io/mlsec-dashboards/dataset-poisoning-detector/

## Project Commands

| Command | What it does |
|---------|-------------|
| `pip install -e ".[dev]"` | Install with dev dependencies |
| `pytest tests/ -v` | Run all tests |
| `pytest tests/ --cov=src` | Run tests with coverage |
| `ruff check .` | Lint |
| `ruff format .` | Format |
| `python scripts/eval_detector.py` | Run CIFAR-10 benchmark |

## Known Limitations

- ROC-AUC is ~0.53-0.56 on CIFAR-10 label-flip (modestly above chance)
- False positive rate ~5% at default contamination setting
- This is a screening tool, not a definitive classifier
- Flagged samples always require human review
