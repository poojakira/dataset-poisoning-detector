# RUNBOOK — dataset-poisoning-detector

## Prerequisites

- Python 3.9+ (local) OR Docker 20.10+
- Dataset in CSV format with labeled columns

## Install (Local)

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Install (Docker)

```bash
docker build -t poisoning-detector .
```

## Run Detection (Batch)

```bash
python detect.py --dataset data/training_set.csv --output results/report.json
```

Docker:
```bash
docker run --rm -v $(pwd)/data:/app/data poisoning-detector --dataset /app/data/training_set.csv
```

## Run Detection (Streaming Mode)

```bash
python detect.py --stream --input-dir data/incoming/ --poll-interval 30
```

Monitors `incoming/` for new CSVs and scores them on arrival. Results append to `results/stream_log.jsonl`.

## Interpret Results

| Field | Meaning |
|-------|---------|
| `outlier_score` | Per-sample anomaly score (higher = more suspicious) |
| `flagged` | Boolean — sample exceeds threshold |
| `auc` | Detector's overall AUC (~0.53 baseline; improve with tuning) |

- AUC 0.53 is near random — expected on clean data or subtle attacks
- Flag rate >5% on known-clean data → lower sensitivity with `--threshold`
- Review flagged samples manually before removing from training set

## Test

```bash
pytest tests/ -v
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Low AUC on known-poisoned data | Try `--method isolation_forest` or tune `--contamination` |
| Docker OOM | Increase memory: `docker run --memory=4g ...` |
| Streaming misses files | Check `--poll-interval` and file permissions |
| CSV parse errors | Ensure UTF-8 encoding, no BOM, consistent delimiters |
