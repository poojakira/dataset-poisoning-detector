# Runbook — Dataset Poisoning Detector

Step-by-step guide to run the dataset poisoning detection tool locally.

---

## Step 1: Prerequisites

- Python 3.10+ (`py --version` on Windows, `python3 --version` on Linux)
- pip (bundled with Python)
- Git
- ~200MB disk space (for CIFAR-10 download on first benchmark run)

---

## Step 2: Clone

**Windows (PowerShell):**
```powershell
cd C:\Users\pooja\repos
git clone https://github.com/poojakira/dataset-poisoning-detector.git
cd dataset-poisoning-detector
```

**Linux/macOS:**
```bash
cd ~/repos
git clone https://github.com/poojakira/dataset-poisoning-detector.git
cd dataset-poisoning-detector
```

---

## Step 3: Install

**Windows (PowerShell):**
```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

**Linux/macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
```

---

## Step 4: Run

**Basic usage (Python API):**

**Windows (PowerShell):**
```powershell
.\.venv\Scripts\python.exe -c "
from poison_detector import detect
import numpy as np

# Generate synthetic training data (1000 samples, 10 features)
data = np.random.randn(1000, 10).tolist()

# method: 'ensemble' (default), 'zscore', 'iqr', 'isolation', or 'spectral'
report = detect(data, method='ensemble')
print(f'Analyzed {report.total_samples} samples')
print(f'Flagged {report.poisoned_count} as poisoned')
print(f'Per-method votes: {report.method_scores}')
"
```

For label-flip attacks (the only method that detects them), pass labels and
use the spectral detector:
```powershell
.\.venv\Scripts\python.exe -c "
from poison_detector import detect
import numpy as np
data = np.random.randn(200, 10).tolist()
labels = ([0]*100) + ([1]*100)
report = detect(data, method='spectral', labels=labels)
print(f'Spectral flagged {report.poisoned_count}/{report.total_samples}')
"
```

**Run the CIFAR-10 evaluation benchmark:**
```powershell
.\.venv\Scripts\python.exe scripts/eval_detector.py
```

**Run the streaming API:**
```powershell
.\.venv\Scripts\python.exe -m poison_detector.api
# API available at http://localhost:8000
# Docs at http://localhost:8000/docs
```

**Linux/macOS:**
```bash
python scripts/eval_detector.py
python -m poison_detector.api
```

---

## Step 5: Expected Output

Evaluation benchmark (`scripts/eval_detector.py`):
```
[Eval] Loading CIFAR-10 dataset...
[Eval] Injecting label-flip poison (5% contamination)...
[Eval] Running detector...
[Eval] ROC-AUC: 0.53-0.56
[Eval] Precision @ 5% FPR: 0.08
[Eval] Flagged samples: 50/1000
[Eval] Results saved to: results/eval_cifar10.json
```

> **Note:** AUC ~0.53-0.56 is modestly above chance. This is a known limitation — the algorithm needs replacement for production use.

Streaming API:
```
INFO:     Started server process [XXXX]
INFO:     Uvicorn running on http://127.0.0.1:8000
```

---

## Step 6: Run Tests

**Windows (PowerShell):**
```powershell
.\.venv\Scripts\python.exe -m pytest tests/ -v
```

**Linux/macOS:**
```bash
pytest tests/ -v
```

**With coverage:**
```powershell
.\.venv\Scripts\python.exe -m pytest tests/ --cov=src --cov-report=term-missing
```

**Lint and format:**
```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format .
```

---

## Docker

```powershell
docker compose up -d
# API available at http://localhost:8000
# Docs at http://localhost:8000/docs
```

---

## View Dashboard

```powershell
py -m http.server 8080 --directory dashboard
# Open http://localhost:8080
```

Or view hosted: https://poojakira.github.io/mlsec-dashboards/dataset-poisoning-detector/

> **Note:** Dashboard shows simulated data — not connected to live detections.

---

## Available Commands

| Command | What it does |
|---------|-------------|
| `pip install -e ".[dev]"` | Install with dev dependencies |
| `pytest tests/ -v` | Run all tests |
| `pytest tests/ --cov=src` | Run tests with coverage |
| `ruff check .` | Lint |
| `ruff format .` | Format |
| `python scripts/eval_detector.py` | Run CIFAR-10 benchmark |
| `python -m poison_detector.api` | Start streaming API |
| `docker compose up -d` | Start API in Docker |

---

## Troubleshooting

### CIFAR-10 Download Fails

First run of `eval_detector.py` downloads CIFAR-10 (~170MB).

**Fix:**
1. Check internet connectivity.
2. If behind a proxy:
   ```powershell
   $env:HTTPS_PROXY = "http://your-proxy:port"
   ```
3. Manually download CIFAR-10 and place in the expected data directory.

---

### Low AUC Score (~0.53)

This is **expected behavior**, not a bug. The current algorithm performs only modestly above chance on CIFAR-10 label-flip attacks. The README documents this limitation.

---

### ImportError: No module named 'poison_detector'

**Fix:** Install in editable mode:
```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

---

### API Won't Start (Port 8000 in Use)

```powershell
# Check what's using port 8000
netstat -ano | findstr :8000

# Use a different port
.\.venv\Scripts\python.exe -m poison_detector.api --port 8001
```

---

### Docker Build Fails

Ensure Docker Desktop is running:
```powershell
docker info
# If this fails, start Docker Desktop
```

---

## Known Limitations

- ROC-AUC is ~0.53-0.56 on CIFAR-10 label-flip (modestly above chance)
- False positive rate ~5% at default contamination setting
- This is a screening/baseline tool — algorithm needs replacement for production
- Flagged samples always require human review
- Dashboard shows simulated data, not live detection results
