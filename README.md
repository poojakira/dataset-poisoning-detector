# dataset-poisoning-detector

Statistical anomaly detection for ML training data. Ensemble of Z-score, IQR fencing, and Isolation Forest with majority vote. Streaming mode processes 12,400 samples/sec at p50=0.08ms.

[![CI](https://github.com/poojakira/dataset-poisoning-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/poojakira/dataset-poisoning-detector/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![MIT](https://img.shields.io/badge/license-MIT-green)

## Honest Assessment

**ROC-AUC 0.53–0.56 on CIFAR-10 label-flip benchmark**  -  barely above random chance. The feature-space approach fundamentally cannot catch clean-label attacks. The streaming infrastructure works well; the core detection algorithm needs replacement. Consider CleanLab or spectral signatures for production use.

This is a screening tool for finding statistical outliers that warrant human review. It's not a defense.

## What It Does

- Three methods (Z-score, IQR, Isolation Forest) + ensemble majority vote
- Streaming mode: 12,400 samples/sec, p50=0.08ms, p99=0.31ms
- Batch mode for static datasets
- Docker + Grafana for monitoring
- PyPI installable

## Quick Start

```bash
pip install dataset-poisoning-detector
python -c "
from poison_detector import detect
import numpy as np
X = np.random.randn(1000, 10); X[999] = [9.9]*10
report = detect(X, method='ensemble')
print(f'Flagged {report.poisoned_count}/{report.total_samples}')
"
```

## License

MIT.
