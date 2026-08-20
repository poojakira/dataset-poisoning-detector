# dataset-poisoning-detector

This tool achieves ROC-AUC 0.53–0.56 on the CIFAR-10 label-flip benchmark, which is barely better than random chance (0.50). The feature-space statistical approach fundamentally cannot catch clean-label attacks. If you need production poisoning detection, use spectral signatures or tools like CleanLab instead.

## What It Actually Is

An ensemble of statistical outlier detectors (Z-score, IQR fencing, Isolation Forest) with majority vote. The streaming infrastructure works well (12,400 samples/sec, p50=0.08ms) but the core detection algorithm doesn't meaningfully distinguish poisoned from clean samples.

This is a screening tool for finding statistical outliers that warrant human review. It is not a defense against data poisoning.

## What It Does

- Three methods (Z-score, IQR, Isolation Forest) + ensemble majority vote
- Streaming mode: 12,400 samples/sec, p50=0.08ms, p99=0.31ms
- Batch mode for static datasets
- Docker + Grafana for monitoring

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
