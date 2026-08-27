# Benchmark Metadata

## Streaming Throughput: ~12,400 samples/sec

- **Metric**: Samples scored per second in streaming mode
- **Method**: `StreamingDetector.score_sample()` called in tight loop
- **Feature dimensions**: 20 (float64)
- **Batch size**: 1 (single-sample scoring)
- **Detector config**: Z-score + IQR (IsolationForest refit disabled during measurement)
- **Hardware**: Apple M2 / 16GB RAM (local benchmark)
- **Python**: 3.12
- **Duration**: 10,000 samples measured after 5,000 warm-up
- **Percentile**: Median throughput across 5 runs
- **Commit**: (insert current HEAD commit)
- **Date**: 2026-08-27
- **Excludes**: IsolationForest refit time, network I/O, serialization
- **Note**: Throughput varies with feature dimensionality and hardware. This is a local benchmark result, not a universal performance guarantee.

## CIFAR-10 Label-Flip AUC: 0.53-0.56

- **Dataset**: CIFAR-10 training set (50,000 samples)
- **Attack**: Random label flip at 10% poison rate
- **Method**: Feature-space ensemble (Z-score + IQR + IsolationForest)
- **Feature extraction**: Raw flattened pixel values (3072 dimensions)
- **Script**: `benchmark/cifar10_label_flip_benchmark.py`
- **Note**: Near-random performance is expected and documented. Feature-space methods cannot detect label-only corruption.
