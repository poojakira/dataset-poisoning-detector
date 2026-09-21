#!/usr/bin/env python3
"""Reproducible benchmark for the shipped dataset-poisoning-detector implementation.

Important evidence boundary:
- This script imports the real package from poison_detector.
- It never falls back to a test stub.
- --ci is a sanity/reproducibility gate, not a hardware performance SLA.
- Report throughput with its environment and configuration; do not generalize it.
"""

from __future__ import annotations

import argparse
import json
import math
import platform
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np

from poison_detector import StreamingDetector, detect


@dataclass
class BenchmarkResult:
    streaming_throughput_samples_per_sec: float
    streaming_latency_p50_ms: float
    streaming_latency_p99_ms: float
    streaming_samples: int
    feature_dimensions: int
    streaming_refit_enabled: bool
    ensemble_latency_ms: float
    ensemble_throughput_samples_per_sec: float
    efficacy_auc_backdoor: float
    efficacy_auc_label_flip: float
    efficacy_auc_subtle: float
    efficacy_samples_per_scenario: int
    python: str
    platform: str
    numpy: str
    ci_sanity_passed: bool
    timestamp_utc: str
    notes: str


def generate_benchmark_dataset(
    n_clean: int,
    n_poisoned: int,
    dim: int,
    poison_type: str,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    clean = rng.normal(0.0, 1.0, (n_clean, dim))
    clean_labels = rng.integers(0, 10, n_clean)

    poisoned = rng.normal(0.0, 1.0, (n_poisoned, dim))
    poison_labels = np.zeros(n_poisoned, dtype=int)

    if poison_type == "backdoor":
        width = min(8, dim)
        poisoned[:, :width] = 8.0 + rng.uniform(0.0, 1.0, (n_poisoned, width))
    elif poison_type == "label_flip":
        poisoned = clean[:n_poisoned].copy()
        poison_labels = (clean_labels[:n_poisoned] + 1) % 10
    elif poison_type == "subtle":
        poisoned[:, : min(4, dim)] += 1.5
    else:
        raise ValueError(f"unknown poison_type: {poison_type}")

    features = np.vstack([clean, poisoned])
    labels = np.concatenate([clean_labels, poison_labels])
    truth = np.concatenate(
        [np.zeros(n_clean, dtype=int), np.ones(n_poisoned, dtype=int)]
    )
    order = rng.permutation(len(features))
    return features[order], labels[order], truth[order]


def compute_auc(y_true: np.ndarray, y_score: np.ndarray) -> float:
    """Rank-based ROC AUC without an additional dependency."""
    y_true = np.asarray(y_true, dtype=int)
    y_score = np.asarray(y_score, dtype=float)
    n_pos = int(y_true.sum())
    n_neg = int(len(y_true) - n_pos)
    if n_pos == 0 or n_neg == 0:
        return 0.5

    order = np.argsort(y_score)
    ranks = np.empty_like(order, dtype=float)
    ranks[order] = np.arange(1, len(y_score) + 1, dtype=float)
    pos_rank_sum = float(ranks[y_true == 1].sum())
    auc = (pos_rank_sum - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)
    return float(auc)


def benchmark_streaming(n_samples: int, dim: int) -> dict[str, float]:
    # This is deliberately a no-refit fast-path microbenchmark.
    detector = StreamingDetector(
        refit_interval=n_samples + 1,
        window_size=max(n_samples + 100, 1000),
    )
    rng = np.random.default_rng(0)
    samples = rng.normal(0.0, 1.0, (n_samples + 100, dim))

    for row in samples[:100]:
        detector.score_sample(row)

    latencies: list[float] = []
    started = time.perf_counter()
    for row in samples[100:]:
        t0 = time.perf_counter()
        detector.score_sample(row)
        latencies.append((time.perf_counter() - t0) * 1000.0)
    elapsed = time.perf_counter() - started

    arr = np.asarray(latencies, dtype=float)
    return {
        "throughput": n_samples / elapsed,
        "p50_ms": float(np.percentile(arr, 50)),
        "p99_ms": float(np.percentile(arr, 99)),
    }


def benchmark_ensemble(n_samples: int, dim: int) -> dict[str, float]:
    rng = np.random.default_rng(7)
    features = rng.normal(0.0, 1.0, (n_samples, dim)).tolist()
    started = time.perf_counter()
    detect(features, method="ensemble")
    elapsed = time.perf_counter() - started
    return {
        "latency_ms": elapsed * 1000.0,
        "throughput": n_samples / elapsed,
    }


def benchmark_efficacy(n_total: int, dim: int) -> dict[str, float]:
    n_poisoned = max(10, n_total // 20)
    n_clean = n_total - n_poisoned
    out: dict[str, float] = {}
    for poison_type in ("backdoor", "label_flip", "subtle"):
        features, _labels, truth = generate_benchmark_dataset(
            n_clean=n_clean,
            n_poisoned=n_poisoned,
            dim=dim,
            poison_type=poison_type,
        )
        report = detect(features.tolist(), method="ensemble")
        scores = np.asarray([r.anomaly_score for r in report.per_sample], dtype=float)
        out[poison_type] = compute_auc(truth, scores)
    return out


def run_all(stream_samples: int, dim: int, efficacy_samples: int) -> BenchmarkResult:
    streaming = benchmark_streaming(stream_samples, dim)
    ensemble = benchmark_ensemble(efficacy_samples, dim)
    efficacy = benchmark_efficacy(efficacy_samples, dim)

    numeric = [
        streaming["throughput"],
        streaming["p50_ms"],
        streaming["p99_ms"],
        ensemble["latency_ms"],
        ensemble["throughput"],
        *efficacy.values(),
    ]
    sanity = all(math.isfinite(v) for v in numeric) and streaming["throughput"] > 0

    return BenchmarkResult(
        streaming_throughput_samples_per_sec=round(streaming["throughput"], 2),
        streaming_latency_p50_ms=round(streaming["p50_ms"], 4),
        streaming_latency_p99_ms=round(streaming["p99_ms"], 4),
        streaming_samples=stream_samples,
        feature_dimensions=dim,
        streaming_refit_enabled=False,
        ensemble_latency_ms=round(ensemble["latency_ms"], 2),
        ensemble_throughput_samples_per_sec=round(ensemble["throughput"], 2),
        efficacy_auc_backdoor=round(efficacy["backdoor"], 4),
        efficacy_auc_label_flip=round(efficacy["label_flip"], 4),
        efficacy_auc_subtle=round(efficacy["subtle"], 4),
        efficacy_samples_per_scenario=efficacy_samples,
        python=platform.python_version(),
        platform=platform.platform(),
        numpy=np.__version__,
        ci_sanity_passed=sanity,
        timestamp_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        notes=(
            "Streaming number is a no-refit score_sample microbenchmark. "
            "It excludes periodic IsolationForest refits, network I/O, serialization, "
            "Kafka, Redis, and API overhead. Efficacy uses the shipped ensemble on "
            "synthetic fixtures and is not a real-world detection rate."
        ),
    )


def main() -> dict:
    parser = argparse.ArgumentParser(description="Dataset poisoning benchmark")
    parser.add_argument("--output", "-o", type=Path)
    parser.add_argument("--ci", action="store_true")
    parser.add_argument("--stream-samples", type=int, default=10_000)
    parser.add_argument("--dim", type=int, default=20)
    parser.add_argument("--efficacy-samples", type=int, default=1_000)
    args = parser.parse_args()

    result = run_all(args.stream_samples, args.dim, args.efficacy_samples)
    report = asdict(result)
    rendered = json.dumps(report, indent=2)
    print(rendered)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")

    if args.ci and not result.ci_sanity_passed:
        print("Benchmark sanity gate failed", file=sys.stderr)
        raise SystemExit(1)
    return report


if __name__ == "__main__":
    main()
