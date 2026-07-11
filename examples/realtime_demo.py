"""
Real-Time Poisoning Detection Demo

Simulates a data pipeline where training samples arrive one at a time.
Injects poisoned samples at random intervals and shows live detection output.

Usage:
    python examples/realtime_demo.py

This demonstrates:
    - StreamingDetector scoring individual samples in real-time
    - ConceptDriftDetector flagging distribution shifts
    - SampleFingerprinter catching duplicate injection attacks
    - Live metrics output showing detection latency and throughput

Requirements:
    pip install -e ".[realtime]"
"""

import time
import random
import sys

import numpy as np

from poison_detector.stream import StreamingDetector
from poison_detector.drift import ConceptDriftDetector
from poison_detector.fingerprint import SampleFingerprinter
from poison_detector.metrics import (
    SAMPLES_PROCESSED,
    SAMPLES_POISONED,
    SCORING_LATENCY,
)


def generate_clean_sample(n_features: int = 10) -> list[float]:
    """Generate a sample from the normal training distribution."""
    return list(np.random.normal(0.0, 1.0, size=n_features))


def generate_poisoned_sample(n_features: int = 10, attack_type: str = "outlier") -> list[float]:
    """Generate a poisoned sample using various attack strategies."""
    if attack_type == "outlier":
        # Extreme point outlier -- easy to detect
        return list(np.random.normal(8.0, 0.5, size=n_features))
    elif attack_type == "cluster":
        # Cluster injection -- subtle but consistent offset
        return list(np.random.normal(2.5, 0.3, size=n_features))
    elif attack_type == "duplicate":
        # Exact duplicate injection
        return [1.0] * n_features
    else:
        # Label-flip proxy: looks normal but with one corrupted feature
        sample = list(np.random.normal(0.0, 1.0, size=n_features))
        sample[0] = 7.0  # single feature corruption
        return sample


def run_demo(
    n_samples: int = 500,
    poison_rate: float = 0.08,
    n_features: int = 10,
) -> None:
    """Run the real-time detection demo."""
    print("=" * 70)
    print("  REAL-TIME DATASET POISONING DETECTION DEMO")
    print("=" * 70)
    print(f"\n  Simulating {n_samples} samples | {poison_rate*100:.0f}% poison rate")
    print(f"  Features: {n_features} | Detection: ensemble + drift + fingerprint")
    print("-" * 70)

    # Initialize detectors
    detector = StreamingDetector(
        window_size=200,
        contamination=0.05,
        drift_sensitivity=0.01,
    )
    drift_detector = ConceptDriftDetector(delta=0.01)
    fingerprinter = SampleFingerprinter(similarity_threshold=0.95)

    # Seed the baseline with clean data
    print("\n[INIT] Seeding baseline with 100 clean samples...")
    baseline = [generate_clean_sample(n_features) for _ in range(100)]
    detector.update_baseline(baseline)
    for sample in baseline:
        fingerprinter.add_sample(sample)
    print("[INIT] Baseline established. Starting live detection.\n")

    # Statistics
    total_clean = 0
    total_poisoned = 0
    true_positives = 0
    false_positives = 0
    false_negatives = 0
    latencies: list[float] = []

    attack_types = ["outlier", "cluster", "duplicate", "feature_flip"]

    for i in range(n_samples):
        # Decide if this sample is poisoned
        is_actually_poisoned = random.random() < poison_rate

        if is_actually_poisoned:
            attack = random.choice(attack_types)
            sample = generate_poisoned_sample(n_features, attack)
            total_poisoned += 1
        else:
            sample = generate_clean_sample(n_features)
            attack = None
            total_clean += 1

        # Score the sample
        start = time.perf_counter()
        result = detector.score_sample(sample)
        drift_detector.update(sample)
        is_dup = fingerprinter.is_duplicate(sample)
        elapsed_ms = (time.perf_counter() - start) * 1000
        latencies.append(elapsed_ms)

        # Combine signals
        flagged = result.is_poisoned or is_dup

        # Track accuracy
        if flagged and is_actually_poisoned:
            true_positives += 1
        elif flagged and not is_actually_poisoned:
            false_positives += 1
        elif not flagged and is_actually_poisoned:
            false_negatives += 1

        # Register sample in fingerprinter
        fingerprinter.add_sample(sample)

        # Print detection events
        if flagged:
            drift_status = " [DRIFT]" if drift_detector.is_drifting() else ""
            dup_status = " [DUP]" if is_dup else ""
            actual = "POISON" if is_actually_poisoned else "CLEAN"
            print(
                f"  [{i+1:04d}] FLAGGED | score={result.score:.3f} | "
                f"actual={actual} | attack={attack or 'n/a'}"
                f"{drift_status}{dup_status}"
            )

        # Progress indicator every 100 samples
        if (i + 1) % 100 == 0 and not flagged:
            print(f"  [{i+1:04d}] ... processed {i+1}/{n_samples} samples")

    # Final report
    print("\n" + "=" * 70)
    print("  DETECTION RESULTS")
    print("=" * 70)
    precision = true_positives / max(true_positives + false_positives, 1)
    recall = true_positives / max(true_positives + false_negatives, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)

    print(f"\n  Total samples:     {n_samples}")
    print(f"  Clean samples:     {total_clean}")
    print(f"  Poisoned samples:  {total_poisoned}")
    print(f"\n  True positives:    {true_positives}")
    print(f"  False positives:   {false_positives}")
    print(f"  False negatives:   {false_negatives}")
    print(f"\n  Precision:         {precision:.3f}")
    print(f"  Recall:            {recall:.3f}")
    print(f"  F1 Score:          {f1:.3f}")

    if latencies:
        sorted_lat = sorted(latencies)
        p50 = sorted_lat[len(sorted_lat) // 2]
        p95 = sorted_lat[int(len(sorted_lat) * 0.95)]
        p99 = sorted_lat[int(len(sorted_lat) * 0.99)]
        print(f"\n  Latency p50:       {p50:.2f} ms")
        print(f"  Latency p95:       {p95:.2f} ms")
        print(f"  Latency p99:       {p99:.2f} ms")
        print(f"  Throughput:        {1000.0 / (sum(latencies) / len(latencies)):.0f} samples/sec")

    print(f"\n  Drift detected:    {drift_detector.is_drifting()}")
    print(f"  Drift score:       {drift_detector.get_drift_score():.4f}")
    stats = detector.get_stats()
    print(f"  Detector stats:    {stats}")
    print("\n" + "=" * 70)


if __name__ == "__main__":
    run_demo()
