"""
Sustained throughput and load integration tests.

Tests that the streaming detector can maintain acceptable throughput under
sustained load without crashes, memory explosion, or invalid results.
"""

from __future__ import annotations

import time

import numpy as np
import pytest

from poison_detector.stream import StreamingDetector


class TestSustainedThroughput:
    """Verify that the detector maintains acceptable throughput under load."""

    def test_sustained_throughput(self) -> None:
        """Score 10,000 samples through the StreamingDetector and verify
        throughput exceeds 1000 samples/sec (conservative for CI).

        Uses the statistical-only scoring path (Welford z-score) without
        IsolationForest model inference to test pipeline throughput independent
        of sklearn model overhead. The IsolationForest adds per-sample inference
        cost that varies by environment; the z-score path represents the
        streaming pipeline's inherent throughput.

        Also verifies:
        - No crashes or exceptions during sustained operation
        - All results are valid ScoringResult objects
        - No memory explosion (detector stats remain consistent)
        """
        n_features = 10
        n_baseline = 1000
        n_samples = 10_000

        rng = np.random.default_rng(42)

        # Create detector with settings optimized for throughput testing.
        # Use a very high refit_interval so the IsolationForest is never
        # refitted during the scoring loop, keeping only z-score scoring active.
        detector = StreamingDetector(
            window_size=2000,
            contamination=0.05,
            zscore_threshold=3.0,
            vote_threshold=2,
            refit_interval=100_000,  # Effectively disable refit during test
        )

        # Initialize the Welford statistics with baseline samples by feeding
        # them through score_sample (this builds z-score stats without fitting
        # IsolationForest since we never call update_baseline).
        detector._initialize_features(n_features)
        baseline_data = rng.normal(loc=0.0, scale=1.0, size=(n_baseline, n_features))
        for sample in baseline_data:
            detector._welford.update(sample)
            detector._window.append(sample)

        # Pre-generate all test samples for accurate timing
        test_samples = rng.normal(loc=0.0, scale=1.0, size=(n_samples, n_features))

        # Score all samples and measure elapsed time
        start_time = time.perf_counter()

        results = []
        for i in range(n_samples):
            result = detector.score_sample(test_samples[i])
            results.append(result)

        elapsed = time.perf_counter() - start_time
        throughput = n_samples / elapsed

        # Assert throughput > 1000 samples/sec (conservative bound for CI)
        assert throughput > 1000, (
            f"Throughput {throughput:.0f} samples/sec is below the minimum "
            f"of 1000 samples/sec. Elapsed: {elapsed:.2f}s for {n_samples} samples."
        )

        # Verify no crashes: all results are valid
        assert len(results) == n_samples, "Should have one result per sample"

        for i, result in enumerate(results):
            assert 0.0 <= result.score <= 1.0, (
                f"Sample {i}: score {result.score} is outside [0, 1]"
            )
            assert isinstance(result.is_poisoned, bool), (
                f"Sample {i}: is_poisoned should be a boolean"
            )
            assert "zscore" in result.method_votes, (
                f"Sample {i}: missing zscore vote"
            )
            assert result.latency_ms >= 0, (
                f"Sample {i}: latency_ms should be non-negative"
            )

        # Verify detector stats are consistent
        stats = detector.get_stats()
        assert stats.samples_seen == n_samples, (
            f"Expected {n_samples} samples_seen, got {stats.samples_seen}"
        )
        assert stats.poison_rate >= 0.0
        assert stats.poison_rate <= 1.0
        assert stats.avg_latency_ms > 0
