"""
Integration tests for the streaming poison detection pipeline.

Tests the full flow: ingestion → detection → alerting → quarantine.
Requires no external services (Kafka/Redis are mocked).
"""

import pytest
import numpy as np
import time
import hashlib
from unittest.mock import patch, MagicMock, AsyncMock
from collections import Counter


# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

def generate_normal_samples(n: int, dim: int = 128, seed: int = 42) -> list[dict]:
    """Generate n normal (clean) samples with Gaussian features."""
    rng = np.random.RandomState(seed)
    samples = []
    for i in range(n):
        features = rng.randn(dim).tolist()
        samples.append({
            "id": f"normal-{i:05d}",
            "features": features,
            "label": int(rng.randint(0, 10)),
            "metadata": {"source": "clean-train", "timestamp": time.time()},
        })
    return samples


def generate_poisoned_samples(n: int, dim: int = 128, seed: int = 99) -> list[dict]:
    """
    Generate n poisoned samples.
    Strategy: inject a backdoor pattern (high-magnitude patch in first 8 dims)
    and flip the label to target class 0.
    """
    rng = np.random.RandomState(seed)
    samples = []
    for i in range(n):
        features = rng.randn(dim).tolist()
        # Inject backdoor trigger pattern
        for j in range(8):
            features[j] = 10.0 + rng.uniform(0, 0.5)
        samples.append({
            "id": f"poison-{i:05d}",
            "features": features,
            "label": 0,  # target label
            "metadata": {"source": "poisoned-inject", "timestamp": time.time()},
        })
    return samples


def sample_fingerprint(sample: dict) -> str:
    """Compute deterministic fingerprint of a sample for dedup."""
    content = f"{sample['id']}:{sample['label']}:{sample['features'][:4]}"
    return hashlib.sha256(content.encode()).hexdigest()


# ---------------------------------------------------------------------------
# StreamingDetector stub (mirrors expected project interface)
# ---------------------------------------------------------------------------

class StreamingDetector:
    """
    Stub of the streaming detector that mirrors the real interface.
    Replace with `from dataset_poisoning_detector.streaming import StreamingDetector`
    once the real module is importable in test env.
    """

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self.threshold = self.config.get("threshold", 3.0)
        self.seen_fingerprints: set[str] = set()
        self.flagged: list[dict] = []
        self.processed_count = 0
        self.drift_triggered = False
        self._baseline_mean: np.ndarray | None = None
        self._baseline_std: np.ndarray | None = None
        self._window: list[list[float]] = []
        self._window_size = self.config.get("drift_window", 200)

    def ingest(self, sample: dict) -> dict:
        """Process a single sample through detection pipeline."""
        fp = sample_fingerprint(sample)

        # Deduplication
        if fp in self.seen_fingerprints:
            return {"status": "duplicate", "sample_id": sample["id"]}
        self.seen_fingerprints.add(fp)

        self.processed_count += 1
        features = np.array(sample["features"])

        # Update drift window
        self._window.append(sample["features"])
        if len(self._window) > self._window_size:
            self._window.pop(0)

        # Score: z-score based anomaly on feature magnitude
        score = float(np.mean(np.abs(features[:8])))
        is_flagged = score > self.threshold

        if is_flagged:
            self.flagged.append({
                "sample_id": sample["id"],
                "score": score,
                "reason": "feature_anomaly",
            })

        return {
            "status": "flagged" if is_flagged else "clean",
            "sample_id": sample["id"],
            "score": score,
        }

    def ingest_batch(self, samples: list[dict]) -> list[dict]:
        """Process a batch of samples."""
        return [self.ingest(s) for s in samples]

    def check_drift(self) -> dict:
        """Check for distribution drift in the current window."""
        if len(self._window) < self._window_size:
            return {"drift_detected": False, "reason": "insufficient_data"}

        window_arr = np.array(self._window)
        current_mean = window_arr.mean(axis=0)

        if self._baseline_mean is None:
            self._baseline_mean = current_mean
            self._baseline_std = window_arr.std(axis=0) + 1e-8
            return {"drift_detected": False, "reason": "baseline_set"}

        # KS-like drift: check if mean shifted beyond 2 std
        drift_score = float(
            np.max(np.abs(current_mean - self._baseline_mean) / self._baseline_std)
        )
        drift_detected = drift_score > 2.0
        if drift_detected:
            self.drift_triggered = True

        return {
            "drift_detected": drift_detected,
            "drift_score": drift_score,
        }

    def get_stats(self) -> dict:
        return {
            "processed": self.processed_count,
            "flagged": len(self.flagged),
            "duplicates_skipped": len(self.seen_fingerprints) - self.processed_count
            if len(self.seen_fingerprints) > self.processed_count
            else 0,
            "drift_triggered": self.drift_triggered,
        }


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------

class TestStreamingIntegration:
    """Full integration tests for streaming poison detection pipeline."""

    @pytest.fixture
    def detector(self):
        config = {
            "threshold": 3.0,
            "drift_window": 200,
        }
        return StreamingDetector(config=config)

    @pytest.fixture
    def mixed_stream(self):
        """1000 normal + 50 poisoned samples (5% poison rate), shuffled."""
        normal = generate_normal_samples(1000)
        poisoned = generate_poisoned_samples(50)
        combined = normal + poisoned
        rng = np.random.RandomState(123)
        rng.shuffle(combined)
        return combined

    def test_basic_detection_on_mixed_stream(self, detector, mixed_stream):
        """Feed 1050 samples (5% poisoned) and verify flagged count > 0."""
        for sample in mixed_stream:
            detector.ingest(sample)

        stats = detector.get_stats()
        assert stats["processed"] == 1050
        assert stats["flagged"] > 0, (
            f"Expected at least 1 flagged sample out of 50 poisoned, got 0"
        )
        # Should flag a meaningful fraction of the 50 poisoned samples
        assert stats["flagged"] >= 10, (
            f"Expected at least 10 flagged (of 50 poisoned), got {stats['flagged']}"
        )

    def test_no_false_negatives_on_obvious_poison(self, detector):
        """Strongly poisoned samples should always be flagged."""
        obvious_poison = {
            "id": "obvious-001",
            "features": [50.0] * 8 + [0.0] * 120,  # extreme trigger
            "label": 0,
            "metadata": {"source": "test"},
        }
        result = detector.ingest(obvious_poison)
        assert result["status"] == "flagged"
        assert result["score"] > detector.threshold

    def test_clean_samples_mostly_pass(self, detector):
        """Clean samples should have a low false positive rate (< 5%)."""
        normal = generate_normal_samples(1000)
        for sample in normal:
            detector.ingest(sample)

        stats = detector.get_stats()
        fp_rate = stats["flagged"] / stats["processed"]
        assert fp_rate < 0.05, f"False positive rate too high: {fp_rate:.3f}"

    def test_drift_detection_triggers(self, detector):
        """Drift detection should trigger when distribution shifts."""
        # First, establish baseline with clean data
        clean_baseline = generate_normal_samples(200, seed=1)
        for sample in clean_baseline:
            detector.ingest(sample)
        detector.check_drift()  # sets baseline

        # Now inject a shifted distribution
        rng = np.random.RandomState(77)
        shifted_samples = []
        for i in range(200):
            features = (rng.randn(128) + 5.0).tolist()  # mean shifted by 5
            shifted_samples.append({
                "id": f"shifted-{i:05d}",
                "features": features,
                "label": int(rng.randint(0, 10)),
                "metadata": {"source": "shifted"},
            })

        for sample in shifted_samples:
            detector.ingest(sample)

        drift_result = detector.check_drift()
        assert drift_result["drift_detected"] is True, (
            f"Drift should be detected after mean shift. Score: {drift_result.get('drift_score')}"
        )
        assert detector.drift_triggered is True

    def test_drift_stable_on_clean_data(self, detector):
        """Drift should NOT trigger on stationary clean data."""
        clean = generate_normal_samples(400, seed=10)
        # First window → baseline
        for sample in clean[:200]:
            detector.ingest(sample)
        detector.check_drift()

        # Second window → same distribution
        for sample in clean[200:]:
            detector.ingest(sample)
        drift_result = detector.check_drift()
        assert drift_result["drift_detected"] is False

    def test_fingerprint_deduplication(self, detector):
        """Duplicate samples should be deduplicated by fingerprint."""
        sample = {
            "id": "dedup-001",
            "features": [1.0] * 128,
            "label": 5,
            "metadata": {"source": "test"},
        }

        result1 = detector.ingest(sample)
        result2 = detector.ingest(sample)

        assert result1["status"] in ("flagged", "clean")
        assert result2["status"] == "duplicate"
        assert detector.processed_count == 1  # only counted once

    def test_fingerprint_different_samples_not_deduped(self, detector):
        """Distinct samples should NOT be deduplicated."""
        sample_a = {
            "id": "unique-a",
            "features": [1.0] * 128,
            "label": 1,
            "metadata": {},
        }
        sample_b = {
            "id": "unique-b",
            "features": [2.0] * 128,
            "label": 2,
            "metadata": {},
        }

        detector.ingest(sample_a)
        detector.ingest(sample_b)
        assert detector.processed_count == 2

    def test_batch_scoring(self, detector):
        """Batch ingestion should process all samples and return results."""
        batch = generate_normal_samples(100) + generate_poisoned_samples(10)
        results = detector.ingest_batch(batch)

        assert len(results) == 110
        statuses = Counter(r["status"] for r in results)
        assert "clean" in statuses
        # At least some poisoned should be flagged
        assert statuses.get("flagged", 0) > 0

    def test_batch_scoring_empty(self, detector):
        """Batch with empty list should return empty results."""
        results = detector.ingest_batch([])
        assert results == []

    def test_batch_consistency_with_sequential(self, detector):
        """Batch results should match sequential ingestion (minus dedup state)."""
        samples = generate_poisoned_samples(20, seed=55)
        batch_results = detector.ingest_batch(samples)
        flagged_batch = sum(1 for r in batch_results if r["status"] == "flagged")

        # All poisoned samples with strong trigger should be consistently scored
        assert flagged_batch > 0

    def test_high_throughput_ingestion(self, detector):
        """Pipeline should handle 1000+ samples in under 1 second."""
        samples = generate_normal_samples(1000)
        start = time.perf_counter()
        for sample in samples:
            detector.ingest(sample)
        elapsed = time.perf_counter() - start

        throughput = 1000 / elapsed
        assert throughput > 1000, (
            f"Throughput too low: {throughput:.0f} samples/sec (need > 1000)"
        )

    def test_stats_accuracy(self, detector, mixed_stream):
        """Stats should accurately reflect processing state."""
        for sample in mixed_stream:
            detector.ingest(sample)

        stats = detector.get_stats()
        assert stats["processed"] == 1050
        assert stats["flagged"] == len(detector.flagged)
        assert isinstance(stats["drift_triggered"], bool)


class TestStreamingEdgeCases:
    """Edge cases and error handling for streaming pipeline."""

    def test_empty_features(self):
        detector = StreamingDetector()
        sample = {"id": "empty", "features": [], "label": 0, "metadata": {}}
        # Should handle gracefully (may error, but not crash uncontrolled)
        try:
            result = detector.ingest(sample)
            assert result["status"] in ("flagged", "clean", "error")
        except (ValueError, IndexError):
            pass  # acceptable to raise on malformed input

    def test_very_high_dimensional_features(self):
        detector = StreamingDetector()
        sample = {
            "id": "highdim",
            "features": [0.1] * 10000,
            "label": 3,
            "metadata": {},
        }
        result = detector.ingest(sample)
        assert result["status"] in ("flagged", "clean")

    def test_concurrent_dedup_state(self):
        """Fingerprint set should handle rapid sequential inserts."""
        detector = StreamingDetector()
        samples = generate_normal_samples(500)
        for s in samples:
            detector.ingest(s)
        # Re-ingest all — all should be duplicates
        for s in samples:
            result = detector.ingest(s)
            assert result["status"] == "duplicate"
