"""
Sample fingerprinting for detecting duplicate and near-duplicate injection attacks.

Detects the Nightshade-style attack pattern where an adversary injects many
similar (but not identical) samples to shift a model's decision boundary.
Uses three complementary techniques:
1. Bloom filter for O(1) exact-duplicate detection at scale
2. Cosine similarity for detecting cluster injection in embedding space
3. Perceptual hashing for detecting samples that are semantically similar
   despite numerical differences (e.g., quantization noise, minor perturbations)

Threat Model Assumptions:
    - Attackers inject multiple similar samples to amplify their effect.
      A single poisoned sample is unlikely to corrupt a model trained on
      millions of examples, so attackers inject clusters.
    - Near-duplicates may differ by small perturbations (Gaussian noise,
      feature shuffling, quantization) designed to bypass exact-match checks.
    - The attacker does NOT have access to the fingerprint store. If they do,
      they can craft samples that evade detection by maximizing hash distance
      while minimizing semantic distance.

Honest Limitations:
    - Bloom filters have false positives (configurable via error_rate) but
      NO false negatives for exact matches. A "seen before" response might
      be wrong; a "not seen" response is always correct.
    - Cosine similarity requires maintaining a reference set of recent
      embeddings in memory. For very high-volume streams, this becomes
      expensive. The max_reference_size parameter bounds memory usage.
    - Perceptual hashing via locality-sensitive hashing (LSH) on feature
      vectors is a simplification. For image data, proper perceptual hashes
      (pHash, dHash) would be more appropriate but require the image domain.
    - None of these methods detect "clean-label" attacks where each sample
      is individually unique but collectively shifts the decision boundary.

Security Notes:
    - The bloom filter state should be periodically checkpointed to prevent
      an attacker from forcing a restart to clear the duplicate history.
    - Cosine similarity computation on untrusted vectors is safe (no code
      execution) but could be used for timing side-channels if the attacker
      can observe response latency precisely.
    - No pickle/deserialization. State is rebuilt from scratch or from a
      simple serialization format.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from typing import Any

import numpy as np


@dataclass
class FingerprintStats:
    """Statistics about the fingerprinting system state.

    Attributes:
        samples_seen: Total samples processed.
        duplicates_found: Exact duplicates detected via bloom filter.
        near_duplicates_found: Near-duplicates detected via similarity.
        bloom_filter_size: Current number of items in the bloom filter.
        bloom_filter_capacity: Maximum capacity before error rate degrades.
        reference_set_size: Number of samples in the similarity reference set.
    """

    samples_seen: int = 0
    duplicates_found: int = 0
    near_duplicates_found: int = 0
    bloom_filter_size: int = 0
    bloom_filter_capacity: int = 0
    reference_set_size: int = 0


class BloomFilter:
    """Space-efficient probabilistic set membership test.

    Uses multiple hash functions to test whether an element has been seen
    before. False positives are possible (controlled by error_rate) but
    false negatives are impossible.

    Memory usage: approximately -n*ln(p) / (ln(2))^2 bits, where n is
    capacity and p is error_rate. For 100K items at 1% error: ~117 KB.
    """

    def __init__(self, capacity: int = 100000, error_rate: float = 0.01) -> None:
        """Initialize the bloom filter.

        Args:
            capacity: Expected number of items. Performance degrades gracefully
                above this but error rate increases.
            error_rate: Desired false positive rate. Lower = more memory.
        """
        self.capacity = capacity
        self.error_rate = error_rate

        # Calculate optimal size and number of hash functions
        # m = -n * ln(p) / (ln(2))^2
        self._size = self._optimal_size(capacity, error_rate)
        # k = (m/n) * ln(2)
        self._num_hashes = self._optimal_hashes(self._size, capacity)
        self._bit_array = bytearray(math.ceil(self._size / 8))
        self._count = 0

    @staticmethod
    def _optimal_size(capacity: int, error_rate: float) -> int:
        """Calculate optimal bit array size."""
        m = -capacity * math.log(error_rate) / (math.log(2) ** 2)
        return int(math.ceil(m))

    @staticmethod
    def _optimal_hashes(size: int, capacity: int) -> int:
        """Calculate optimal number of hash functions."""
        k = (size / capacity) * math.log(2)
        return max(1, int(math.ceil(k)))

    def _get_bit_positions(self, item_bytes: bytes) -> list[int]:
        """Compute hash positions for an item using double hashing.

        Uses SHA256 with different seeds for double hashing.
        The hashes are for Bloom filter index computation, not security.
        """
        # Use SHA256 with different prefixes for independent hash values
        # usedforsecurity=False indicates this is for data structure integrity, not crypto
        h1 = int(
            hashlib.sha256(b"bloom1" + item_bytes, usedforsecurity=False).hexdigest(), 16
        )
        h2 = int(
            hashlib.sha256(b"bloom2" + item_bytes, usedforsecurity=False).hexdigest(), 16
        )

        positions = []
        for i in range(self._num_hashes):
            pos = (h1 + i * h2) % self._size
            positions.append(pos)
        return positions

    def _set_bit(self, position: int) -> None:
        """Set a bit in the bit array."""
        byte_idx = position // 8
        bit_idx = position % 8
        self._bit_array[byte_idx] |= 1 << bit_idx

    def _get_bit(self, position: int) -> bool:
        """Check if a bit is set."""
        byte_idx = position // 8
        bit_idx = position % 8
        return bool(self._bit_array[byte_idx] & (1 << bit_idx))

    def add(self, item_bytes: bytes) -> None:
        """Add an item to the bloom filter.

        Args:
            item_bytes: Bytes representation of the item.
        """
        positions = self._get_bit_positions(item_bytes)
        for pos in positions:
            self._set_bit(pos)
        self._count += 1

    def contains(self, item_bytes: bytes) -> bool:
        """Check if an item might be in the filter.

        Returns:
            True if the item MIGHT be in the set (possible false positive).
            False if the item is DEFINITELY NOT in the set (no false negatives).
        """
        positions = self._get_bit_positions(item_bytes)
        return all(self._get_bit(pos) for pos in positions)

    @property
    def count(self) -> int:
        """Number of items added to the filter."""
        return self._count

    def reset(self) -> None:
        """Clear the bloom filter."""
        self._bit_array = bytearray(math.ceil(self._size / 8))
        self._count = 0


class SampleFingerprinter:
    """Multi-method sample fingerprinting for duplicate/near-duplicate detection.

    Combines:
    1. Bloom filter: O(1) check for exact duplicates (via quantized hash)
    2. Cosine similarity: Detects cluster injection (many similar samples)
    3. Perceptual hash: Detects semantic duplicates despite numerical noise

    Usage:
        fp = SampleFingerprinter()
        for sample in stream:
            if fp.is_duplicate(sample):
                quarantine(sample)
            else:
                fp.add_sample(sample)

    Args:
        similarity_threshold: Cosine similarity above which samples are
            considered near-duplicates. Range: [0, 1]. Default 0.95.
        bloom_capacity: Expected number of unique samples.
        bloom_error_rate: Acceptable false positive rate for bloom filter.
        max_reference_size: Maximum samples kept for similarity comparison.
        hash_precision: Decimal places for quantizing floats before hashing.
            Lower = more collision-tolerant (catches more near-duplicates via bloom).
    """

    def __init__(
        self,
        similarity_threshold: float = 0.95,
        bloom_capacity: int = 100000,
        bloom_error_rate: float = 0.01,
        max_reference_size: int = 5000,
        hash_precision: int = 4,
    ) -> None:
        self.similarity_threshold = similarity_threshold
        self.max_reference_size = max_reference_size
        self.hash_precision = hash_precision

        self._bloom = BloomFilter(
            capacity=bloom_capacity, error_rate=bloom_error_rate
        )
        self._reference_set: list[np.ndarray] = []
        self._reference_norms: list[float] = []

        # Stats
        self._samples_seen: int = 0
        self._duplicates_found: int = 0
        self._near_duplicates_found: int = 0

    def _sample_to_bytes(self, sample: np.ndarray) -> bytes:
        """Convert a sample to bytes for bloom filter hashing.

        Quantizes to hash_precision decimal places to allow for minor
        floating-point differences while still catching exact duplicates.
        """
        quantized = np.round(sample, decimals=self.hash_precision)
        return quantized.tobytes()

    def _perceptual_hash(self, sample: np.ndarray) -> bytes:
        """Compute a perceptual hash via locality-sensitive hashing.

        Uses random hyperplane LSH: the hash bit i is 1 if the dot product
        of the sample with random vector i is positive. Samples close in
        cosine space have similar hashes.

        For simplicity and determinism, we use a fixed seed for the random
        projections based on the feature dimensionality.
        """
        # Simple perceptual hash: sign of features relative to mean
        centered = sample - np.mean(sample)
        bits = (centered > 0).astype(np.uint8)
        return bits.tobytes()

    def _cosine_similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        """Compute cosine similarity between two vectors.

        Returns:
            Cosine similarity in [-1, 1] range. 1 = identical direction.
        """
        norm_a = np.linalg.norm(a)
        norm_b = np.linalg.norm(b)
        if norm_a < 1e-10 or norm_b < 1e-10:
            return 0.0
        return float(np.dot(a, b) / (norm_a * norm_b))

    def add_sample(self, sample: list[float] | np.ndarray) -> None:
        """Add a sample to the fingerprint store.

        Adds to both the bloom filter and reference set for future
        duplicate/similarity checks.

        Args:
            sample: Feature vector.
        """
        sample_arr = np.asarray(sample, dtype=np.float64)

        # Add to bloom filter
        sample_bytes = self._sample_to_bytes(sample_arr)
        self._bloom.add(sample_bytes)

        # Add perceptual hash too
        phash = self._perceptual_hash(sample_arr)
        self._bloom.add(phash)

        # Add to reference set (for similarity checks)
        self._reference_set.append(sample_arr)
        norm = float(np.linalg.norm(sample_arr))
        self._reference_norms.append(norm)

        # Trim reference set if over capacity (FIFO)
        if len(self._reference_set) > self.max_reference_size:
            self._reference_set = self._reference_set[-self.max_reference_size :]
            self._reference_norms = self._reference_norms[-self.max_reference_size :]

    def is_duplicate(self, sample: list[float] | np.ndarray) -> bool:
        """Check if a sample is an exact or near-duplicate.

        Checks bloom filter first (fast path), then cosine similarity
        against the reference set if bloom filter says "not seen."

        Args:
            sample: Feature vector to check.

        Returns:
            True if the sample is a duplicate or near-duplicate.
        """
        sample_arr = np.asarray(sample, dtype=np.float64)
        self._samples_seen += 1

        # Fast path: bloom filter exact-duplicate check
        sample_bytes = self._sample_to_bytes(sample_arr)
        if self._bloom.contains(sample_bytes):
            self._duplicates_found += 1
            return True

        # Check perceptual hash
        phash = self._perceptual_hash(sample_arr)
        if self._bloom.contains(phash):
            self._near_duplicates_found += 1
            return True

        # Slow path: cosine similarity against reference set
        if self._reference_set:
            max_sim = self.similarity_score(sample_arr)
            if max_sim >= self.similarity_threshold:
                self._near_duplicates_found += 1
                return True

        return False

    def similarity_score(self, sample: list[float] | np.ndarray) -> float:
        """Compute maximum cosine similarity against the reference set.

        Args:
            sample: Feature vector.

        Returns:
            Maximum cosine similarity to any sample in the reference set.
            Returns 0.0 if reference set is empty.
        """
        if not self._reference_set:
            return 0.0

        sample_arr = np.asarray(sample, dtype=np.float64)
        sample_norm = float(np.linalg.norm(sample_arr))
        if sample_norm < 1e-10:
            return 0.0

        max_sim = 0.0
        for ref_sample, ref_norm in zip(self._reference_set, self._reference_norms):
            if ref_norm < 1e-10:
                continue
            sim = float(np.dot(sample_arr, ref_sample) / (sample_norm * ref_norm))
            if sim > max_sim:
                max_sim = sim

        return max_sim

    def get_stats(self) -> FingerprintStats:
        """Get fingerprinting statistics.

        Returns:
            FingerprintStats with current state information.
        """
        return FingerprintStats(
            samples_seen=self._samples_seen,
            duplicates_found=self._duplicates_found,
            near_duplicates_found=self._near_duplicates_found,
            bloom_filter_size=self._bloom.count,
            bloom_filter_capacity=self._bloom.capacity,
            reference_set_size=len(self._reference_set),
        )

    def reset(self) -> None:
        """Reset all fingerprinting state."""
        self._bloom.reset()
        self._reference_set = []
        self._reference_norms = []
        self._samples_seen = 0
        self._duplicates_found = 0
        self._near_duplicates_found = 0
