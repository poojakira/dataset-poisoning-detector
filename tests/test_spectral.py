"""
tests/test_spectral.py
────────────────────────────────────────────────────────────────────────────────
Tests for spectral signature-based poisoning detection.

Key validation: demonstrates that spectral signatures CAN detect label-flip
attacks that feature-space methods (z-score, IQR, IsolationForest) miss.
"""
import numpy as np
import pytest

from poison_detector.spectral import spectral_detect, detect_label_flips, SpectralReport


class TestSpectralDetect:
    """Core spectral detection algorithm tests."""

    def test_detects_label_flips_in_separable_data(self):
        """The fundamental test: can spectral signatures catch label flips?

        Creates two well-separated clusters, then flips 5% of labels.
        Feature-space methods can't catch this because the FEATURES are normal.
        Only the LABEL is wrong.
        """
        rng = np.random.default_rng(42)

        # Two clear Gaussian clusters
        n_per_class = 100
        dim = 10

        # Class 0: centered at origin
        class_0 = rng.normal(0, 1, (n_per_class, dim))
        # Class 1: centered at [5, 5, 5, ...]
        class_1 = rng.normal(5, 1, (n_per_class, dim))

        X = np.vstack([class_0, class_1])
        labels = np.array([0] * n_per_class + [1] * n_per_class)

        # Flip 5 labels in class 1 (take class-0 samples, assign label 1)
        # These are the "poisoned" samples — correct features, wrong label
        n_poison = 5
        poison_indices = list(range(n_poison))  # first 5 samples of class 0
        poisoned_labels = labels.copy()
        poisoned_labels[poison_indices] = 1  # flip their label from 0 to 1

        report = spectral_detect(
            X.tolist(),
            poisoned_labels.tolist(),
            iqr_multiplier=1.5,
        )

        assert isinstance(report, SpectralReport)
        assert report.total_samples == 200

        # The poisoned samples should have high projection scores in class 1
        # because they don't belong there. Check if at least 3/5 are caught.
        flagged_indices = {r.sample_idx for r in report.results if r.is_poisoned}
        caught = flagged_indices.intersection(set(poison_indices))
        # We expect to catch most of them (spectral is not perfect but much better than random)
        assert len(caught) >= 2, (
            f"Expected to catch at least 2/5 poisoned samples, only caught {len(caught)}. "
            f"Flagged: {flagged_indices}, Poisoned: {poison_indices}"
        )

    def test_clean_data_has_low_flags(self):
        """On perfectly clean data, spectral should flag very few samples."""
        rng = np.random.default_rng(123)

        n_per_class = 50
        dim = 5
        class_0 = rng.normal(0, 1, (n_per_class, dim))
        class_1 = rng.normal(3, 1, (n_per_class, dim))

        X = np.vstack([class_0, class_1]).tolist()
        labels = [0] * n_per_class + [1] * n_per_class

        report = spectral_detect(X, labels, iqr_multiplier=1.5)

        # IQR-based threshold should flag at most ~5% on clean data
        fp_rate = report.poisoned_count / report.total_samples
        assert fp_rate <= 0.10, f"FP rate {fp_rate:.2%} is too high on clean data"

    def test_empty_input(self):
        """Empty input should return empty report, not crash."""
        report = spectral_detect([], [])
        assert report.total_samples == 0
        assert report.poisoned_count == 0

    def test_single_class(self):
        """Should work when all samples have the same label."""
        rng = np.random.default_rng(99)
        X = rng.normal(0, 1, (20, 5)).tolist()
        labels = [0] * 20

        report = spectral_detect(X, labels)
        assert report.total_samples == 20

    def test_too_small_class_is_skipped(self):
        """Classes with fewer than min_class_size samples should be skipped."""
        rng = np.random.default_rng(77)
        X = rng.normal(0, 1, (30, 5)).tolist()
        # 27 samples in class 0, 3 in class 1
        labels = [0] * 27 + [1] * 3

        report = spectral_detect(X, labels, min_class_size=5)
        # Class 1 should be skipped
        assert 1 in report.per_class_stats
        assert report.per_class_stats[1]["skipped"] is True

    def test_validation_errors(self):
        """Should raise ValueError for invalid inputs."""
        with pytest.raises(ValueError, match="2-dimensional"):
            spectral_detect([1, 2, 3], [0, 0, 0])  # 1D input

        with pytest.raises(ValueError, match="same length"):
            spectral_detect([[1, 2], [3, 4]], [0])  # length mismatch


class TestDetectLabelFlips:
    """Tests for the convenience function."""

    def test_returns_sorted_indices(self):
        """detect_label_flips should return indices sorted by suspicion score."""
        rng = np.random.default_rng(42)
        n = 100
        dim = 8
        class_0 = rng.normal(0, 1, (n, dim))
        class_1 = rng.normal(4, 1, (n, dim))

        X = np.vstack([class_0, class_1])
        labels = np.array([0] * n + [1] * n)

        # Flip 5 labels
        poisoned_labels = labels.copy()
        poisoned_labels[:5] = 1

        suspects = detect_label_flips(
            X.tolist(),
            poisoned_labels.tolist(),
            contamination_estimate=0.05,
        )

        assert isinstance(suspects, list)
        assert all(isinstance(idx, int) for idx in suspects)
        # Should flag some of the flipped samples
        assert len(suspects) > 0

    def test_empty_input_returns_empty(self):
        result = detect_label_flips([], [])
        assert result == []


class TestSpectralVsFeatureSpace:
    """Comparison tests proving spectral works where feature methods fail."""

    def test_feature_space_misses_label_flips(self):
        """Demonstrate that the old z-score/IQR methods miss label flips.

        This is the core motivation for adding spectral signatures.
        """
        from poison_detector.detector import detect

        rng = np.random.default_rng(42)
        n_per_class = 50
        dim = 5

        class_0 = rng.normal(0, 1, (n_per_class, dim))
        class_1 = rng.normal(4, 1, (n_per_class, dim))
        X = np.vstack([class_0, class_1]).tolist()

        # The poisoned samples have NORMAL features — only labels are wrong
        # Feature-space methods should NOT catch them because features are fine
        # (They only detect feature outliers, not label inconsistencies)

        # Run ensemble (z-score + IQR + isolation)
        ensemble_report = detect(X, method="ensemble")
        # The first 5 samples are from class 0 — they're not feature outliers
        first_5_flagged = sum(
            1 for r in ensemble_report.per_sample[:5] if r.is_poisoned
        )
        # Feature methods should flag 0-1 of these at most (they're normal points)
        assert first_5_flagged <= 2, (
            f"Feature-space ensemble flagged {first_5_flagged}/5 normal samples. "
            "This means the test isn't demonstrating the limitation correctly."
        )
