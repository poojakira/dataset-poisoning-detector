"""Tests for the StreamingDetector dimensionality-reduction and label path."""

import numpy as np

from poison_detector.sample import Sample
from poison_detector.stream import StreamingDetector


def test_reduce_dim_scores_high_dimensional_input():
    """With reduce_dim set, the detector operates in the reduced space."""
    rng = np.random.default_rng(0)
    clean = rng.normal(0.0, 1.0, size=(300, 256))
    detector = StreamingDetector(
        window_size=1000, contamination=0.05, reduce_dim=32, reduce_method="gaussian"
    )
    detector.update_baseline(clean.tolist())

    # Internal state now lives in the 32-dim reduced space.
    assert detector._n_features == 32
    assert detector._reducer is not None

    # A normal sample scores; an off-distribution sample scores higher.
    normal = detector.score_sample(rng.normal(0.0, 1.0, size=256).tolist())
    outlier = detector.score_sample((rng.normal(0.0, 1.0, size=256) + 8.0).tolist())
    assert 0.0 <= normal.score <= 1.0
    assert outlier.score >= normal.score


def test_reduce_dim_lazy_gaussian_without_baseline():
    """Gaussian reduction can fit lazily on the first sample (no baseline)."""
    detector = StreamingDetector(reduce_dim=16, reduce_method="gaussian")
    result = detector.score_sample([float(i) for i in range(128)])
    assert detector._n_features == 16
    assert result.score >= 0.0


def test_pca_passthrough_without_baseline():
    """PCA reduction cannot fit on one row, so it passes through until baseline."""
    detector = StreamingDetector(reduce_dim=16, reduce_method="pca")
    result = detector.score_sample([float(i) for i in range(128)])
    # Passthrough -> feature space is still the full 128 dims.
    assert detector._n_features == 128
    assert result.score >= 0.0


def test_sample_object_and_label_passthrough():
    detector = StreamingDetector(window_size=100)
    result = detector.score_sample(Sample(features=[1.0, 2.0, 3.0], label=7))
    assert result.label == 7


def test_dict_sample_label_passthrough():
    detector = StreamingDetector(window_size=100)
    result = detector.score_sample({"features": [1.0, 2.0], "label": 2})
    assert result.label == 2


def test_reset_clears_reducer():
    rng = np.random.default_rng(1)
    detector = StreamingDetector(reduce_dim=8, reduce_method="gaussian")
    detector.update_baseline(rng.normal(size=(50, 64)).tolist())
    assert detector._reducer is not None
    detector.reset()
    assert detector._reducer is None
    assert detector._n_features is None
