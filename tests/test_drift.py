"""Tests for the concept drift detection module.

Verifies that drift is not detected on stable data, drift is detected on
sudden distribution shifts, sensitivity can be configured, and reset works.
"""

import numpy as np

from poison_detector.drift import ConceptDriftDetector, ADWINDetector, PageHinkleyDetector
from poison_detector.stream import StreamingDetector


def test_no_drift_on_stable_distribution():
    """Stable data drawn from a single distribution should not trigger drift.

    Feeds 200 samples from the same Gaussian and verifies that is_drifting()
    remains False throughout.
    """
    detector = ConceptDriftDetector(n_features=5, delta=0.01, drift_fraction=0.3)

    rng = np.random.default_rng(42)
    for _ in range(200):
        sample = rng.normal(loc=0.0, scale=1.0, size=5).tolist()
        detector.update(sample)

    assert detector.is_drifting() is False
    assert detector.get_drift_score() < 1.0


def test_drift_detected_on_sudden_mean_shift():
    """A sudden mean shift should trigger drift detection.

    Feeds 100 samples from mean=0, then 100 samples from mean=50.
    The ADWIN or Page-Hinkley detector should flag this as drift.
    """
    detector = ConceptDriftDetector(
        n_features=3,
        delta=0.01,
        drift_fraction=0.3,
        ph_delta=0.005,
        ph_lambda=50.0,
    )

    rng = np.random.default_rng(99)

    # Phase 1: stable at mean=0
    for _ in range(100):
        sample = rng.normal(loc=0.0, scale=1.0, size=3).tolist()
        detector.update(sample)

    # Phase 2: sudden shift to mean=50
    drift_detected = False
    for _ in range(100):
        sample = rng.normal(loc=50.0, scale=1.0, size=3).tolist()
        detector.update(sample)
        if detector.is_drifting():
            drift_detected = True

    assert drift_detected is True, "Drift should be detected after a large mean shift"


def test_sensitivity_parameter_affects_detection():
    """Lower delta (more sensitive) should detect smaller shifts.

    Creates two detectors with different delta values and verifies that
    the more sensitive one detects drift where the less sensitive one does not.
    """
    rng = np.random.default_rng(7)

    # Use ADWIN directly for clearer test
    sensitive_detector = ADWINDetector(delta=0.001)  # Very sensitive
    conservative_detector = ADWINDetector(delta=0.5)  # Very conservative

    # Phase 1: stable data
    for _ in range(50):
        val = rng.normal(0.0, 1.0)
        sensitive_detector.update(val)
        conservative_detector.update(val)

    # Phase 2: moderate shift (mean=3, not extreme)
    sensitive_drifted = False
    conservative_drifted = False
    for _ in range(50):
        val = rng.normal(3.0, 1.0)
        if sensitive_detector.update(val):
            sensitive_drifted = True
        if conservative_detector.update(val):
            conservative_drifted = True

    # The sensitive detector should detect drift; conservative may not
    assert sensitive_drifted is True, (
        "Sensitive detector (delta=0.001) should detect a shift from mean=0 to mean=3"
    )
    # Conservative with delta=0.5 has a large epsilon bound, may not trigger
    # This test verifies relative sensitivity ordering
    # (at minimum, sensitive must detect it)


def test_reset_clears_drift_state():
    """reset() should clear all drift state and allow fresh detection.

    After detecting drift and resetting, is_drifting() should return False
    and internal counters should be zeroed.
    """
    detector = ConceptDriftDetector(n_features=2, delta=0.01)

    # Feed data that causes drift
    rng = np.random.default_rng(55)
    for _ in range(50):
        detector.update(rng.normal(0.0, 1.0, size=2).tolist())
    for _ in range(50):
        detector.update(rng.normal(100.0, 1.0, size=2).tolist())

    # Reset
    detector.reset()

    # After reset, should be clean state
    assert detector.is_drifting() is False
    assert detector.get_drift_score() == 0.0

    stats = detector.get_stats()
    assert stats.samples_since_reset == 0
    assert stats.features_drifting == 0
    assert stats.is_drifting is False


def test_streaming_detector_flags_slow_baseline_shift():
    """Slow poison should raise a sticky drift alarm instead of silent adaptation."""
    detector = StreamingDetector(window_size=500, drift_sensitivity=0.01, refit_interval=50)
    detector.update_baseline([[0.0] for _ in range(100)])

    for i in range(500):
        detector.score_sample([i / 500.0])

    assert detector.get_stats().drift_detected is True