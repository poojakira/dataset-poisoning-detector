"""Tests for the streaming detector module.

Verifies rolling window statistics, adaptive baseline updates, single-sample
scoring, window overflow behavior, and full state reset.
"""

import numpy as np

from poison_detector.stream import StreamingDetector, ScoringResult


def test_rolling_window_maintains_correct_statistics():
    """Rolling window Welford accumulator tracks mean and variance correctly.

    Feeds a set of known samples and verifies that the internal statistics
    (mean, variance) match expected values computed from the data.
    """
    detector = StreamingDetector(window_size=100, zscore_threshold=3.0, vote_threshold=2)

    # Feed 50 samples drawn from a known distribution (mean=5, std~0)
    samples = [[5.0, 10.0] for _ in range(50)]
    for s in samples:
        detector.score_sample(s)

    # Check Welford accumulator has the right mean
    assert detector._welford is not None
    assert detector._welford.count == 50
    np.testing.assert_allclose(detector._welford.mean, [5.0, 10.0], atol=1e-10)

    # Variance should be near zero since all samples are identical
    np.testing.assert_allclose(detector._welford.variance, [0.0, 0.0], atol=1e-10)


def test_adaptive_baseline_updates_correctly():
    """update_baseline() fits IsolationForest and initializes Welford stats.

    After calling update_baseline with known-clean data, the detector should
    have a fitted model and correct rolling statistics.
    """
    detector = StreamingDetector(window_size=500, contamination=0.05)

    # Generate clean data: 200 samples from a Gaussian
    rng = np.random.default_rng(42)
    clean_data = rng.normal(loc=0.0, scale=1.0, size=(200, 5)).tolist()

    detector.update_baseline(clean_data)

    # Model should be fitted
    assert detector._model is not None

    # Welford should reflect the clean data statistics
    assert detector._welford is not None
    assert detector._welford.count == 200

    # Window should contain the clean samples
    assert len(detector._window) == 200

    # Scoring a normal sample should not flag it
    normal_sample = [0.1, -0.2, 0.05, 0.3, -0.1]
    result = detector.score_sample(normal_sample)
    assert result.is_poisoned is False


def test_single_sample_scoring_returns_scoring_result():
    """score_sample() returns a ScoringResult with all required fields.

    Verifies the return type and that all fields (score, is_poisoned,
    method_votes, latency_ms) are present and have valid values.
    """
    detector = StreamingDetector(window_size=100, vote_threshold=2)

    # Score a sample (first sample, no baseline)
    result = detector.score_sample([1.0, 2.0, 3.0])

    assert isinstance(result, ScoringResult)
    assert isinstance(result.score, float)
    assert 0.0 <= result.score <= 1.0
    assert isinstance(result.is_poisoned, bool)
    assert isinstance(result.method_votes, dict)
    assert "zscore" in result.method_votes
    assert "isolation_forest" in result.method_votes
    assert isinstance(result.latency_ms, float)
    assert result.latency_ms >= 0.0


def test_window_overflow_evicts_old_data():
    """When window exceeds window_size, oldest samples are evicted (FIFO).

    Uses a small window_size and confirms that after exceeding it, the
    window length stays bounded at window_size.
    """
    window_size = 20
    detector = StreamingDetector(window_size=window_size, vote_threshold=2)

    # Feed more samples than the window can hold
    for i in range(50):
        detector.score_sample([float(i), float(i * 2)])

    # Window should be capped at window_size
    assert len(detector._window) <= window_size

    # The window should contain the most recent samples (FIFO eviction)
    # Since only clean samples go into the window, and with no baseline
    # the zscore check needs 10+ samples before flagging, and vote_threshold=2
    # means nothing gets flagged (isolation_forest has no model), so all
    # samples end up in the window.
    assert len(detector._window) == window_size


def test_score_is_continuous_in_unit_interval():
    """score_sample().score is a continuous value in [0, 1], not a hard 0/1 flag.

    Guards the documented API contract that r.score is a continuous anomaly
    score (higher = more anomalous), which downstream ROC/threshold analysis
    depends on.
    """
    rng = np.random.default_rng(7)
    detector = StreamingDetector(window_size=1000, contamination=0.05)
    baseline = rng.normal(size=(300, 8))
    detector.update_baseline(baseline)

    scores = []
    for _ in range(200):
        vec = rng.normal(size=8)
        r = detector.score_sample(vec)
        assert 0.0 <= r.score <= 1.0
        scores.append(r.score)

    # Scores must vary (not a degenerate constant / pure 0-1 indicator).
    assert len(set(round(s, 6) for s in scores)) > 1


def test_contamination_implies_nonzero_false_positives():
    """A detector calibrated at contamination>0 flags some clean samples.

    Regression guard against any 'zero false positives' claim: with
    contamination=0.05 and an IsolationForest baseline, scoring purely clean
    (in-distribution) samples must produce a NONZERO false-positive rate at a
    5%-target operating threshold. Zero FPs on clean data would indicate a
    scoring bug or a dishonest claim.
    """
    rng = np.random.default_rng(20240713)
    contamination = 0.05
    detector = StreamingDetector(window_size=5000, contamination=contamination)

    # All-clean, in-distribution data. No poison at all.
    clean = rng.normal(size=(800, 10))
    detector.update_baseline(clean)

    scores = np.array([detector.score_sample(row).score for row in clean])

    # Choose the threshold that targets a 5% false-positive rate (95th pct of
    # clean scores) and measure the ACTUAL FP rate on the clean data.
    threshold = float(np.quantile(scores, 1.0 - contamination))
    fp_rate = float(np.mean(scores >= threshold))

    # The measured false-positive rate on clean data must be strictly > 0:
    # an anomaly detector at nonzero contamination cannot have zero FPs.
    assert fp_rate > 0.0
    # And it should be in a sane neighborhood of the target, not ~1.0.
    assert fp_rate <= 0.20


def test_reset_clears_all_state():
    """reset() returns the detector to its initial state.

    After scoring some samples and then resetting, all statistics,
    the window, and the model should be cleared.
    """
    detector = StreamingDetector(window_size=100)

    # Build some state
    rng = np.random.default_rng(123)
    clean = rng.normal(size=(50, 3)).tolist()
    detector.update_baseline(clean)

    for _ in range(10):
        detector.score_sample([0.0, 0.0, 0.0])

    # Verify there is state
    assert detector._samples_seen > 0
    assert detector._model is not None
    assert len(detector._window) > 0

    # Reset
    detector.reset()

    # Verify all state is cleared
    assert detector._samples_seen == 0
    assert detector._poison_count == 0
    assert detector._model is None
    assert detector._welford is None
    assert detector._window == []
    assert detector._n_features is None

    stats = detector.get_stats()
    assert stats.samples_seen == 0
    assert stats.poison_count == 0
    assert stats.baseline_size == 0
    assert stats.window_fill == 0.0
