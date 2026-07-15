"""
Concept drift detection to distinguish legitimate distribution shifts from attacks.

Implements ADWIN (Adaptive Windowing) and Page-Hinkley tests to detect when
the data distribution changes. This is critical for reducing false positives:
when drift is detected, poison alerts are suppressed because the anomalies
may be legitimate changes rather than adversarial manipulation.

Threat Model Assumptions:
    - Legitimate concept drift occurs in production ML systems (user behavior
      changes, seasonal patterns, product updates). The detector must not
      flag all distribution changes as attacks.
    - An attacker who knows drift detection is active might try to make their
      poisoning look like natural drift. This is partially mitigated by the
      Page-Hinkley test which detects sudden shifts (attacks are usually more
      abrupt than natural drift).
    - Drift detection provides a SIGNAL, not a DECISION. It suppresses alerts
      but does not bypass quarantine. Samples during drift should be logged
      for later human review.

Honest Limitations:
    - ADWIN operates on scalar streams. For multi-dimensional data, we run
      one ADWIN instance per feature and aggregate. This misses drift in
      feature correlations (e.g., features individually stable but their
      relationship changes).
    - Page-Hinkley has a cumulative sum that can be slow to reset after
      a detected change. The reset() after detection helps but creates a
      blind spot during the reset period.
    - Neither algorithm handles cyclical/seasonal patterns natively. For
      time-series data with known periodicity, pre-detrend before feeding
      to drift detection.
    - The delta parameter (sensitivity) requires tuning per use case.
      Too sensitive = false drift alarms. Too insensitive = missed attacks.

Security Notes:
    - Drift detection state is in-memory. An attacker who can crash/restart
      the process resets drift state, potentially enabling a "restart then
      inject" attack pattern. Persist drift state for critical deployments.
    - No external I/O in this module. Pure computation on provided values.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class DriftStats:
    """Statistics about drift detection state.

    Attributes:
        is_drifting: Whether drift is currently detected.
        drift_score: Aggregate drift score across all features (0-1).
        features_drifting: Number of individual features showing drift.
        total_features: Total number of features being monitored.
        samples_since_reset: Samples processed since last reset.
        page_hinkley_triggered: Whether the Page-Hinkley test fired.
    """

    is_drifting: bool = False
    drift_score: float = 0.0
    features_drifting: int = 0
    total_features: int = 0
    samples_since_reset: int = 0
    page_hinkley_triggered: bool = False


class ADWINBucket:
    """Single bucket in the ADWIN exponential histogram.

    ADWIN maintains a variable-length window that shrinks when drift is
    detected by comparing sub-window means.
    """

    def __init__(self) -> None:
        self.total: float = 0.0
        self.count: int = 0
        self.variance: float = 0.0


class ADWINDetector:
    """Adaptive Windowing (ADWIN) drift detector for a single stream.

    ADWIN maintains a variable-length window of recent values. When the
    means of two sub-windows differ by more than a statistical bound
    (controlled by delta), drift is detected and the older sub-window
    is dropped.

    Based on: Bifet & Gavalda, "Learning from Time-Changing Data with
    Adaptive Windowing" (2007).

    Args:
        delta: Confidence parameter. Lower = more sensitive to drift.
            Typical range: 0.001 (very sensitive) to 0.1 (conservative).
    """

    def __init__(self, delta: float = 0.01) -> None:
        self.delta = delta
        self._window: list[float] = []
        self._total: float = 0.0
        self._count: int = 0
        self._variance: float = 0.0
        self._width: int = 0
        self._drift_detected: bool = False

    @property
    def drift_detected(self) -> bool:
        """Whether drift was detected on the last update."""
        return self._drift_detected

    @property
    def mean(self) -> float:
        """Current window mean."""
        if self._count == 0:
            return 0.0
        return self._total / self._count

    def update(self, value: float) -> bool:
        """Add a new value and check for drift.

        Args:
            value: New scalar observation.

        Returns:
            True if drift is detected, False otherwise.
        """
        self._drift_detected = False
        self._window.append(value)
        self._total += value
        self._count += 1

        # Check for drift by comparing sub-windows
        if self._count >= 10:  # Minimum window for meaningful comparison
            self._drift_detected = self._check_drift()

        # Limit window size to prevent unbounded memory growth
        max_window = 10000
        if len(self._window) > max_window:
            removed = self._window[0]
            self._window = self._window[1:]
            self._total -= removed
            self._count -= 1

        return self._drift_detected

    def _check_drift(self) -> bool:
        """Check if the window shows statistically significant drift.

        Compares the means of the first half and second half of the window.
        Uses a Hoeffding-style bound controlled by delta.

        Returns:
            True if the difference exceeds the statistical bound.
        """
        n = len(self._window)
        if n < 10:
            return False

        # Try multiple split points (simplified ADWIN: check midpoint and quartiles)
        for split_frac in (0.25, 0.5, 0.75):
            split = max(5, int(n * split_frac))
            if split >= n - 5:
                continue

            window_1 = self._window[:split]
            window_2 = self._window[split:]

            n1 = len(window_1)
            n2 = len(window_2)

            mean_1 = sum(window_1) / n1
            mean_2 = sum(window_2) / n2

            # Hoeffding bound for the difference of means
            # epsilon = sqrt((1/(2*n)) * ln(4/delta))
            m = 1.0 / (1.0 / n1 + 1.0 / n2)
            epsilon_cut = math.sqrt(
                (1.0 / (2.0 * m)) * math.log(4.0 / self.delta)
            )

            if abs(mean_1 - mean_2) >= epsilon_cut:
                # Drift detected: drop the older sub-window
                self._window = window_2[:]
                self._total = sum(self._window)
                self._count = len(self._window)
                return True

        return False

    def reset(self) -> None:
        """Reset the detector state."""
        self._window = []
        self._total = 0.0
        self._count = 0
        self._variance = 0.0
        self._drift_detected = False


class PageHinkleyDetector:
    """Page-Hinkley test for detecting abrupt distribution changes.

    Monitors the cumulative sum of deviations from the running mean.
    When the cumulative sum exceeds a threshold (lambda_), a change point
    is declared. More sensitive to sudden shifts than ADWIN.

    Based on: Page (1954) "Continuous Inspection Schemes" and
    Hinkley (1971) "Inference about the change-point from cumulative sum tests."

    Args:
        delta: Magnitude tolerance. Small positive value that controls
            the minimum magnitude of change to detect. Higher = less sensitive.
        lambda_: Detection threshold. The cumulative sum must exceed this
            to trigger. Higher = fewer false alarms but slower detection.
        alpha: Forgetting factor for the running mean (0-1). Lower values
            mean the reference mean adapts more slowly.
    """

    def __init__(
        self,
        delta: float = 0.005,
        lambda_: float = 50.0,
        alpha: float = 0.9999,
    ) -> None:
        self.delta = delta
        self.lambda_ = lambda_
        self.alpha = alpha

        self._count: int = 0
        self._sum: float = 0.0
        self._running_mean: float = 0.0
        self._cumulative_sum: float = 0.0
        self._min_cumulative_sum: float = float("inf")
        self._drift_detected: bool = False

    @property
    def drift_detected(self) -> bool:
        """Whether a change point was detected on the last update."""
        return self._drift_detected

    @property
    def test_statistic(self) -> float:
        """Current Page-Hinkley test statistic (PH_t - min(PH_t))."""
        if self._min_cumulative_sum == float("inf"):
            return 0.0
        return self._cumulative_sum - self._min_cumulative_sum

    def update(self, value: float) -> bool:
        """Add a new value and check for change point.

        Args:
            value: New scalar observation.

        Returns:
            True if a change point is detected, False otherwise.
        """
        self._drift_detected = False
        self._count += 1

        # Update running mean with forgetting factor
        if self._count == 1:
            self._running_mean = value
        else:
            self._running_mean = (
                self.alpha * self._running_mean + (1 - self.alpha) * value
            )

        # Update cumulative sum
        self._cumulative_sum += value - self._running_mean - self.delta

        # Track minimum cumulative sum
        if self._cumulative_sum < self._min_cumulative_sum:
            self._min_cumulative_sum = self._cumulative_sum

        # Check threshold
        if self._count > 30:  # Burn-in period
            if self.test_statistic > self.lambda_:
                self._drift_detected = True
                # Reset after detection to find the next change point
                self._reset_cumulative()

        return self._drift_detected

    def _reset_cumulative(self) -> None:
        """Reset cumulative sums after detection (keep running mean)."""
        self._cumulative_sum = 0.0
        self._min_cumulative_sum = float("inf")

    def reset(self) -> None:
        """Full reset of all state."""
        self._count = 0
        self._sum = 0.0
        self._running_mean = 0.0
        self._cumulative_sum = 0.0
        self._min_cumulative_sum = float("inf")
        self._drift_detected = False


class ConceptDriftDetector:
    """Multi-feature concept drift detector combining ADWIN and Page-Hinkley.

    Runs independent ADWIN detectors per feature and a global Page-Hinkley
    test on the aggregate anomaly score. Drift is declared when either:
    - A sufficient fraction of features show ADWIN drift, OR
    - The Page-Hinkley test detects a sudden shift in aggregate statistics.

    When drift is detected, the detector signals that poison alerts should be
    SUPPRESSED -- the anomalies may be legitimate distribution changes.

    Usage:
        drift_detector = ConceptDriftDetector(n_features=10)
        for sample in stream:
            drift_detector.update(sample)
            if drift_detector.is_drifting():
                suppress_poison_alerts()

    Args:
        n_features: Number of features to monitor. If None, auto-detected
            on first update() call.
        delta: ADWIN sensitivity parameter.
        drift_fraction: Fraction of features that must show drift to declare
            overall drift (e.g., 0.3 = 30% of features drifting).
        ph_delta: Page-Hinkley delta (magnitude tolerance).
        ph_lambda: Page-Hinkley detection threshold.
    """

    def __init__(
        self,
        n_features: int | None = None,
        delta: float = 0.01,
        drift_fraction: float = 0.3,
        ph_delta: float = 0.005,
        ph_lambda: float = 50.0,
    ) -> None:
        self.delta = delta
        self.drift_fraction = drift_fraction
        self._n_features = n_features
        self._adwin_detectors: list[ADWINDetector] = []
        self._page_hinkley = PageHinkleyDetector(delta=ph_delta, lambda_=ph_lambda)
        self._initialized = False
        self._samples_seen: int = 0
        self._features_drifting: int = 0
        self._is_drifting: bool = False
        self._drift_score: float = 0.0

        if n_features is not None:
            self._initialize(n_features)

    def _initialize(self, n_features: int) -> None:
        """Initialize per-feature ADWIN detectors."""
        self._n_features = n_features
        self._adwin_detectors = [
            ADWINDetector(delta=self.delta) for _ in range(n_features)
        ]
        self._initialized = True

    def update(self, sample: list[float]) -> None:
        """Update drift detection with a new sample.

        Args:
            sample: Feature vector as list of floats.
        """
        if not self._initialized:
            self._initialize(len(sample))

        self._samples_seen += 1

        # Update per-feature ADWIN detectors
        features_drifting = 0
        for i, value in enumerate(sample):
            if i < len(self._adwin_detectors):
                if self._adwin_detectors[i].update(value):
                    features_drifting += 1

        self._features_drifting = features_drifting

        # Update Page-Hinkley with the mean of the sample
        # (aggregate signal for sudden shifts)
        if len(sample) > 0:
            sample_mean = sum(sample) / len(sample)
            self._page_hinkley.update(sample_mean)

        # Determine drift state
        n_features = self._n_features or 1
        feature_drift_ratio = features_drifting / n_features
        ph_triggered = self._page_hinkley.drift_detected

        self._is_drifting = (
            feature_drift_ratio >= self.drift_fraction or ph_triggered
        )

        # Compute drift score (0 = no drift, 1 = maximum drift)
        ph_score = min(1.0, self._page_hinkley.test_statistic / max(self._page_hinkley.lambda_, 1.0))
        adwin_score = feature_drift_ratio / max(self.drift_fraction, 0.01)
        self._drift_score = min(1.0, max(ph_score, adwin_score))

    def is_drifting(self) -> bool:
        """Check if concept drift is currently detected.

        Returns:
            True if drift is detected (poison alerts should be suppressed).
        """
        return self._is_drifting

    def get_drift_score(self) -> float:
        """Get the current aggregate drift score.

        Returns:
            Float in [0, 1] range. 0 = no drift, 1 = maximum drift signal.
        """
        return self._drift_score

    def get_stats(self) -> DriftStats:
        """Get detailed drift detection statistics.

        Returns:
            DriftStats dataclass with current state information.
        """
        return DriftStats(
            is_drifting=self._is_drifting,
            drift_score=self._drift_score,
            features_drifting=self._features_drifting,
            total_features=self._n_features or 0,
            samples_since_reset=self._samples_seen,
            page_hinkley_triggered=self._page_hinkley.drift_detected,
        )

    def reset(self) -> None:
        """Reset all drift detection state."""
        for detector in self._adwin_detectors:
            detector.reset()
        self._page_hinkley.reset()
        self._samples_seen = 0
        self._features_drifting = 0
        self._is_drifting = False
        self._drift_score = 0.0
