"""
Streaming detector for real-time sample-by-sample poisoning detection.

Scores samples as they arrive using online statistics (Welford's algorithm)
and periodic IsolationForest refitting. Designed for production data pipelines
where samples arrive one-at-a-time or in small batches, not the full dataset
at once.

Threat Model Assumptions:
    - Samples arrive from an untrusted source (training data pipeline).
    - An attacker may attempt to slowly shift the baseline ("boiling frog")
      by sending many borderline samples before injecting overtly poisoned ones.
    - The streaming detector must maintain a stable baseline that resists
      gradual manipulation while adapting to legitimate distribution shifts
      (detected via the drift module).

Honest Limitations:
    - Online statistics (mean, variance) are computed per-feature independently.
      They cannot capture feature correlations. The IsolationForest refit
      handles multivariate anomalies but only runs periodically.
    - The window_size parameter creates a tradeoff: larger windows are more
      stable but slower to adapt. There is no universally correct value.
    - score_sample() is O(features) for the statistical check, but the
      IsolationForest predict is O(trees * depth) when the model exists.
      For very high-dimensional data (>10K features), consider dimensionality
      reduction before this stage.
    - score_sample() is synchronous and not thread-safe. For multi-threaded
      access, wrap calls with an external threading.Lock. Single-threaded
      async event loops (the common FastAPI deployment) are safe.

Security Notes:
    - Sample data is stored in memory (the rolling window). Ensure the process
      has appropriate memory limits to prevent OOM from adversarial flooding.
    - The IsolationForest model is fit on data from the window. If an attacker
      fills the window with poisoned data before the first refit, the baseline
      is compromised. Always call update_baseline() with known-clean data first.
    - No pickle/deserialization of models from untrusted sources.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from .reduction import DimensionalityReducer
from .sample import Sample, coerce_sample


@dataclass
class ScoringResult:
    """Result of scoring a single sample.

    Attributes:
        score: Anomaly score in [0, 1] range. Higher = more anomalous.
        is_poisoned: Whether the sample exceeds the poisoning threshold.
        method_votes: Dict of method_name -> voted_poisoned (True/False).
        latency_ms: Time taken to score this sample in milliseconds.
        label: The optional label carried by the input sample (passed through
            for triage; the unsupervised streaming path does not use it to
            score). None when the sample was unlabeled.
    """

    score: float
    is_poisoned: bool
    method_votes: dict[str, bool] = field(default_factory=dict)
    latency_ms: float = 0.0
    label: int | None = None


@dataclass
class StreamStats:
    """Statistics about the streaming detector state.

    Attributes:
        samples_seen: Total number of samples scored since creation/reset.
        poison_count: Number of samples flagged as poisoned.
        poison_rate: Fraction of samples flagged (poison_count / samples_seen).
        avg_latency_ms: Average scoring latency in milliseconds.
        drift_detected: Whether concept drift is currently detected.
        baseline_size: Number of samples in the IsolationForest baseline.
        window_fill: Fraction of the rolling window that is filled.
    """

    samples_seen: int = 0
    poison_count: int = 0
    poison_rate: float = 0.0
    avg_latency_ms: float = 0.0
    drift_detected: bool = False
    baseline_size: int = 0
    window_fill: float = 0.0


class WelfordAccumulator:
    """Online mean and variance computation using Welford's algorithm.

    Computes running mean and variance in O(1) per update, O(features) space.
    Numerically stable for large sample counts.

    Algorithm:
        M_k = M_{k-1} + (x_k - M_{k-1}) / k
        S_k = S_{k-1} + (x_k - M_{k-1}) * (x_k - M_k)
        variance = S_k / (k - 1)
    """

    def __init__(self, n_features: int) -> None:
        """Initialize accumulators for n features.

        Args:
            n_features: Number of features per sample.
        """
        self.n_features = n_features
        self.count: int = 0
        self.mean = np.zeros(n_features, dtype=np.float64)
        self.m2 = np.zeros(n_features, dtype=np.float64)  # S_k in the formula

    def update(self, sample: np.ndarray) -> None:
        """Update running statistics with a new sample.

        Implements Welford's online algorithm:
            M_k = M_{k-1} + (x_k - M_{k-1}) / k
            S_k = S_{k-1} + (x_k - M_{k-1}) * (x_k - M_k)

        Args:
            sample: 1D numpy array of feature values.
        """
        self.count += 1
        delta = sample - self.mean
        self.mean = self.mean + delta / self.count  # M_k formula
        delta2 = sample - self.mean
        self.m2 = self.m2 + delta * delta2  # S_k formula

    @property
    def variance(self) -> np.ndarray:
        """Sample variance (S_k / (k-1)).

        Returns zeros if fewer than 2 samples have been seen.
        """
        if self.count < 2:
            return np.zeros(self.n_features, dtype=np.float64)
        return self.m2 / (self.count - 1)

    @property
    def std(self) -> np.ndarray:
        """Sample standard deviation (sqrt of variance)."""
        return np.sqrt(self.variance)

    def reset(self) -> None:
        """Reset all accumulators to zero."""
        self.count = 0
        self.mean = np.zeros(self.n_features, dtype=np.float64)
        self.m2 = np.zeros(self.n_features, dtype=np.float64)


class StreamingDetector:
    """Real-time streaming poisoning detector with online scoring.

    Maintains rolling statistics via Welford's algorithm and periodically
    refits an IsolationForest on the rolling window for multivariate anomaly
    detection.

    Usage:
        detector = StreamingDetector(window_size=10000, contamination=0.05)
        detector.update_baseline(known_clean_samples)

        for sample in data_stream:
            result = detector.score_sample(sample)
            if result.is_poisoned:
                quarantine(sample)

    Thread Safety:
        score_sample() is synchronous and NOT thread-safe. If called from
        multiple threads, wrap calls with an external threading.Lock. For
        async usage from FastAPI, the GIL provides safety for single-threaded
        async event loops (the common case), but concurrent async tasks
        modifying state should serialize access externally.
    """

    def __init__(
        self,
        window_size: int = 10000,
        contamination: float = 0.05,
        drift_sensitivity: float = 0.01,
        refit_interval: int = 1000,
        zscore_threshold: float = 3.0,
        vote_threshold: int = 2,
        reduce_dim: int | None = None,
        reduce_method: str = "gaussian",
    ) -> None:
        """Initialize the streaming detector.

        Args:
            window_size: Maximum samples in the rolling window.
            contamination: Expected poison fraction for IsolationForest.
            drift_sensitivity: Sensitivity parameter for drift detection.
            refit_interval: Clean samples between IsolationForest refits.
            zscore_threshold: Z-score threshold for statistical anomaly flagging.
            vote_threshold: Minimum method votes to flag as poisoned.
            reduce_dim: If set, project incoming samples to this many dimensions
                BEFORE z-score / IsolationForest scoring. Essential for
                high-dimensional inputs (e.g. 768-dim embeddings) where the
                isolation path would otherwise blow the latency budget and lose
                signal in the noise. None disables reduction (default).
            reduce_method: "gaussian" (random projection, data-independent, the
                safe default for very high dimensions) or "pca" (fit on the
                baseline; keeps max-variance directions).
        """
        self.window_size = window_size
        self.contamination = contamination
        self.drift_sensitivity = drift_sensitivity
        self.refit_interval = refit_interval
        self.zscore_threshold = zscore_threshold
        self.vote_threshold = vote_threshold
        self.reduce_dim = reduce_dim
        self.reduce_method = reduce_method

        # State
        self._welford: WelfordAccumulator | None = None
        self._window: list[np.ndarray] = []
        self._model: IsolationForest | None = None
        self._samples_since_refit: int = 0
        self._n_features: int | None = None
        self._reducer: DimensionalityReducer | None = None

        # Stats tracking
        self._samples_seen: int = 0
        self._poison_count: int = 0
        self._total_latency_ms: float = 0.0
        self._drift_detected: bool = False

    def _initialize_features(self, n_features: int) -> None:
        """Lazily initialize feature-count-dependent state."""
        self._n_features = n_features
        self._welford = WelfordAccumulator(n_features)

    def _project(self, sample_arr: np.ndarray) -> np.ndarray:
        """Apply dimensionality reduction to a single sample if configured.

        For Gaussian random projection the reducer can be fit lazily on the very
        first sample (it only needs the input dimensionality). For PCA a fit
        requires multiple rows, so callers should establish a baseline via
        update_baseline() first; until then PCA reduction is a pass-through.
        """
        if self.reduce_dim is None:
            return sample_arr

        if self._reducer is None or not self._reducer._fitted:
            self._reducer = DimensionalityReducer(
                method=self.reduce_method, n_components=self.reduce_dim
            )
            if self.reduce_method == "gaussian":
                # Random projection needs only the dimensionality -> lazy fit OK.
                self._reducer.fit(sample_arr.reshape(1, -1))
            else:
                # No baseline yet for PCA: cannot fit on one row; pass through.
                return sample_arr

        return self._reducer.transform(sample_arr.reshape(1, -1))[0]

    def score_sample(
        self, sample: list[float] | np.ndarray | Sample | dict
    ) -> ScoringResult:
        """Score a single sample for poisoning indicators.

        Combines z-score based statistical anomaly detection with
        IsolationForest predictions (when a model is fitted).

        Args:
            sample: The sample to score. Accepts the legacy flat formats (list of
                floats or numpy array) as well as the extended data model
                (a Sample or a {"features": [...], "label": ...} dict). Any label
                is passed through to the result but does not influence the
                unsupervised score.

        Returns:
            ScoringResult with score, is_poisoned flag, method votes, latency,
            and the pass-through label.
        """
        start = time.perf_counter()

        # Accept the extended data model while preserving legacy behavior.
        if isinstance(sample, (Sample, dict)):
            coerced = coerce_sample(sample)
            label = coerced.label
            sample_arr = np.asarray(coerced.features, dtype=np.float64)
        else:
            label = None
            sample_arr = np.asarray(sample, dtype=np.float64)

        # Project to a lower dimension first if configured (before feature init
        # so the Welford/IsolationForest state matches the reduced space).
        sample_arr = self._project(sample_arr)

        # Lazy initialization on first sample
        if self._n_features is None:
            self._initialize_features(len(sample_arr))

        method_votes: dict[str, bool] = {}
        scores: list[float] = []

        # --- Z-score based detection ---
        zscore_anomaly = False
        zscore_score = 0.0
        if self._welford is not None and self._welford.count >= 10:
            std = self._welford.std
            mean = self._welford.mean
            # Avoid division by zero for constant features
            safe_std = np.where(std > 1e-10, std, 1.0)
            z_scores = np.abs((sample_arr - mean) / safe_std)
            max_z = float(np.max(z_scores))
            zscore_score = min(max_z / (self.zscore_threshold * 2), 1.0)
            zscore_anomaly = max_z > self.zscore_threshold
            scores.append(zscore_score)
        method_votes["zscore"] = zscore_anomaly

        # --- IsolationForest based detection ---
        iso_anomaly = False
        if self._model is not None:
            raw_score = self._model.score_samples(sample_arr.reshape(1, -1))[0]
            # sklearn: lower score = more anomalous, threshold at 0
            # Normalize: decision_function gives offset from threshold
            decision = self._model.decision_function(sample_arr.reshape(1, -1))[0]
            iso_anomaly = decision < 0
            # Convert to 0-1 scale (approximate)
            iso_score = max(0.0, min(1.0, 0.5 - decision))
            scores.append(iso_score)
        method_votes["isolation_forest"] = iso_anomaly

        # --- Aggregate score ---
        if scores:
            final_score = float(np.mean(scores))
        else:
            final_score = 0.0

        # Vote-based decision
        votes_for_poison = sum(1 for v in method_votes.values() if v)
        is_poisoned = votes_for_poison >= self.vote_threshold

        # Update rolling window and statistics
        self._update_state(sample_arr, is_poisoned)

        elapsed_ms = (time.perf_counter() - start) * 1000.0
        self._samples_seen += 1
        self._total_latency_ms += elapsed_ms
        if is_poisoned:
            self._poison_count += 1

        return ScoringResult(
            score=final_score,
            is_poisoned=is_poisoned,
            method_votes=method_votes,
            latency_ms=elapsed_ms,
            label=label,
        )

    def score_batch(
        self, samples: list[list[float]] | list[np.ndarray]
    ) -> list[ScoringResult]:
        """Score a batch of samples.

        Convenience method that calls score_sample for each sample.
        For very large batches, consider using the async version.

        Args:
            samples: List of feature vectors.

        Returns:
            List of ScoringResult, one per sample, in order.
        """
        return [self.score_sample(s) for s in samples]

    def score_batch_vectorized(
        self,
        samples: list[list[float]] | np.ndarray,
        update_state: bool = True,
    ) -> list[ScoringResult]:
        """Score a whole batch with a single vectorized pass (high throughput).

        The per-sample ``score_sample`` path pays Python-interpreter overhead on
        every row. This method instead evaluates the z-score check for the entire
        batch with numpy array ops and calls the IsolationForest exactly once for
        the batch, which is dramatically faster for bulk auditing / backfill.

        Scoring is performed against the CURRENT baseline (mean/std/model); state
        is then updated in one batch at the end (clean rows only), rather than
        incrementally per row. This keeps the throughput win while preserving the
        "don't let flagged samples pollute the baseline" invariant.

        Args:
            samples: A list of feature vectors or a 2-D numpy array.
            update_state: If True, fold the clean rows into the Welford stats and
                rolling window after scoring. If False, pure read-only scoring.

        Returns:
            List of ScoringResult in input order.
        """
        arr = np.asarray(samples, dtype=np.float64)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        if arr.shape[0] == 0:
            return []

        # Apply reduction to the whole batch at once, if configured.
        if self.reduce_dim is not None:
            if self._reducer is None or not self._reducer._fitted:
                self._reducer = DimensionalityReducer(
                    method=self.reduce_method, n_components=self.reduce_dim
                )
                if self.reduce_method == "gaussian":
                    self._reducer.fit(arr)
                # PCA without a baseline stays pass-through (see _project docstring).
            if self._reducer is not None and self._reducer._fitted:
                arr = np.asarray(self._reducer.transform(arr), dtype=np.float64)

        n, d = arr.shape
        if self._n_features is None:
            self._initialize_features(d)

        # --- vectorized z-score over the whole batch ---
        zscore_anomaly = np.zeros(n, dtype=bool)
        zscore_score = np.zeros(n, dtype=np.float64)
        if self._welford is not None and self._welford.count >= 10:
            std = self._welford.std
            mean = self._welford.mean
            safe_std = np.where(std > 1e-10, std, 1.0)
            z = np.abs((arr - mean) / safe_std)
            max_z = z.max(axis=1)
            zscore_score = np.minimum(max_z / (self.zscore_threshold * 2), 1.0)
            zscore_anomaly = max_z > self.zscore_threshold

        # --- single IsolationForest call for the batch ---
        iso_anomaly = np.zeros(n, dtype=bool)
        iso_score = np.zeros(n, dtype=np.float64)
        have_model = self._model is not None
        if have_model:
            decision = self._model.decision_function(arr)
            iso_anomaly = decision < 0
            iso_score = np.clip(0.5 - decision, 0.0, 1.0)

        # --- aggregate ---
        votes = zscore_anomaly.astype(int) + iso_anomaly.astype(int)
        is_poisoned = votes >= self.vote_threshold

        if have_model:
            final_score = (zscore_score + iso_score) / 2.0
        else:
            final_score = zscore_score

        results: list[ScoringResult] = [
            ScoringResult(
                score=float(final_score[i]),
                is_poisoned=bool(is_poisoned[i]),
                method_votes={
                    "zscore": bool(zscore_anomaly[i]),
                    "isolation_forest": bool(iso_anomaly[i]),
                },
                latency_ms=0.0,
            )
            for i in range(n)
        ]

        # --- bookkeeping ---
        self._samples_seen += n
        self._poison_count += int(is_poisoned.sum())

        if update_state:
            clean_mask = ~is_poisoned
            clean_rows = arr[clean_mask]
            for row in clean_rows:
                if self._welford is not None:
                    self._welford.update(row)
                self._window.append(row)
            self._samples_since_refit += int(clean_mask.sum())
            if len(self._window) > self.window_size:
                self._window = self._window[-self.window_size:]
            if (
                self._samples_since_refit >= self.refit_interval
                and len(self._window) >= 50
            ):
                self._refit_model()

        return results

    def update_baseline(self, clean_samples: list[list[float]] | np.ndarray) -> None:
        """Update the baseline model with known-clean samples.

        Fits a new IsolationForest on the provided samples and resets
        the rolling statistics to match the clean distribution.

        Args:
            clean_samples: Known-clean samples to establish the baseline.
                Should be representative of the expected data distribution.
        """
        clean_arr = np.asarray(clean_samples, dtype=np.float64)
        if clean_arr.ndim == 1:
            clean_arr = clean_arr.reshape(1, -1)

        # Fit dimensionality reduction on the (known-clean) baseline, then work
        # entirely in the reduced space so Welford stats and the IsolationForest
        # match the space score_sample() will operate in.
        if self.reduce_dim is not None:
            self._reducer = DimensionalityReducer(
                method=self.reduce_method, n_components=self.reduce_dim
            )
            clean_arr = np.asarray(
                self._reducer.fit_transform(clean_arr), dtype=np.float64
            )

        n_samples, n_features = clean_arr.shape

        # Initialize or re-initialize feature state
        self._initialize_features(n_features)

        # Update Welford statistics with all clean samples
        for row in clean_arr:
            self._welford.update(row)

        # Fit IsolationForest
        self._model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
        )
        self._model.fit(clean_arr)

        # Set window to clean samples (up to window_size)
        if n_samples <= self.window_size:
            self._window = [row for row in clean_arr]
        else:
            self._window = [row for row in clean_arr[-self.window_size :]]

        self._samples_since_refit = 0

    def get_stats(self) -> StreamStats:
        """Get current detector statistics.

        Returns:
            StreamStats dataclass with current state information.
        """
        poison_rate = 0.0
        if self._samples_seen > 0:
            poison_rate = self._poison_count / self._samples_seen

        avg_latency = 0.0
        if self._samples_seen > 0:
            avg_latency = self._total_latency_ms / self._samples_seen

        window_fill = 0.0
        if self.window_size > 0:
            window_fill = len(self._window) / self.window_size

        baseline_size = len(self._window)

        return StreamStats(
            samples_seen=self._samples_seen,
            poison_count=self._poison_count,
            poison_rate=poison_rate,
            avg_latency_ms=avg_latency,
            drift_detected=self._drift_detected,
            baseline_size=baseline_size,
            window_fill=window_fill,
        )

    def reset(self) -> None:
        """Reset all state to initial conditions.

        Clears the rolling window, statistics, and fitted model.
        Call update_baseline() again after reset.
        """
        self._welford = None
        self._window = []
        self._model = None
        self._samples_since_refit = 0
        self._n_features = None
        self._reducer = None
        self._samples_seen = 0
        self._poison_count = 0
        self._total_latency_ms = 0.0
        self._drift_detected = False

    def _update_state(self, sample: np.ndarray, is_poisoned: bool) -> None:
        """Update internal state with a new sample.

        - Updates Welford statistics only for clean samples (prevents baseline
          corruption from poisoned samples shifting z-score mean/variance)
        - Adds to rolling window if not poisoned (clean samples only)
        - Triggers IsolationForest refit when enough clean samples accumulated

        Args:
            sample: The sample feature vector.
            is_poisoned: Whether this sample was flagged as poisoned.
        """
        # Only add clean samples to the window and Welford stats
        # (avoid poisoning the z-score baseline with flagged samples)
        if not is_poisoned:
            if self._welford is not None:
                self._welford.update(sample)
            self._window.append(sample)
            self._samples_since_refit += 1

            # Trim window if over capacity
            if len(self._window) > self.window_size:
                self._window = self._window[-self.window_size :]

            # Periodic refit
            if self._samples_since_refit >= self.refit_interval and len(self._window) >= 50:
                self._refit_model()

    def _refit_model(self) -> None:
        """Refit the IsolationForest on the current rolling window.

        Only called periodically (every refit_interval clean samples) to
        amortize the O(n * trees * depth) fitting cost.
        """
        window_arr = np.array(self._window)
        self._model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
        )
        self._model.fit(window_arr)
        self._samples_since_refit = 0
