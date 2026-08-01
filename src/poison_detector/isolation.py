"""
Isolation Forest wrapper for dataset poisoning detection.

Wraps scikit-learn's IsolationForest with a consistent interface that returns
anomaly scores normalized to [0, 1] range for all samples, not just flagged ones.

Threat Model Assumptions:
    - Poisoned samples are isolatable -- they occupy sparse regions of feature
      space that require fewer random splits to separate.
    - The contamination parameter approximates the expected poison rate. Setting
      this too low misses attacks; too high produces false positives.
    - Feature space is meaningful: random forests split on raw feature values,
      so features should be at comparable scales for balanced splitting.

Honest Limitations:
    - IsolationForest is a density-based method. It catches point anomalies and
      small cluster anomalies but CANNOT detect:
        * Clean-label attacks (in-distribution features, wrong labels)
        * Distributed poisoning where each sample is individually normal but
          collectively shifts the decision boundary
        * Backdoor triggers that activate only on specific input patterns
    - The contamination parameter is a guess. In practice, you rarely know
      the true poison rate a priori. Cross-validation on held-out clean data
      is recommended but not enforced here.
    - Scores are relative to the training set. Adding or removing samples
      changes all scores (non-stationary).

Why scikit-learn:
    - Widely used scikit-learn implementation with known algorithmic properties.
    - Reproducible via random_state parameter.
    - NOT auditable at the Python level (Cython internals), which is why
      this module is paired with pure-Python statistical methods for
      defense-in-depth.
"""

from __future__ import annotations

from sklearn.ensemble import IsolationForest


class IsolationDetector:
    """Isolation Forest-based anomaly detector with normalized scoring.

    Converts sklearn's convention (lower score = more anomalous) to an
    intuitive 0-1 scale where higher = more anomalous.

    The normalization uses min-max scaling of sklearn's raw anomaly scores:
        normalized = (max_score - raw_score) / (max_score - min_score)

    This means scores are RELATIVE, not absolute. A score of 0.8 means
    "more anomalous than 80% of this dataset" -- not "80% likely to be
    poisoned." Thresholding decisions should be made on the relative
    distribution, not on absolute cutoffs.
    """

    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        """Initialize with contamination estimate and random seed.

        Args:
            contamination: Expected proportion of anomalies. Must be in (0, 0.5].
                This directly controls the decision threshold but does NOT
                affect the anomaly scores themselves.
            random_state: Random seed for reproducibility.
        """
        self.contamination = contamination
        self.random_state = random_state
        self._model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100,
        )

    def fit_predict(self, X: list[list[float]]) -> list[tuple[int, float]]:
        """Fit the model and return anomaly scores for ALL samples.

        Unlike the statistical methods which only return flagged samples,
        this returns scores for every sample. The caller can threshold as needed.

        Args:
            X: Feature matrix as list of lists. Each inner list is one sample.

        Returns:
            List of (sample_index, anomaly_score) for ALL samples.
            Scores are in [0, 1] range where higher = more anomalous.
            Sorted by sample index.
        """
        self._model.fit(X)

        raw_scores = self._model.score_samples(X)

        min_score = min(raw_scores)
        max_score = max(raw_scores)

        if max_score == min_score:
            return [(i, 0.5) for i in range(len(X))]

        normalized = []
        for i, score in enumerate(raw_scores):
            norm_score = (max_score - score) / (max_score - min_score)
            normalized.append((i, float(norm_score)))

        return normalized
