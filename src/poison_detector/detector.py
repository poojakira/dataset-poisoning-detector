"""
Ensemble poisoning detector combining multiple anomaly detection methods.

This module is the primary entry point for dataset poisoning detection. It
orchestrates z-score, IQR, and Isolation Forest methods and aggregates their
results via majority voting.

Threat Model Assumptions:
    - Different attack strategies leave different statistical fingerprints.
      Z-score catches extreme point outliers, IQR catches robust distributional
      outliers, IsolationForest catches density-based anomalies.
    - Ensemble (majority vote) reduces false positives: a sample must be
      flagged by at least 2 of 3 methods to be considered poisoned.
    - The attacker does NOT have knowledge of which detection methods are in
      use (non-adaptive adversary). An adaptive adversary who knows the exact
      ensemble configuration can craft samples that evade all three methods.

Defense-in-Depth Reasoning:
    - No single method is sufficient. Z-score fails on non-Gaussian data,
      IQR misses within-fence attacks, IsolationForest is fooled by masking
      in high dimensions.
    - Majority vote is deliberately conservative: we accept higher false
      negatives in exchange for lower false positives, because flagging clean
      data for manual review wastes analyst time.
    - Each method uses independent statistical assumptions. Correlated failures
      are unlikely (but not impossible -- see limitations).

Honest Limitations:
    - Ensemble majority vote is a simple aggregation. It does not weight
      methods by confidence or reliability for the given data distribution.
    - All methods are unsupervised. They detect statistical anomalies, not
      malicious intent. A legitimate rare sample and a poisoned sample look
      identical to these methods.
    - No temporal awareness: cannot detect slow-drip poisoning where each
      batch is individually clean but the cumulative effect corrupts the model.
    - Scores from different methods are NOT directly comparable. A z-score of
      4.0 and an isolation score of 0.8 measure different things.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .statistical import zscore_detect, iqr_detect
from .isolation import IsolationDetector
from .attribution import feature_attribution
from .spectral import spectral_detect


@dataclass
class PoisonResult:
    """Detection result for a single sample.

    Attributes:
        sample_idx: Index of the sample in the input matrix.
        anomaly_score: Aggregate anomaly score (method-dependent).
        method: Detection method that produced this result.
        features_flagged: List of feature indices that contributed most.
        is_poisoned: Whether the sample exceeds the detection threshold.
    """

    sample_idx: int
    anomaly_score: float
    method: str
    features_flagged: list[int] = field(default_factory=list)
    is_poisoned: bool = False


@dataclass
class DetectionReport:
    """Complete detection report for a dataset scan.

    Attributes:
        total_samples: Number of samples analyzed.
        poisoned_count: Number of samples flagged as poisoned.
        method_scores: Per-method summary scores (e.g., count flagged per method).
        per_sample: Detailed per-sample results.
    """

    total_samples: int
    poisoned_count: int
    method_scores: dict[str, float] = field(default_factory=dict)
    per_sample: list[PoisonResult] = field(default_factory=list)


def detect(X: list[list[float]], method: str = "ensemble", labels: list[int] | None = None) -> DetectionReport:
    """Run poisoning detection on a feature matrix.

    This is the main entry point. Takes a raw feature matrix and returns
    a structured report with per-sample anomaly scores and poison flags.

    Args:
        X: Feature matrix as list of lists. Each inner list is one sample.
            All samples must have the same number of features.
        method: Detection method to use. One of:
            - "zscore": Z-score based detection (pure Python)
            - "iqr": IQR fencing (pure Python)
            - "isolation": Isolation Forest (scikit-learn)
            - "ensemble": Majority vote across all three (default)
            - "spectral": Spectral signature analysis (requires labels)
        labels: Integer class labels for each sample. REQUIRED for "spectral"
            method. For label-flip poisoning detection, this is the only
            method that actually works (feature-space methods cannot detect
            label-only corruptions).

    Returns:
        DetectionReport with per-sample results and summary statistics.

    Raises:
        ValueError: If method is not one of the supported methods.
        ValueError: If labels is None when method="spectral".
    """
    valid_methods = {"zscore", "iqr", "isolation", "ensemble", "spectral"}
    if method not in valid_methods:
        raise ValueError(f"Unknown method '{method}'. Must be one of {valid_methods}")

    n_samples = len(X)

    if method == "spectral":
        if labels is None:
            raise ValueError(
                "labels are required for spectral detection. "
                "Spectral signatures analyze the covariance structure "
                "WITHIN each class to find mislabeled samples."
            )
        return _spectral_report(X, labels)

    if method == "ensemble":
        return _ensemble_detect(X)

    if method == "zscore":
        return _zscore_report(X)

    if method == "iqr":
        return _iqr_report(X)

    if method == "isolation":
        return _isolation_report(X)

    raise ValueError(f"Unhandled method: {method}")  # pragma: no cover


def _zscore_report(X: list[list[float]]) -> DetectionReport:
    """Generate report using z-score detection only."""
    n_samples = len(X)
    flagged = zscore_detect(X)
    flagged_indices = [idx for idx, _ in flagged]
    flagged_set = set(flagged_indices)
    score_map = {idx: score for idx, score in flagged}

    attr = feature_attribution(X, flagged_indices)

    per_sample: list[PoisonResult] = []
    for i in range(n_samples):
        is_poisoned = i in flagged_set
        score = score_map.get(i, 0.0)
        features = [f_idx for f_idx, _ in attr.get(i, [])[:3]]
        per_sample.append(
            PoisonResult(
                sample_idx=i,
                anomaly_score=score,
                method="zscore",
                features_flagged=features,
                is_poisoned=is_poisoned,
            )
        )

    return DetectionReport(
        total_samples=n_samples,
        poisoned_count=len(flagged),
        method_scores={"zscore": len(flagged)},
        per_sample=per_sample,
    )


def _iqr_report(X: list[list[float]]) -> DetectionReport:
    """Generate report using IQR detection only."""
    n_samples = len(X)
    flagged = iqr_detect(X)
    flagged_indices = [idx for idx, _ in flagged]
    flagged_set = set(flagged_indices)
    score_map = {idx: score for idx, score in flagged}

    attr = feature_attribution(X, flagged_indices)

    per_sample: list[PoisonResult] = []
    for i in range(n_samples):
        is_poisoned = i in flagged_set
        score = score_map.get(i, 0.0)
        features = [f_idx for f_idx, _ in attr.get(i, [])[:3]]
        per_sample.append(
            PoisonResult(
                sample_idx=i,
                anomaly_score=score,
                method="iqr",
                features_flagged=features,
                is_poisoned=is_poisoned,
            )
        )

    return DetectionReport(
        total_samples=n_samples,
        poisoned_count=len(flagged),
        method_scores={"iqr": len(flagged)},
        per_sample=per_sample,
    )


def _isolation_report(X: list[list[float]]) -> DetectionReport:
    """Generate report using Isolation Forest detection only."""
    n_samples = len(X)
    detector = IsolationDetector()
    results = detector.fit_predict(X)

    predictions = detector._model.predict(X)
    flagged_indices = [i for i, pred in enumerate(predictions) if pred == -1]
    flagged_set = set(flagged_indices)
    score_map = {idx: score for idx, score in results}

    attr = feature_attribution(X, flagged_indices)

    per_sample: list[PoisonResult] = []
    for i in range(n_samples):
        is_poisoned = i in flagged_set
        score = score_map.get(i, 0.0)
        features = [f_idx for f_idx, _ in attr.get(i, [])[:3]]
        per_sample.append(
            PoisonResult(
                sample_idx=i,
                anomaly_score=score,
                method="isolation",
                features_flagged=features,
                is_poisoned=is_poisoned,
            )
        )

    return DetectionReport(
        total_samples=n_samples,
        poisoned_count=len(flagged_indices),
        method_scores={"isolation": len(flagged_indices)},
        per_sample=per_sample,
    )


def _ensemble_detect(X: list[list[float]]) -> DetectionReport:
    """Ensemble detection using majority vote across all methods.

    A sample is flagged as poisoned only if at least 2 out of 3 methods
    agree it is anomalous. This reduces false positives at the cost of
    potentially missing borderline cases that only one method catches.
    """
    n_samples = len(X)

    zscore_flagged = set(idx for idx, _ in zscore_detect(X))
    iqr_flagged = set(idx for idx, _ in iqr_detect(X))

    iso_detector = IsolationDetector()
    iso_results = iso_detector.fit_predict(X)
    iso_predictions = iso_detector._model.predict(X)
    iso_flagged = set(i for i, pred in enumerate(iso_predictions) if pred == -1)

    iso_score_map = {idx: score for idx, score in iso_results}

    ensemble_flagged: set[int] = set()
    for i in range(n_samples):
        votes = sum(
            [
                i in zscore_flagged,
                i in iqr_flagged,
                i in iso_flagged,
            ]
        )
        if votes >= 2:
            ensemble_flagged.add(i)

    attr = feature_attribution(X, sorted(ensemble_flagged))

    per_sample: list[PoisonResult] = []
    for i in range(n_samples):
        is_poisoned = i in ensemble_flagged
        score = iso_score_map.get(i, 0.0)
        features = [f_idx for f_idx, _ in attr.get(i, [])[:3]]
        per_sample.append(
            PoisonResult(
                sample_idx=i,
                anomaly_score=score,
                method="ensemble",
                features_flagged=features,
                is_poisoned=is_poisoned,
            )
        )

    return DetectionReport(
        total_samples=n_samples,
        poisoned_count=len(ensemble_flagged),
        method_scores={
            "zscore": len(zscore_flagged),
            "iqr": len(iqr_flagged),
            "isolation": len(iso_flagged),
        },
        per_sample=per_sample,
    )


def _spectral_report(X: list[list[float]], labels: list[int]) -> DetectionReport:
    """Generate report using spectral signature detection.

    This is the recommended method for label-flip poisoning. It examines
    the covariance structure within each class — poisoned samples (which
    have the wrong label) will have high projection onto the top singular
    vector of their assigned class.
    """
    report = spectral_detect(X, labels)

    per_sample: list[PoisonResult] = []
    for result in report.results:
        per_sample.append(
            PoisonResult(
                sample_idx=result.sample_idx,
                anomaly_score=result.projection_score,
                method="spectral",
                features_flagged=[],  # spectral works on projections, not individual features
                is_poisoned=result.is_poisoned,
            )
        )

    # Sort by sample index for consistent output
    per_sample.sort(key=lambda r: r.sample_idx)

    return DetectionReport(
        total_samples=report.total_samples,
        poisoned_count=report.poisoned_count,
        method_scores={"spectral": report.poisoned_count},
        per_sample=per_sample,
    )
