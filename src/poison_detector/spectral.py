"""
poison_detector/spectral.py
────────────────────────────────────────────────────────────────────────────────
Spectral signature detection for dataset poisoning.

Implements the key insight from Tran et al. (2018) "Spectral Signatures in
Backdoor Attacks": poisoned samples leave a detectable trace in the covariance
spectrum of learned representations. Specifically, if we compute the top
singular vector of the centered representation matrix for each class, poisoned
samples will have unusually high correlation with that direction.

Why this works when z-score/IQR fails:
    - Z-score and IQR only detect feature-space outliers. Label-flip attacks
      don't change features, so they're invisible to those methods.
    - Spectral signatures work on the REPRESENTATION SPACE conditioned on
      labels. A flipped sample has the wrong label, so when we look at
      the covariance structure within its (incorrectly) assigned class, it
      stands out as having high projection onto the top singular vector.

Algorithm:
    1. Separate samples by label.
    2. For each class, center the features and compute SVD.
    3. Project each sample onto the top-k singular vectors.
    4. Samples with projection magnitude exceeding a threshold are flagged.

The threshold is set using the interquartile range of projection scores
within each class — this makes it robust to varying data distributions.

Reference:
    Tran, B., Li, J., & Madry, A. (2018). "Spectral Signatures in Backdoor
    Attacks." NeurIPS 2018.

Dependencies:
    - numpy (for SVD computation)
    - No scikit-learn required for the core algorithm
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

import numpy as np


@dataclass
class SpectralResult:
    """Detection result from spectral signature analysis.

    Attributes:
        sample_idx: Original index in the full dataset.
        label: The assigned label for this sample.
        projection_score: Magnitude of projection onto top singular vector.
        threshold: The class-specific threshold used.
        is_poisoned: Whether projection exceeds threshold.
        rank_in_class: Rank of this sample's score within its class (1 = most suspicious).
    """

    sample_idx: int
    label: int
    projection_score: float
    threshold: float
    is_poisoned: bool
    rank_in_class: int = 0


@dataclass
class SpectralReport:
    """Complete spectral analysis report.

    Attributes:
        total_samples: Total samples analyzed.
        poisoned_count: Number of flagged samples.
        per_class_stats: Summary statistics per class.
        results: Per-sample results sorted by suspicion score.
    """

    total_samples: int
    poisoned_count: int
    per_class_stats: dict[int, dict[str, Any]] = field(default_factory=dict)
    results: list[SpectralResult] = field(default_factory=list)


def spectral_detect(
    X: list[list[float]] | np.ndarray,
    labels: list[int] | np.ndarray,
    *,
    n_components: int = 1,
    iqr_multiplier: float = 1.5,
    min_class_size: int = 5,
) -> SpectralReport:
    """Detect poisoned samples using spectral signature analysis.

    This is the primary entry point for label-aware poisoning detection.
    It examines the covariance structure within each class to find samples
    whose representations are inconsistent with their assigned labels.

    Parameters
    ----------
    X : array-like of shape (n_samples, n_features)
        Feature matrix. Can be raw features or learned representations.
        Works best with representations from a trained model's penultimate
        layer, but also works on raw features for simple datasets.

    labels : array-like of shape (n_samples,)
        Integer class labels for each sample. These are the ASSIGNED labels
        (which may be wrong for poisoned samples).

    n_components : int, default=1
        Number of top singular vectors to use for projection.
        1 is usually sufficient for detecting single-source attacks.
        Increase to 2-3 for multi-source or distributed attacks.

    iqr_multiplier : float, default=1.5
        Multiplier for IQR-based threshold. Higher = fewer false positives
        but more missed poisons. Standard box-plot fence is 1.5.
        Use 1.0 for aggressive detection, 2.0 for conservative.

    min_class_size : int, default=5
        Minimum samples per class to perform spectral analysis.
        Classes with fewer samples are skipped (not enough data for SVD).

    Returns
    -------
    SpectralReport
        Contains per-sample scores, flags, and class-level statistics.

    Notes
    -----
    The algorithm computes O(n_classes * n_features * min(n_samples, n_features))
    for the SVD step, which is efficient for typical ML datasets but may be
    slow for very high-dimensional data (>10K features). In that case, use
    PCA-reduced representations or model embeddings as input.
    """
    X_arr = np.asarray(X, dtype=np.float64)
    labels_arr = np.asarray(labels, dtype=np.int64)

    if X_arr.size == 0:
        return SpectralReport(total_samples=0, poisoned_count=0)

    if X_arr.ndim != 2:
        raise ValueError(f"X must be 2-dimensional, got shape {X_arr.shape}")
    if labels_arr.ndim != 1:
        raise ValueError(f"labels must be 1-dimensional, got shape {labels_arr.shape}")
    if len(X_arr) != len(labels_arr):
        raise ValueError(f"X and labels must have same length: {len(X_arr)} vs {len(labels_arr)}")
    if len(X_arr) == 0:
        return SpectralReport(total_samples=0, poisoned_count=0)

    n_samples, n_features = X_arr.shape
    unique_labels = np.unique(labels_arr)

    all_results: list[SpectralResult] = []
    per_class_stats: dict[int, dict[str, Any]] = {}

    for class_label in unique_labels:
        class_label_int = int(class_label)
        # Get indices of samples assigned to this class
        class_mask = labels_arr == class_label
        class_indices = np.where(class_mask)[0]
        class_size = len(class_indices)

        if class_size < min_class_size:
            # Not enough samples for meaningful SVD
            per_class_stats[class_label_int] = {
                "size": class_size,
                "skipped": True,
                "reason": f"class size {class_size} < min_class_size {min_class_size}",
            }
            continue

        # Extract class-specific feature matrix and center it
        X_class = X_arr[class_indices]
        X_centered = X_class - X_class.mean(axis=0)

        # Compute SVD — we only need the top-k left singular vectors
        # For efficiency, use truncated SVD when class is large
        try:
            if class_size > n_features:
                # More samples than features: compute on X_centered directly
                U, S, Vt = np.linalg.svd(X_centered, full_matrices=False)
            else:
                U, S, Vt = np.linalg.svd(X_centered, full_matrices=False)
        except np.linalg.LinAlgError:
            # SVD failed (degenerate matrix) — skip this class
            per_class_stats[class_label_int] = {
                "size": class_size,
                "skipped": True,
                "reason": "SVD failed (degenerate matrix)",
            }
            continue

        # Use top-k right singular vectors (principal directions)
        # Each sample's "spectral score" is its projection magnitude onto these
        top_k = min(n_components, len(S))
        V_top = Vt[:top_k]  # shape: (top_k, n_features)

        # Project each centered sample onto the top-k directions
        projections = X_centered @ V_top.T  # shape: (class_size, top_k)
        # Combine projections into a single score (L2 norm of projection vector)
        scores = np.linalg.norm(projections, axis=1)

        # Compute threshold using IQR method (robust to outliers)
        q1 = np.percentile(scores, 25)
        q3 = np.percentile(scores, 75)
        iqr = q3 - q1
        threshold = q3 + iqr_multiplier * iqr

        # Explained variance ratio for diagnostics
        total_var = np.sum(S**2)
        explained_var = np.sum(S[:top_k] ** 2) / total_var if total_var > 0 else 0.0

        # Rank samples within this class by score (descending)
        sorted_local_indices = np.argsort(-scores)
        rank_map = {idx: rank + 1 for rank, idx in enumerate(sorted_local_indices)}

        # Generate per-sample results
        flagged_count = 0
        for local_idx in range(class_size):
            global_idx = int(class_indices[local_idx])
            score = float(scores[local_idx])
            is_poisoned = score > threshold
            if is_poisoned:
                flagged_count += 1

            all_results.append(
                SpectralResult(
                    sample_idx=global_idx,
                    label=class_label_int,
                    projection_score=round(score, 6),
                    threshold=round(threshold, 6),
                    is_poisoned=is_poisoned,
                    rank_in_class=rank_map[local_idx],
                )
            )

        per_class_stats[class_label_int] = {
            "size": class_size,
            "skipped": False,
            "flagged": flagged_count,
            "threshold": round(threshold, 6),
            "q1": round(q1, 6),
            "q3": round(q3, 6),
            "iqr": round(iqr, 6),
            "top_singular_value": round(float(S[0]), 6) if len(S) > 0 else 0.0,
            "explained_variance_ratio": round(explained_var, 4),
            "mean_score": round(float(np.mean(scores)), 6),
            "max_score": round(float(np.max(scores)), 6),
        }

    # Sort results by projection score descending (most suspicious first)
    all_results.sort(key=lambda r: r.projection_score, reverse=True)
    poisoned_count = sum(1 for r in all_results if r.is_poisoned)

    return SpectralReport(
        total_samples=n_samples,
        poisoned_count=poisoned_count,
        per_class_stats=per_class_stats,
        results=all_results,
    )


def detect_label_flips(
    X: list[list[float]] | np.ndarray,
    labels: list[int] | np.ndarray,
    *,
    contamination_estimate: float = 0.05,
    n_components: int = 1,
) -> list[int]:
    """Convenience function: return indices of likely label-flip poisoned samples.

    Uses a percentile-based threshold instead of IQR, calibrated to the
    expected contamination rate.

    Parameters
    ----------
    X : array-like of shape (n_samples, n_features)
        Feature matrix.
    labels : array-like of shape (n_samples,)
        Assigned integer labels.
    contamination_estimate : float, default=0.05
        Expected fraction of poisoned samples. Used to set the threshold
        at the (1 - contamination) percentile of projection scores.
    n_components : int, default=1
        Number of spectral components.

    Returns
    -------
    list[int]
        Indices of suspected poisoned samples, sorted by score (most suspicious first).
    """
    X_arr = np.asarray(X, dtype=np.float64)
    labels_arr = np.asarray(labels, dtype=np.int64)

    if len(X_arr) == 0:
        return []

    unique_labels = np.unique(labels_arr)
    suspected: list[tuple[int, float]] = []  # (global_idx, score)

    for class_label in unique_labels:
        class_mask = labels_arr == class_label
        class_indices = np.where(class_mask)[0]
        class_size = len(class_indices)

        if class_size < 5:
            continue

        X_class = X_arr[class_indices]
        X_centered = X_class - X_class.mean(axis=0)

        try:
            _, S, Vt = np.linalg.svd(X_centered, full_matrices=False)
        except np.linalg.LinAlgError:
            continue

        top_k = min(n_components, len(S))
        V_top = Vt[:top_k]
        projections = X_centered @ V_top.T
        scores = np.linalg.norm(projections, axis=1)

        # Threshold at (1 - contamination) percentile
        cutoff_percentile = (1.0 - contamination_estimate) * 100
        threshold = np.percentile(scores, cutoff_percentile)

        for local_idx in range(class_size):
            if scores[local_idx] > threshold:
                global_idx = int(class_indices[local_idx])
                suspected.append((global_idx, float(scores[local_idx])))

    # Sort by score descending
    suspected.sort(key=lambda x: x[1], reverse=True)
    return [idx for idx, _ in suspected]


def detect_label_flips_crossclass(
    X: list[list[float]] | np.ndarray,
    labels: list[int] | np.ndarray,
    *,
    contamination_estimate: float = 0.05,
) -> list[int]:
    """Cross-class centroid detector for label-flip poisoning (strongest method).

    Key insight
    -----------
    A label-flip does not perturb features — it moves a genuine class-A sample
    into class B's label set. Such a sample therefore sits **closer to class A's
    centroid than to its (wrongly) assigned class B centroid**. Within-class
    spectral variance (Tran et al. top-1) only partially captures this; the
    direct cross-class comparison captures it strongly.

    Algorithm
    ---------
    For every sample assigned to class ``c`` with robust (median) centroids
    ``m_k`` per class::

        score(x) = || x - m_c ||  -  min_{k != c} || x - m_k ||

    A positive, large score means the sample is closer to some *other* class's
    centroid than to its own — the signature of a flipped sample. The top
    ``contamination_estimate`` fraction per class is flagged.

    Robustness: medians resist the poisoned subgroup; the score is
    scale-consistent and needs no threshold tuning beyond the contamination
    budget. Complexity is O(n_samples * n_classes * n_features).

    Returns indices of suspected flipped samples, most suspicious first.
    """
    X_arr = np.asarray(X, dtype=np.float64)
    labels_arr = np.asarray(labels, dtype=np.int64)
    if len(X_arr) == 0:
        return []

    classes = np.unique(labels_arr)
    if len(classes) < 2:
        return []

    centres = {int(c): np.median(X_arr[labels_arr == c], axis=0) for c in classes}
    suspected: list[tuple[int, float]] = []
    n_total = len(labels_arr)

    for c in classes:
        idx = np.where(labels_arr == c)[0]
        if len(idx) < 5:
            continue
        Xc = X_arr[idx]
        own = np.linalg.norm(Xc - centres[int(c)], axis=1)
        others = np.min(
            [np.linalg.norm(Xc - centres[int(o)], axis=1) for o in classes if o != c],
            axis=0,
        )
        score = own - others  # positive => closer to another class => likely flipped
        per_class_flag = max(1, int(round(contamination_estimate * n_total * len(idx) / n_total)))
        order = np.argsort(-score)
        for li in order[:per_class_flag]:
            suspected.append((int(idx[li]), float(score[li])))

    suspected.sort(key=lambda x: x[1], reverse=True)
    return [idx for idx, _ in suspected]


def detect_label_flips_robust(
    X: list[list[float]] | np.ndarray,
    labels: list[int] | np.ndarray,
    *,
    contamination_estimate: float = 0.05,
    n_components: int = 8,
    ridge: float = 1e-3,
) -> list[int]:
    """Improved label-flip detector (robust spectral + Mahalanobis scoring).

    Why this beats the top-1 percentile approach on label-flip attacks
    ------------------------------------------------------------------
    A label-flip injects class-0 embeddings into class 1. Those samples do NOT
    necessarily maximise the projection onto class 1's top-1 singular vector,
    which is why the original ``detect_label_flips`` (top-1, mean-centred,
    percentile) recovers only a fraction of them.

    This detector instead:
      1. Centres each class on its **coordinate-wise median** (robust to the
         poisoned subgroup, which drags the mean toward class 0).
      2. Works in the **top-k spectral subspace** (default k=8) so the
         discriminative directions that separate the injected cluster are
         retained, not just the single dominant variance axis.
      3. Scores each sample by its **whitened (Mahalanobis-style) distance** in
         that subspace, so a coherent off-centroid cluster of flipped samples
         stands out strongly.
      4. Flags the top ``contamination_estimate`` fraction per class.

    The math stays O(n_classes * n_features * min(n, n_features)) — the same
    complexity class as the original SVD approach.

    Parameters mirror ``detect_label_flips``; ``ridge`` stabilises the whitening
    when singular values are small.
    """
    X_arr = np.asarray(X, dtype=np.float64)
    labels_arr = np.asarray(labels, dtype=np.int64)
    if len(X_arr) == 0:
        return []

    unique_labels = np.unique(labels_arr)
    suspected: list[tuple[int, float]] = []

    for class_label in unique_labels:
        class_indices = np.where(labels_arr == class_label)[0]
        class_size = len(class_indices)
        if class_size < 5:
            continue

        X_class = X_arr[class_indices]
        # Robust centre: coordinate-wise median resists the poisoned subgroup.
        centre = np.median(X_class, axis=0)
        Xc = X_class - centre

        try:
            _, S, Vt = np.linalg.svd(Xc, full_matrices=False)
        except np.linalg.LinAlgError:
            continue

        k = min(n_components, len(S))
        V_top = Vt[:k]                      # (k, n_features)
        proj = Xc @ V_top.T                 # (class_size, k)

        # Whiten by singular values (Mahalanobis in the retained subspace).
        denom = (S[:k] / np.sqrt(max(class_size - 1, 1))) + ridge
        whitened = proj / denom
        scores = np.linalg.norm(whitened, axis=1)

        # Flag the top-`contamination` fraction within this class.
        n_flag = max(1, int(round(contamination_estimate * len(labels_arr))))
        # distribute per-class proportional to class share of the flag budget
        per_class_flag = min(class_size, max(1, int(round(n_flag * class_size / len(labels_arr)))))
        order = np.argsort(-scores)
        for local_idx in order[:per_class_flag]:
            suspected.append((int(class_indices[local_idx]), float(scores[local_idx])))

    suspected.sort(key=lambda x: x[1], reverse=True)
    return [idx for idx, _ in suspected]
