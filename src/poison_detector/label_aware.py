"""
Label-aware poisoning detection (kNN label-disagreement / confident-learning style).

Every other detector in this project is feature-only: it looks at where a
sample sits in feature space and asks "is this an outlier?". That is blind to
the single most common real-world poisoning attack -- LABEL FLIPPING -- where
the attacker takes a perfectly ordinary feature vector and simply attaches the
wrong label. Nothing about the features is anomalous, so z-score, IQR,
IsolationForest and even spectral signatures all pass it.

This module closes that gap. It requires labels (the data model now optionally
carries them) and flags a sample when its label disagrees with the consensus
label of its nearest neighbors in feature space.

Method:
    For each sample, find its k nearest neighbors (excluding itself) among all
    samples. Compute the fraction of those neighbors whose label differs from
    the sample's own label. A high disagreement fraction means "everything that
    looks like me is labeled differently" -- the hallmark of a flipped label.
    This is the intuition behind confident-learning / kNN label-noise methods.

Threat Model Assumptions:
    - The clean majority in any local neighborhood carries the correct label,
      so a flipped sample is surrounded by correctly-labeled neighbors.
    - Classes are at least locally separable in feature space. Where classes
      genuinely overlap, disagreement is high for clean points too and the
      signal weakens (documented below).

Honest Limitations:
    - In regions where two classes overlap heavily, honest samples also
      disagree with their neighbors, inflating false positives. This detector
      is strongest on well-separated classes.
    - kNN is O(n^2) naive; we use scikit-learn's KDTree/BallTree via
      NearestNeighbors which is fine to tens of thousands of rows but is not a
      streaming, per-sample method. It is a batch auditing tool.
    - It cannot detect label flips that move a sample to a label that its
      neighbors ALSO carry (i.e., genuinely ambiguous boundary points).

Security Notes:
    - Pure numpy + scikit-learn NearestNeighbors. No pickle, no eval.
    - Deterministic given the input (kNN ties broken by index order).
"""

from __future__ import annotations

import numpy as np
from sklearn.neighbors import NearestNeighbors


def label_disagreement_scores(
    X: list[list[float]] | np.ndarray,
    y: list[int] | np.ndarray,
    n_neighbors: int = 10,
) -> list[float]:
    """Score every sample by how much its label disagrees with its neighbors.

    Args:
        X: Feature matrix (samples x features).
        y: Integer labels aligned with X.
        n_neighbors: Number of nearest neighbors to consult (excluding self).
            Clamped to at most n_samples - 1.

    Returns:
        List of floats in [0, 1], one per sample. 0 = label matches all
        neighbors, 1 = label differs from every neighbor. Empty list for
        empty input.

    Raises:
        ValueError: If len(X) != len(y).
    """
    arr = np.asarray(X, dtype=np.float64)
    labels = np.asarray(y)
    if arr.ndim != 2 or arr.shape[0] == 0:
        return []
    if len(labels) != arr.shape[0]:
        raise ValueError("X and y must have the same number of rows")

    n_samples = arr.shape[0]
    if n_samples < 2:
        return [0.0] * n_samples

    k = min(n_neighbors, n_samples - 1)

    # Query k+1 because the nearest neighbor of a point is itself.
    nn = NearestNeighbors(n_neighbors=k + 1)
    nn.fit(arr)
    _, indices = nn.kneighbors(arr)

    scores: list[float] = []
    for i in range(n_samples):
        neighbor_idx = [j for j in indices[i] if j != i][:k]
        if not neighbor_idx:
            scores.append(0.0)
            continue
        neighbor_labels = labels[neighbor_idx]
        disagreement = float(np.mean(neighbor_labels != labels[i]))
        scores.append(disagreement)

    return scores


def label_aware_detect(
    X: list[list[float]] | np.ndarray,
    y: list[int] | np.ndarray,
    n_neighbors: int = 10,
    threshold: float = 0.7,
) -> list[tuple[int, float]]:
    """Flag samples whose label disagrees with most of their neighbors.

    Args:
        X: Feature matrix.
        y: Integer labels aligned with X.
        n_neighbors: Neighbors to consult per sample.
        threshold: Disagreement fraction in [0, 1] above which a sample is
            flagged. Default 0.7 means "more than 70% of my neighbors carry a
            different label" -- deliberately conservative to limit false
            positives in overlapping regions.

    Returns:
        Sorted list of (sample_index, disagreement_score) for flagged samples.
    """
    scores = label_disagreement_scores(X, y, n_neighbors=n_neighbors)
    return [(i, s) for i, s in enumerate(scores) if s >= threshold]
