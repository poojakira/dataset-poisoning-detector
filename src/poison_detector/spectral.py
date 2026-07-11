"""
Spectral / SVD-based poisoning detection (covariance-aware).

This is the detector that per-feature statistics structurally cannot be:
z-score and IQR examine one column at a time, so a sample whose every feature
is individually in-range but whose *combination* violates the data covariance
sails straight through them. SVD of the centered feature matrix exposes exactly
that joint structure.

The module computes two complementary SVD-derived signals and combines them,
because -- as the project's own benchmark makes plain -- no single spectral
signal covers every covariance attack:

  1. Spectral signature (Tran, Li & Madry, 2018): projection energy onto the
     TOP-k right singular vectors. Large when poison adds a strong correlated
     shift or forms an off-manifold cluster (backdoor / cluster attacks). This
     is the classic "spectral signature" used to strip backdoors.

  2. Covariance residual (whitened Mahalanobis via the SAME SVD): each sample's
     projection onto every singular direction is normalized by that direction's
     variance. Samples that put unexpected energy into LOW-variance directions
     score highly. This is precisely what a covariance-breaking attack does
     (features individually normal, jointly impossible), and it is the signal
     the top-k projection alone misses.

The public ``spectral_scores`` combines the two by rank-normalizing each and
taking the elementwise maximum, so a sample is flagged if EITHER signal fires.
Both raw signals remain available for callers that want just one.

Threat Model Assumptions:
    - Contamination is a minority. If poison dominates it can define the top
      singular vectors (hiding itself) and inflate the variance estimates the
      covariance residual normalizes by. Spectral methods assume < ~30% poison.
    - The clean majority's covariance is well-estimated by the sample SVD.

Honest Limitations:
    - The covariance residual regularizes tiny singular values (adds a small
      epsilon) to stay numerically stable. Directions with near-zero clean
      variance are therefore slightly down-weighted, which can mask attacks
      confined entirely to a degenerate direction.
    - Both signals are unsupervised outlier scores, not proof of malice. Rare
      but legitimate correlated samples also score highly.
    - Choosing k (top components) is a tuning knob; the default is small.

Security Notes:
    - numpy LAPACK-backed SVD only. No pickle, no eval; deterministic per input.
"""

from __future__ import annotations

import numpy as np


def _svd_components(arr: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Return (centered, projections, per-direction variance) from a single SVD.

    projections[i, j] is sample i's coordinate along right singular vector j.
    variance[j] is the clean-data variance along that direction (s_j^2 / (n-1)).
    """
    centered = arr - arr.mean(axis=0, keepdims=True)
    _, s, vt = np.linalg.svd(centered, full_matrices=False)
    projections = centered @ vt.T
    n = arr.shape[0]
    variance = (s**2) / max(n - 1, 1)
    return centered, projections, variance


def spectral_signature_scores(
    X: list[list[float]] | np.ndarray, n_components: int = 3
) -> list[float]:
    """Top-k spectral signature: projection energy onto leading singular vectors.

    Strong for correlated-additive / backdoor poison and off-manifold clusters.

    Args:
        X: Feature matrix (samples x features).
        n_components: Number of leading singular directions to use.

    Returns:
        Per-sample non-negative scores (empty list for empty input).
    """
    arr = np.asarray(X, dtype=np.float64)
    if arr.ndim != 2 or arr.shape[0] == 0 or arr.shape[1] == 0:
        return []
    try:
        _, projections, _ = _svd_components(arr)
    except np.linalg.LinAlgError:
        return [0.0] * arr.shape[0]
    k = max(1, min(n_components, projections.shape[1]))
    scores = np.sum(projections[:, :k] ** 2, axis=1)
    return [float(v) for v in scores]


def covariance_residual_scores(
    X: list[list[float]] | np.ndarray, reg: float = 1e-6
) -> list[float]:
    """Whitened Mahalanobis distance via SVD: catches covariance-breaking poison.

    Each projection is normalized by its direction's variance, so unexpected
    energy in low-variance directions (the fingerprint of features that are
    individually normal but jointly impossible) produces a high score.

    Args:
        X: Feature matrix (samples x features).
        reg: Regularization added to each direction's variance, as a fraction of
            the mean variance, to keep near-zero directions numerically stable.

    Returns:
        Per-sample non-negative scores (empty list for empty input).
    """
    arr = np.asarray(X, dtype=np.float64)
    if arr.ndim != 2 or arr.shape[0] == 0 or arr.shape[1] == 0:
        return []
    try:
        _, projections, variance = _svd_components(arr)
    except np.linalg.LinAlgError:
        return [0.0] * arr.shape[0]
    eps = reg * float(variance.mean()) if variance.size else reg
    denom = variance + max(eps, 1e-12)
    scores = np.sum(projections**2 / denom, axis=1)
    return [float(v) for v in scores]


def _rank_normalize(values: list[float]) -> np.ndarray:
    """Map scores to [0, 1] by rank so the two signals become comparable."""
    arr = np.asarray(values, dtype=np.float64)
    n = len(arr)
    if n == 0:
        return arr
    order = arr.argsort()
    ranks = np.empty(n, dtype=np.float64)
    ranks[order] = np.arange(n, dtype=np.float64)
    if n > 1:
        ranks /= n - 1
    return ranks


def spectral_scores(
    X: list[list[float]] | np.ndarray, n_components: int = 3
) -> list[float]:
    """Combined spectral score: max of rank-normalized signature and residual.

    A sample is anomalous if EITHER the top-k spectral signature (cluster /
    correlated-additive poison) OR the covariance residual (covariance-breaking
    poison) fires. Combining is what gives spectral broad coverage instead of
    excelling on one attack while failing on another.

    Args:
        X: Feature matrix (samples x features).
        n_components: Leading singular directions for the signature term.

    Returns:
        Per-sample score in [0, 1] (empty list for empty input).
    """
    arr = np.asarray(X, dtype=np.float64)
    if arr.ndim != 2 or arr.shape[0] == 0 or arr.shape[1] == 0:
        return []

    signature = spectral_signature_scores(arr, n_components=n_components)
    residual = covariance_residual_scores(arr)
    if not signature or not residual:
        return signature or residual

    combined = np.maximum(_rank_normalize(signature), _rank_normalize(residual))
    return [float(v) for v in combined]


def spectral_detect(
    X: list[list[float]] | np.ndarray,
    n_components: int = 3,
    quantile: float = 0.95,
) -> list[tuple[int, float]]:
    """Flag samples whose combined spectral score exceeds a high quantile.

    A quantile threshold is used (rather than an absolute cutoff) because the
    combined score is dataset-relative and has no universal scale.

    Args:
        X: Feature matrix.
        n_components: Top singular directions for the signature term.
        quantile: Fraction in (0, 1). Samples at/above this quantile are flagged.

    Returns:
        Sorted list of (sample_index, combined_score) for flagged samples.
    """
    scores = spectral_scores(X, n_components=n_components)
    if not scores:
        return []
    threshold = float(np.quantile(scores, quantile))
    return [(i, s) for i, s in enumerate(scores) if s >= threshold and s > 0.0]
