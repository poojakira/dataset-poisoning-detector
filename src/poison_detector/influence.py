"""
Loss- and influence-based poisoning scoring via a cheap surrogate model.

Top labs increasingly triage suspected poison by asking a supervised question
that unsupervised outlier detectors never ask: "does this labeled sample hurt
the model?" A poisoned sample -- especially a label-flipped or boundary-shifting
one -- tends to be hard for a model to fit (high per-sample loss) and to exert
outsized pull on the decision boundary (high influence).

This module provides two APPROXIMATE, deliberately cheap scorers:

    1. loss_scores        : train a surrogate classifier on all data, then score
                            each sample by its own training loss (log-loss of the
                            true label). Mislabeled / off-manifold points have
                            high loss. This is a fast proxy for "is this sample
                            inconsistent with the pattern the model learned?".

    2. influence_scores   : a leave-one-out-flavored self-influence proxy. We
                            compare the surrogate's confidence in a sample's own
                            label to the average confidence, so points the model
                            is forced to memorize (typical of poison) stand out.

Both are honest APPROXIMATIONS of the exact influence-function machinery
(Koh & Liang, 2017), which requires Hessian-vector products that are far too
expensive for a streaming security tool. We trade exactness for speed and say
so loudly.

Threat Model Assumptions:
    - Labels are available (this is a supervised signal). Without labels, use the
      unsupervised detectors instead.
    - The surrogate model is expressive enough to fit the clean majority but not
      so flexible that it memorizes poison without penalty. Logistic regression
      is a good default: linear, fast, and reveals mislabeled points as high loss.

Honest Limitations:
    - This is NOT the exact influence function. It is a loss/confidence proxy.
      It will disagree with exact leave-one-out retraining on hard cases.
    - Trained on contaminated data, so the surrogate is itself slightly poisoned.
      For heavy contamination the signal degrades.
    - Multiclass log-loss requires probability estimates; we clip probabilities
      away from 0/1 to keep the loss finite.

Security Notes:
    - scikit-learn LogisticRegression only; no pickle of untrusted models.
    - Deterministic via fixed random_state.
"""

from __future__ import annotations

import numpy as np
from sklearn.linear_model import LogisticRegression


def _fit_surrogate(
    arr: np.ndarray, labels: np.ndarray, max_iter: int
) -> LogisticRegression | None:
    """Fit a cheap logistic-regression surrogate; return None if infeasible."""
    if len(np.unique(labels)) < 2:
        return None
    # NOTE: the ``multi_class`` argument was removed in scikit-learn 1.7+;
    # multinomial handling is now automatic, so we simply omit it.
    model = LogisticRegression(
        max_iter=max_iter,
        random_state=42,
    )
    try:
        model.fit(arr, labels)
    except ValueError:
        return None
    return model


def loss_scores(
    X: list[list[float]] | np.ndarray,
    y: list[int] | np.ndarray,
    max_iter: int = 200,
) -> list[float]:
    """Score each sample by its surrogate-model log-loss on its own label.

    Args:
        X: Feature matrix.
        y: Integer labels aligned with X.
        max_iter: Max iterations for the logistic-regression surrogate.

    Returns:
        List of non-negative floats (per-sample log-loss). Higher = the model
        finds this labeled sample harder / more inconsistent. Returns zeros if a
        surrogate cannot be fit (e.g., a single class present).

    Raises:
        ValueError: If len(X) != len(y).
    """
    arr = np.asarray(X, dtype=np.float64)
    labels = np.asarray(y)
    if arr.ndim != 2 or arr.shape[0] == 0:
        return []
    if len(labels) != arr.shape[0]:
        raise ValueError("X and y must have the same number of rows")

    model = _fit_surrogate(arr, labels, max_iter)
    if model is None:
        return [0.0] * arr.shape[0]

    proba = model.predict_proba(arr)
    # Map each true label to its column index in model.classes_.
    class_to_col = {c: idx for idx, c in enumerate(model.classes_)}
    eps = 1e-12
    scores: list[float] = []
    for i, label in enumerate(labels):
        col = class_to_col.get(label)
        if col is None:
            scores.append(0.0)
            continue
        p = min(max(proba[i, col], eps), 1.0 - eps)
        scores.append(float(-np.log(p)))
    return scores


def influence_scores(
    X: list[list[float]] | np.ndarray,
    y: list[int] | np.ndarray,
    max_iter: int = 200,
) -> list[float]:
    """Approximate self-influence: how far below average is the model's
    confidence in each sample's own label.

    We compute, per sample, ``mean_confidence - confidence_in_true_label`` and
    clamp at zero. Points the model is much less confident about than typical
    (a signature of memorized poison / mislabeled data) score highly. This is a
    cheap surrogate for leave-one-out influence, documented as approximate.

    Args:
        X: Feature matrix.
        y: Integer labels aligned with X.
        max_iter: Max iterations for the logistic-regression surrogate.

    Returns:
        List of floats in [0, 1], one per sample. Zeros if no surrogate can be fit.

    Raises:
        ValueError: If len(X) != len(y).
    """
    arr = np.asarray(X, dtype=np.float64)
    labels = np.asarray(y)
    if arr.ndim != 2 or arr.shape[0] == 0:
        return []
    if len(labels) != arr.shape[0]:
        raise ValueError("X and y must have the same number of rows")

    model = _fit_surrogate(arr, labels, max_iter)
    if model is None:
        return [0.0] * arr.shape[0]

    proba = model.predict_proba(arr)
    class_to_col = {c: idx for idx, c in enumerate(model.classes_)}

    true_conf = np.array([
        proba[i, class_to_col.get(label, 0)] for i, label in enumerate(labels)
    ])
    mean_conf = float(np.mean(true_conf))

    # Below-average confidence in the assigned label -> higher influence proxy.
    scores = np.clip(mean_conf - true_conf, 0.0, 1.0)
    return [float(s) for s in scores]


def influence_detect(
    X: list[list[float]] | np.ndarray,
    y: list[int] | np.ndarray,
    quantile: float = 0.95,
    max_iter: int = 200,
) -> list[tuple[int, float]]:
    """Flag samples whose surrogate loss exceeds a high quantile of all losses.

    Args:
        X: Feature matrix.
        y: Integer labels aligned with X.
        quantile: Fraction in (0, 1); samples at/above this quantile of the loss
            distribution are flagged.
        max_iter: Max iterations for the surrogate.

    Returns:
        Sorted list of (sample_index, loss) for flagged samples.
    """
    scores = loss_scores(X, y, max_iter=max_iter)
    if not scores or all(s == 0.0 for s in scores):
        return []
    threshold = float(np.quantile(scores, quantile))
    return [(i, s) for i, s in enumerate(scores) if s >= threshold and s > 0.0]
