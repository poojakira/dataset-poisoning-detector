"""
Feature-level attribution for flagged anomalous samples.

Given a set of samples already identified as potential poison, this module
answers "which features made this sample look anomalous?" by comparing each
flagged sample's feature values against the dataset mean.

Threat Model Assumptions:
    - Attribution is a post-hoc explanation tool, not a detection method.
    - It assumes the dataset mean represents "normal" behavior. This fails
      if the poison rate is high enough to shift the mean itself.
    - Useful for human-in-the-loop review: security engineers can look at
      the top-contributing features and decide if the anomaly is malicious
      or just a rare legitimate sample.

Honest Limitations:
    - Mean-deviation attribution is simplistic. It cannot detect:
        * Correlated feature manipulations (features individually normal but
          their combination is impossible)
        * Subtle attacks that move features by small amounts across many
          dimensions simultaneously
    - Does not account for feature correlations or covariance structure.
      A feature 2 std from mean might be normal given another feature's value.
    - Attribution magnitude is in raw feature units. Without normalization,
      features with larger scales will dominate. Caller should pre-normalize
      if features have different units.

Security Notes:
    - Pure Python, fully auditable.
    - No side effects, no state mutation.
    - Deterministic: same inputs always produce same attribution ranking.
"""

from __future__ import annotations


def feature_attribution(
    X: list[list[float]], flagged_indices: list[int]
) -> dict[int, list[tuple[int, float]]]:
    """Compute per-feature deviation scores for flagged samples.

    For each flagged sample, calculates how far each feature deviates from
    the dataset mean (across all samples, not just clean ones). Features are
    ranked by absolute deviation magnitude.

    Args:
        X: Complete feature matrix (all samples, not just flagged).
        flagged_indices: List of sample indices identified as anomalous.

    Returns:
        Dictionary mapping sample_idx to a list of (feature_idx, deviation_magnitude)
        tuples, sorted by deviation magnitude in descending order.
        Returns empty dict if flagged_indices is empty.

    Example:
        >>> X = [[1.0, 2.0], [1.1, 2.1], [10.0, 2.0]]
        >>> feature_attribution(X, [2])
        {2: [(0, 5.966...), (1, 0.033...)]}
    """
    if not flagged_indices or not X or not X[0]:
        return {}

    n_samples = len(X)
    n_features = len(X[0])

    feature_means: list[float] = []
    for j in range(n_features):
        col_sum = sum(X[i][j] for i in range(n_samples))
        feature_means.append(col_sum / n_samples)

    result: dict[int, list[tuple[int, float]]] = {}
    for idx in flagged_indices:
        deviations: list[tuple[int, float]] = []
        for j in range(n_features):
            deviation = abs(X[idx][j] - feature_means[j])
            deviations.append((j, deviation))
        deviations.sort(key=lambda x: x[1], reverse=True)
        result[idx] = deviations

    return result


def format_attribution(
    attr: dict[int, list[tuple[int, float]]], feature_names: list[str] | None = None
) -> str:
    """Format attribution results into a human-readable string.

    Produces a report suitable for security engineer review, listing each
    flagged sample and its top contributing features.

    Args:
        attr: Output from feature_attribution().
        feature_names: Optional list of feature names. If None, uses
            "feature_0", "feature_1", etc.

    Returns:
        Formatted multi-line string. Empty string if attr is empty.
    """
    if not attr:
        return ""

    lines: list[str] = []
    for sample_idx in sorted(attr.keys()):
        lines.append(f"Sample {sample_idx}:")
        for feature_idx, magnitude in attr[sample_idx]:
            if feature_names and feature_idx < len(feature_names):
                name = feature_names[feature_idx]
            else:
                name = f"feature_{feature_idx}"
            lines.append(f"  {name}: deviation = {magnitude:.4f}")
        lines.append("")

    return "\n".join(lines)
