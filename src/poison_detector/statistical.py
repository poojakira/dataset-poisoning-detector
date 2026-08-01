"""
Pure-Python statistical anomaly detection for dataset poisoning.

Implements z-score and IQR (interquartile range) methods without numpy
dependencies. This deliberate choice ensures the statistical core remains
fully auditable -- every arithmetic operation is visible in source, with
no hidden vectorized paths that could mask subtle numerical bugs.

Threat Model Assumptions:
    - Attacker injects samples with feature values far outside the training
      distribution (point anomalies in feature space).
    - The clean majority of the dataset is approximately unimodal per feature.
    - Features are continuous and roughly comparable in scale.

Honest Limitations:
    - Z-score assumes approximate normality. Heavy-tailed distributions will
      produce false negatives (anomalies hidden in the tails).
    - IQR is robust to outliers but blind to adversarial samples placed just
      inside the 1.5*IQR fence (subversive poisoning).
    - Neither method detects clean-label attacks where feature values are
      in-distribution but labels are flipped.
    - Pure Python is ~100x slower than vectorized numpy for large datasets.
      This is an acceptable tradeoff for auditability up to ~50k samples.

Security Notes:
    - No external imports. Every line of math is reviewable.
    - Deterministic output: same input always produces same output.
    - No file I/O, no network calls, no subprocess invocations.
"""

from __future__ import annotations


def _mean(values: list[float]) -> float:
    """Compute arithmetic mean of a list of floats.

    Returns 0.0 for empty lists to avoid ZeroDivisionError in downstream
    callers. This is a deliberate sentinel -- callers should check length
    before interpreting results.
    """
    if not values:
        return 0.0
    return sum(values) / len(values)


def _std(values: list[float], mean: float) -> float:
    """Compute population standard deviation given a precomputed mean.

    Uses population std (N denominator) rather than sample std (N-1) because
    we treat the dataset as the full population under analysis, not a sample
    drawn from a larger distribution.

    Returns 0.0 for lists with fewer than 2 elements.
    """
    if len(values) < 2:
        return 0.0
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    return variance**0.5


def _percentile(sorted_vals: list[float], p: float) -> float:
    """Compute the p-th percentile from a pre-sorted list using linear interpolation.

    Uses the 'inclusive' interpolation method (matching numpy's default 'linear'
    method) for consistency with standard statistical libraries.

    Args:
        sorted_vals: Values sorted in ascending order. Caller must ensure sorting.
        p: Percentile in range [0, 100].

    Returns:
        Interpolated percentile value.
    """
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (p / 100.0) * (len(sorted_vals) - 1)
    floor_k = int(k)
    ceil_k = min(floor_k + 1, len(sorted_vals) - 1)
    fraction = k - floor_k
    return sorted_vals[floor_k] + fraction * (sorted_vals[ceil_k] - sorted_vals[floor_k])


def zscore_detect(X: list[list[float]], threshold: float = 3.0) -> list[tuple[int, float]]:
    """Detect anomalous samples using per-feature z-score analysis.

    For each sample, computes the z-score of every feature relative to the
    column (feature) distribution. A sample is flagged if ANY single feature
    has |z-score| >= threshold.

    The returned score is the maximum absolute z-score across all features
    for that sample, giving a single scalar measure of "how anomalous."

    Args:
        X: Feature matrix as list of lists. Each inner list is one sample.
        threshold: Z-score threshold for flagging. Default 3.0 corresponds
            to ~0.27% of samples under normality assumption.

    Returns:
        List of (sample_index, max_z_score) for each flagged sample.
        Sorted by sample index for deterministic output.

    Caveat:
        Relative scores only. A z-score of 4.0 in a Gaussian feature is
        far more suspicious than 4.0 in a Cauchy-distributed feature.
        No normality test is performed -- caller should validate assumptions.
    """
    if not X or not X[0]:
        return []

    n_samples = len(X)
    n_features = len(X[0])

    feature_means: list[float] = []
    feature_stds: list[float] = []
    for j in range(n_features):
        col = [X[i][j] for i in range(n_samples)]
        m = _mean(col)
        feature_means.append(m)
        feature_stds.append(_std(col, m))

    flagged: list[tuple[int, float]] = []
    for i in range(n_samples):
        max_z = 0.0
        for j in range(n_features):
            if feature_stds[j] == 0.0:
                continue
            z = abs(X[i][j] - feature_means[j]) / feature_stds[j]
            if z > max_z:
                max_z = z
        if max_z >= threshold:
            flagged.append((i, max_z))

    return flagged


def iqr_detect(X: list[list[float]], k: float = 1.5) -> list[tuple[int, float]]:
    """Detect anomalous samples using per-feature IQR fencing.

    The IQR method is more robust to outliers than z-score because it uses
    order statistics (Q1, Q3) rather than mean/std which are sensitive to
    extreme values. A sample is flagged if any feature falls outside
    [Q1 - k*IQR, Q3 + k*IQR].

    The returned score represents how far outside the fence the most deviant
    feature is, normalized by IQR for cross-feature comparability.

    Args:
        X: Feature matrix as list of lists.
        k: IQR multiplier. Default 1.5 (standard Tukey fence). Use 3.0 for
            far outliers only.

    Returns:
        List of (sample_index, iqr_score) for flagged samples.
        iqr_score = max across features of (distance_outside_fence / IQR).

    Caveat:
        IQR is undefined for features with zero spread (all identical values).
        Such features are skipped. If all features have zero spread, no samples
        are flagged regardless of their values.
    """
    if not X or not X[0]:
        return []

    n_samples = len(X)
    n_features = len(X[0])

    q1s: list[float] = []
    q3s: list[float] = []
    iqrs: list[float] = []
    for j in range(n_features):
        col = sorted(X[i][j] for i in range(n_samples))
        q1 = _percentile(col, 25.0)
        q3 = _percentile(col, 75.0)
        q1s.append(q1)
        q3s.append(q3)
        iqrs.append(q3 - q1)

    flagged: list[tuple[int, float]] = []
    for i in range(n_samples):
        max_score = 0.0
        is_outlier = False
        for j in range(n_features):
            if iqrs[j] == 0.0:
                continue
            lower = q1s[j] - k * iqrs[j]
            upper = q3s[j] + k * iqrs[j]
            val = X[i][j]
            if val < lower:
                score = (lower - val) / iqrs[j]
                is_outlier = True
                if score > max_score:
                    max_score = score
            elif val > upper:
                score = (val - upper) / iqrs[j]
                is_outlier = True
                if score > max_score:
                    max_score = score
        if is_outlier:
            flagged.append((i, max_score))

    return flagged
