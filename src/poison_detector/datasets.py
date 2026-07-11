"""
Real-dataset loading and controlled poison injection for honest benchmarking.

Prior to this module every metric quoted for the project came from a handful of
hand-crafted synthetic attacks (numpy Gaussians plus four fixed attack shapes).
That made the reported precision/recall meaningless as a production signal. This
module replaces "synthetic only" with:

    1. Loaders for REAL datasets that ship *inside* scikit-learn
       (breast cancer, digits, wine, iris). No network is required at test
       time, so the benchmark stays hermetic and fast in CI.
    2. A ``PoisonInjector`` that injects controlled attacks at KNOWN indices so
       precision/recall can be computed against ground truth.

Supported attacks (each documented with the detector it is meant to stress):
    - label_flip          : real feature vectors with a deliberately wrong label.
                            Invisible to feature-only detectors; caught by the
                            label-aware detector (see label_aware.py).
    - feature_outlier     : samples pushed far outside every per-feature range.
                            The easy case: z-score / IQR / IsolationForest catch it.
    - cluster_injection   : a tight cluster placed far from the data manifold.
                            Density methods (IsolationForest) catch it well.
    - duplicate_injection : near-exact duplicates of one real sample. Caught by
                            fingerprinting; often missed by distributional stats.
    - correlation_poison  : every feature is individually in-range, but the joint
                            covariance is destroyed (features permuted across the
                            marginal). Per-feature Welford / z-score / IQR are
                            structurally BLIND to this; spectral / SVD catches it.

Threat Model Assumptions:
    - The clean reference dataset is trusted ground truth. In production you
      never have that luxury; here we use it only to *measure* detector quality.
    - Injected poison indices are the positive class. A detector "hit" means it
      flagged a truly-injected sample.

Honest Limitations:
    - sklearn's bundled datasets are small (hundreds to ~1.8k rows) and clean.
      Absolute numbers here will differ from web-scale, noisy production data.
      The RELATIVE ranking of methods and attacks is the transferable signal.
    - correlation_poison uses per-feature marginal permutation. It is one
      concrete instance of covariance attacks, not the whole family.
    - label_flip only makes sense for datasets that carry labels; the loaders
      always return labels so this always works.

Security Notes:
    - No pickle, no eval, no network at import or test time.
    - All randomness flows through an explicit, seeded numpy Generator so
      injected poison is reproducible across runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

# sklearn bundled loaders -- all ship data inside the wheel (no download).
from sklearn.datasets import (
    load_breast_cancer,
    load_digits,
    load_iris,
    load_wine,
)
from sklearn.preprocessing import StandardScaler


# Attack name constants (avoid stringly-typed typos across the codebase).
ATTACK_LABEL_FLIP = "label_flip"
ATTACK_FEATURE_OUTLIER = "feature_outlier"
ATTACK_CLUSTER = "cluster_injection"
ATTACK_DUPLICATE = "duplicate_injection"
ATTACK_CORRELATION = "correlation_poison"

ALL_ATTACKS = (
    ATTACK_LABEL_FLIP,
    ATTACK_FEATURE_OUTLIER,
    ATTACK_CLUSTER,
    ATTACK_DUPLICATE,
    ATTACK_CORRELATION,
)

_LOADERS = {
    "breast_cancer": load_breast_cancer,
    "digits": load_digits,
    "iris": load_iris,
    "wine": load_wine,
}


@dataclass
class DatasetBundle:
    """A loaded, optionally standardized real dataset.

    Attributes:
        name: Human-readable dataset identifier.
        X: Feature matrix as a list of float rows (JSON/API friendly).
        y: Integer class labels, one per row.
        feature_names: Column names (best effort; synthesized if unavailable).
        n_classes: Number of distinct labels.
        standardized: Whether features were zero-mean/unit-variance scaled.
    """

    name: str
    X: list[list[float]]
    y: list[int]
    feature_names: list[str] = field(default_factory=list)
    n_classes: int = 0
    standardized: bool = False

    @property
    def n_samples(self) -> int:
        return len(self.X)

    @property
    def n_features(self) -> int:
        return len(self.X[0]) if self.X else 0


@dataclass
class PoisonedDataset:
    """A clean dataset with poison appended at known indices.

    Attributes:
        X: Combined feature matrix (clean rows first, poison rows appended).
        y: Combined labels aligned with X.
        poison_indices: Sorted indices of the injected poison rows.
        attack: Which attack produced the poison.
        contamination: Poison fraction = len(poison_indices) / len(X).
        n_clean: Number of clean rows (poison indices start at this value).
    """

    X: list[list[float]]
    y: list[int]
    poison_indices: list[int]
    attack: str
    contamination: float
    n_clean: int

    @property
    def labels_binary(self) -> list[int]:
        """Ground-truth poison labels: 1 for poison rows, 0 for clean rows."""
        poison = set(self.poison_indices)
        return [1 if i in poison else 0 for i in range(len(self.X))]


def available_datasets() -> list[str]:
    """Return the names of datasets this module can load without network access."""
    return sorted(_LOADERS.keys())


def load_reference_dataset(
    name: str = "breast_cancer",
    standardize: bool = True,
    max_samples: int | None = None,
) -> DatasetBundle:
    """Load a real, bundled scikit-learn dataset as a DatasetBundle.

    Args:
        name: One of available_datasets() (breast_cancer, digits, iris, wine).
        standardize: If True, zero-mean/unit-variance scale each feature. This
            is important because z-score and IsolationForest both assume roughly
            comparable feature scales.
        max_samples: Optional cap on rows (useful to keep tests fast). The cap is
            applied deterministically (first N rows) after loading.

    Returns:
        DatasetBundle with features, labels, and metadata.

    Raises:
        ValueError: If name is not a known dataset.
    """
    if name not in _LOADERS:
        raise ValueError(
            f"Unknown dataset '{name}'. Available: {available_datasets()}"
        )

    bunch = _LOADERS[name]()
    X = np.asarray(bunch.data, dtype=np.float64)
    y = np.asarray(bunch.target, dtype=int)

    if max_samples is not None and max_samples < len(X):
        X = X[:max_samples]
        y = y[:max_samples]

    if standardize:
        X = StandardScaler().fit_transform(X)

    feature_names = list(getattr(bunch, "feature_names", []))
    if not feature_names:
        feature_names = [f"feature_{i}" for i in range(X.shape[1])]
    else:
        feature_names = [str(f) for f in feature_names]

    return DatasetBundle(
        name=name,
        X=X.tolist(),
        y=y.tolist(),
        feature_names=feature_names,
        n_classes=int(len(np.unique(y))),
        standardized=standardize,
    )


class PoisonInjector:
    """Inject controlled poison attacks at known indices for benchmarking.

    Every method returns ``(poison_X, poison_y)`` numpy arrays containing only
    the newly generated poison rows. Use :func:`inject_poison` to combine them
    with a clean dataset and obtain ground-truth poison indices.

    All randomness is seeded so results are reproducible.
    """

    def __init__(self, seed: int = 42) -> None:
        self.rng = np.random.default_rng(seed)

    # --- individual attacks -------------------------------------------------

    def label_flip(
        self, X: np.ndarray, y: np.ndarray, n: int
    ) -> tuple[np.ndarray, np.ndarray]:
        """Copy n real samples but assign each a deliberately wrong label.

        Features remain perfectly in-distribution -- this is a clean-label /
        label-flip attack. Feature-only detectors cannot see it; the label-aware
        detector can, by comparing the label against feature-space neighbors.
        """
        classes = np.unique(y)
        if len(classes) < 2:
            raise ValueError("label_flip requires at least 2 classes")

        idx = self.rng.choice(len(X), size=n, replace=n > len(X))
        poison_X = X[idx].copy()
        poison_y = np.empty(n, dtype=int)
        for k, orig_label in enumerate(y[idx]):
            # Choose any label different from the true one, uniformly.
            other = classes[classes != orig_label]
            poison_y[k] = self.rng.choice(other)
        return poison_X, poison_y

    def feature_outlier(
        self, X: np.ndarray, y: np.ndarray, n: int, magnitude: float = 8.0
    ) -> tuple[np.ndarray, np.ndarray]:
        """Generate n samples pushed far outside every per-feature range."""
        col_min = X.min(axis=0)
        col_max = X.max(axis=0)
        span = np.where((col_max - col_min) > 1e-9, col_max - col_min, 1.0)
        # Randomly push each feature above the max or below the min.
        direction = self.rng.choice([-1.0, 1.0], size=(n, X.shape[1]))
        base = np.where(direction > 0, col_max, col_min)
        poison_X = base + direction * magnitude * span * self.rng.uniform(
            0.5, 1.5, size=(n, X.shape[1])
        )
        poison_y = self.rng.choice(np.unique(y), size=n)
        return poison_X, poison_y

    def cluster_injection(
        self, X: np.ndarray, y: np.ndarray, n: int, offset: float = 6.0
    ) -> tuple[np.ndarray, np.ndarray]:
        """Inject a tight Gaussian cluster placed far from the data manifold."""
        center = X.mean(axis=0) + offset * X.std(axis=0)
        scale = 0.05 * (X.std(axis=0) + 1e-9)
        poison_X = self.rng.normal(
            loc=center, scale=scale, size=(n, X.shape[1])
        )
        poison_y = self.rng.choice(np.unique(y), size=n)
        return poison_X, poison_y

    def duplicate_injection(
        self, X: np.ndarray, y: np.ndarray, n: int, jitter: float = 1e-4
    ) -> tuple[np.ndarray, np.ndarray]:
        """Create n near-exact duplicates of a single real sample.

        Tiny jitter is added so the rows are not byte-identical (a realistic
        duplication attack rarely produces bit-perfect copies). Caught by
        fingerprinting / cosine similarity, usually missed by distributional
        statistics because the values sit inside the normal range.
        """
        src = self.rng.integers(0, len(X))
        base = X[src]
        noise = self.rng.normal(0.0, jitter, size=(n, X.shape[1]))
        poison_X = base + noise
        poison_y = np.full(n, y[src], dtype=int)
        return poison_X, poison_y

    def correlation_poison(
        self, X: np.ndarray, y: np.ndarray, n: int
    ) -> tuple[np.ndarray, np.ndarray]:
        """Generate samples that keep marginals but destroy joint covariance.

        For each poison row, each feature value is drawn independently from that
        feature's empirical marginal (a random real value seen for that column).
        Every individual value is therefore perfectly in-range, so per-feature
        z-score and IQR see nothing wrong. The *combination* of feature values is
        statistically impossible under the true covariance -- exactly what
        spectral/SVD signatures are designed to surface.
        """
        n_features = X.shape[1]
        poison_X = np.empty((n, n_features), dtype=np.float64)
        for j in range(n_features):
            # Independent bootstrap of column j across all poison rows.
            picks = self.rng.integers(0, len(X), size=n)
            poison_X[:, j] = X[picks, j]
        poison_y = self.rng.choice(np.unique(y), size=n)
        return poison_X, poison_y

    # --- dispatch -----------------------------------------------------------

    def generate(
        self, attack: str, X: np.ndarray, y: np.ndarray, n: int
    ) -> tuple[np.ndarray, np.ndarray]:
        """Dispatch to the named attack generator.

        Raises:
            ValueError: If the attack name is unknown.
        """
        dispatch = {
            ATTACK_LABEL_FLIP: self.label_flip,
            ATTACK_FEATURE_OUTLIER: self.feature_outlier,
            ATTACK_CLUSTER: self.cluster_injection,
            ATTACK_DUPLICATE: self.duplicate_injection,
            ATTACK_CORRELATION: self.correlation_poison,
        }
        if attack not in dispatch:
            raise ValueError(
                f"Unknown attack '{attack}'. Available: {list(dispatch)}"
            )
        return dispatch[attack](X, y, n)


def inject_poison(
    bundle: DatasetBundle,
    attack: str,
    contamination: float = 0.05,
    seed: int = 42,
) -> PoisonedDataset:
    """Append poison rows to a clean dataset and return ground-truth indices.

    Args:
        bundle: A clean DatasetBundle from load_reference_dataset().
        attack: One of ALL_ATTACKS.
        contamination: Target poison fraction of the FINAL dataset. The number
            of poison rows is round(contamination / (1 - contamination) * n_clean)
            so that len(poison) / len(total) approximates contamination.
        seed: RNG seed for reproducible injection.

    Returns:
        PoisonedDataset with combined X/y and sorted poison_indices.

    Raises:
        ValueError: If contamination is not in (0, 0.5) or attack is unknown.
    """
    if not (0.0 < contamination < 0.5):
        raise ValueError("contamination must be in the open interval (0, 0.5)")

    X_clean = np.asarray(bundle.X, dtype=np.float64)
    y_clean = np.asarray(bundle.y, dtype=int)
    n_clean = len(X_clean)

    # Solve n_poison / (n_clean + n_poison) = contamination for n_poison.
    n_poison = int(round(contamination / (1.0 - contamination) * n_clean))
    n_poison = max(1, n_poison)

    injector = PoisonInjector(seed=seed)
    poison_X, poison_y = injector.generate(attack, X_clean, y_clean, n_poison)

    X_combined = np.vstack([X_clean, poison_X])
    y_combined = np.concatenate([y_clean, poison_y])
    poison_indices = list(range(n_clean, n_clean + n_poison))
    actual_contamination = n_poison / (n_clean + n_poison)

    return PoisonedDataset(
        X=X_combined.tolist(),
        y=y_combined.tolist(),
        poison_indices=poison_indices,
        attack=attack,
        contamination=actual_contamination,
        n_clean=n_clean,
    )
