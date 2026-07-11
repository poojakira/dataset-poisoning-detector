"""
Dimensionality reduction applied BEFORE density-based detection.

IsolationForest's per-sample inference cost and its statistical power both
degrade as dimensionality grows. Modern poisoning targets increasingly live in
embedding space (e.g. 768-dim sentence/transformer embeddings), where fitting
and querying an isolation forest on the raw vectors blows the <50ms p99 latency
budget and dilutes the anomaly signal across hundreds of noisy dimensions.

This module provides two cheap, well-understood projections to run first:

    - PCA                       : keeps the directions of greatest variance.
                                  Best when the signal lives in a low-rank
                                  subspace (common for embeddings).
    - Gaussian random projection: Johnson-Lindenstrauss style. Distances are
                                  approximately preserved with high probability,
                                  it is O(d * k) per sample, needs no fit on huge
                                  data, and is the pragmatic default for very high
                                  dimensions.

Threat Model Assumptions:
    - Reduction is a PERFORMANCE and signal-to-noise aid, not a security control.
      An attacker who knows the projection could try to hide poison in the
      discarded directions; PCA in particular discards low-variance directions.
    - The clean data's important structure is captured by the retained
      components. If poison lives entirely in a discarded PCA direction it will
      be missed -- random projection is more robust to that (it does not
      preferentially discard any direction).

Honest Limitations:
    - PCA must be fit on data; fitting on contaminated data slightly tilts the
      components toward the poison. For heavy contamination prefer random
      projection, which is data-independent.
    - Reducing too aggressively destroys the very structure detectors rely on.
      There is no universal target dimension; we expose it and default to a
      conservative value.
    - Random projection preserves pairwise distances only approximately, so
      IsolationForest scores shift slightly versus the full-dimension run.

Security Notes:
    - scikit-learn PCA / GaussianRandomProjection only. Deterministic via a
      fixed random_state. No pickle of untrusted transformers.
"""

from __future__ import annotations

import numpy as np
from sklearn.decomposition import PCA
from sklearn.random_projection import GaussianRandomProjection


class DimensionalityReducer:
    """Fit-once / transform-many projection wrapper for the detection path.

    Usage:
        reducer = DimensionalityReducer(method="pca", n_components=32)
        reducer.fit(clean_matrix)          # or fit_transform
        low_dim = reducer.transform(sample_batch)

    The reducer is a no-op when the input dimensionality is already at or below
    the requested ``n_components`` -- it will not *expand* data.
    """

    VALID_METHODS = ("pca", "gaussian")

    def __init__(
        self,
        method: str = "gaussian",
        n_components: int = 64,
        random_state: int = 42,
    ) -> None:
        """Initialize the reducer.

        Args:
            method: "pca" or "gaussian" (Gaussian random projection).
            n_components: Target dimensionality.
            random_state: Seed for reproducibility.

        Raises:
            ValueError: If method is unknown or n_components < 1.
        """
        if method not in self.VALID_METHODS:
            raise ValueError(
                f"Unknown method '{method}'. Must be one of {self.VALID_METHODS}"
            )
        if n_components < 1:
            raise ValueError("n_components must be >= 1")

        self.method = method
        self.n_components = n_components
        self.random_state = random_state
        self._transformer: PCA | GaussianRandomProjection | None = None
        self._passthrough = False
        self._fitted = False

    def fit(self, X: list[list[float]] | np.ndarray) -> "DimensionalityReducer":
        """Fit the projection on X.

        If the input already has <= n_components features, the reducer becomes a
        pass-through (reduction would be meaningless or an expansion).

        Args:
            X: Feature matrix to fit on.

        Returns:
            self, for chaining.
        """
        arr = np.asarray(X, dtype=np.float64)
        if arr.ndim != 2 or arr.shape[0] == 0:
            raise ValueError("X must be a non-empty 2D matrix")

        n_samples, n_features = arr.shape
        if n_features <= self.n_components:
            self._passthrough = True
            self._fitted = True
            return self

        if self.method == "pca":
            # PCA cannot keep more components than min(n_samples, n_features).
            k = min(self.n_components, n_samples, n_features)
            self._transformer = PCA(
                n_components=k, random_state=self.random_state
            )
        else:
            self._transformer = GaussianRandomProjection(
                n_components=self.n_components, random_state=self.random_state
            )

        self._transformer.fit(arr)
        self._fitted = True
        return self

    def transform(self, X: list[list[float]] | np.ndarray) -> np.ndarray:
        """Project X into the reduced space.

        Args:
            X: Feature matrix (or a single row) to project.

        Returns:
            Reduced matrix as a 2D numpy array. If the reducer is a pass-through,
            the input is returned unchanged (as float64).

        Raises:
            RuntimeError: If called before fit().
        """
        if not self._fitted:
            raise RuntimeError("DimensionalityReducer.transform called before fit()")

        arr = np.asarray(X, dtype=np.float64)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)

        if self._passthrough or self._transformer is None:
            return arr
        return self._transformer.transform(arr)

    def fit_transform(self, X: list[list[float]] | np.ndarray) -> np.ndarray:
        """Fit on X and return the projected matrix in one call."""
        self.fit(X)
        return self.transform(X)

    @property
    def is_passthrough(self) -> bool:
        """True if the reducer leaves data unchanged (input dim <= target dim)."""
        return self._passthrough

    @property
    def output_dim(self) -> int:
        """The dimensionality the reducer emits (post-fit)."""
        if not self._fitted:
            return self.n_components
        if self._passthrough or self._transformer is None:
            return -1  # unknown until data seen; equals input dim
        return int(self._transformer.n_components_)
