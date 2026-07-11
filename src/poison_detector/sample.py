"""
Extended sample data model with optional labels and metadata.

Historically a sample in this project was just a flat list of floats
(``{"features": [...]}``). That was enough for unsupervised, feature-only
detection but it structurally prevented label-aware detection: you cannot catch
a label-flip attack if labels never enter the system. This module introduces a
richer ``Sample`` type that OPTIONALLY carries a label and free-form metadata,
while remaining 100% backward compatible with the old flat-list format.

The coercion helpers accept, interchangeably:
    - a bare list/tuple of floats               -> Sample(features=[...])
    - a numpy 1-D array                         -> Sample(features=[...])
    - a dict {"features": [...], "label": 1}    -> Sample(features=[...], label=1)
    - an existing Sample                        -> returned unchanged

Threat Model Assumptions:
    - Labels, like features, arrive from an untrusted pipeline. A poisoned label
      is exactly the thing label-aware detection is meant to catch, so labels are
      treated as data to be scrutinized, never as trusted ground truth.
    - Metadata is opaque and never executed or eval'd. It is carried for triage
      (source, ingestion timestamp, tenant) only.

Honest Limitations:
    - The label is a single integer class id. Multi-label / regression targets
      are out of scope here; they would need a richer target type.
    - Metadata is not size-bounded by this module; the API layer enforces bounds.

Security Notes:
    - Pure dataclasses + validation. No pickle, no eval, no dynamic imports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np


@dataclass
class Sample:
    """A single sample: features plus optional label and metadata.

    Attributes:
        features: The feature vector as a list of floats.
        label: Optional integer class id. None means "unlabeled".
        metadata: Optional opaque key/value context for triage.
    """

    features: list[float]
    label: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.features is None or len(self.features) == 0:
            raise ValueError("Sample.features must be a non-empty sequence")


def extract_features(obj: Sample | dict | list | tuple | np.ndarray) -> list[float]:
    """Return the feature list from any supported sample representation.

    Args:
        obj: A Sample, a {"features": [...]} dict, a list/tuple of floats, or a
            1-D numpy array.

    Returns:
        The features as a list of Python floats.

    Raises:
        ValueError: If the object carries no usable features.
        TypeError: If the object type is unsupported.
    """
    return coerce_sample(obj).features


def coerce_sample(obj: Sample | dict | list | tuple | np.ndarray) -> Sample:
    """Coerce any supported representation into a Sample.

    Backward compatibility is the whole point: passing a plain list of floats
    (the pre-1.1.0 format) still works and yields an unlabeled Sample.

    Args:
        obj: A Sample, dict, list/tuple, or numpy array.

    Returns:
        A Sample instance.

    Raises:
        ValueError: If a dict is missing or has invalid 'features'.
        TypeError: If the object type is unsupported.
    """
    if isinstance(obj, Sample):
        return obj

    if isinstance(obj, np.ndarray):
        if obj.ndim != 1:
            raise ValueError("A numpy sample must be a 1-D array of features")
        return Sample(features=[float(v) for v in obj.tolist()])

    if isinstance(obj, (list, tuple)):
        return Sample(features=[float(v) for v in obj])

    if isinstance(obj, dict):
        if "features" not in obj:
            raise ValueError("Sample dict must contain a 'features' key")
        features = obj["features"]
        if not isinstance(features, (list, tuple, np.ndarray)):
            raise ValueError("'features' must be a sequence of numbers")
        label = obj.get("label")
        if label is not None:
            label = int(label)
        metadata = obj.get("metadata", {}) or {}
        if not isinstance(metadata, dict):
            raise ValueError("'metadata' must be a mapping")
        return Sample(
            features=[float(v) for v in features],
            label=label,
            metadata=metadata,
        )

    raise TypeError(
        f"Unsupported sample type {type(obj).__name__}; expected Sample, dict, "
        "list, tuple, or 1-D numpy array"
    )


def coerce_matrix(
    rows: list[Sample | dict | list | tuple | np.ndarray] | np.ndarray,
) -> tuple[list[list[float]], list[int | None]]:
    """Coerce a batch of mixed sample representations into (features, labels).

    Args:
        rows: A list of samples in any supported representation, or a 2-D numpy
            array (each row a sample).

    Returns:
        A tuple ``(X, labels)`` where X is a list of feature rows and labels is a
        parallel list of optional integer labels (None where unlabeled).
    """
    if isinstance(rows, np.ndarray):
        if rows.ndim != 2:
            raise ValueError("A numpy matrix must be 2-D (samples x features)")
        return [[float(v) for v in row] for row in rows.tolist()], [None] * len(rows)

    X: list[list[float]] = []
    labels: list[int | None] = []
    for row in rows:
        sample = coerce_sample(row)
        X.append(sample.features)
        labels.append(sample.label)
    return X, labels
