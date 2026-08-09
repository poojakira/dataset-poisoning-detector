"""
Scan a dataset from a link before you train on it.

Data poisoning is a first-class supply-chain threat: the 2026 wave of malicious
public artifacts (FakeGit/AgentBaiting, typosquatted skills, poisoned PyPI
packages) showed attackers seeding training data and public datasets. The
defensive move is the same as for models - inspect BEFORE you ingest.

This module fetches a HuggingFace dataset's numeric feature matrix via the
public datasets-server API (no full download of multi-GB shards) and runs the
spectral-signature detector to flag samples whose representations are
inconsistent with their labels - the fingerprint of label-flip poisoning.

Uses only the stdlib for HTTP. No dataset is executed; only rows are parsed.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from .spectral import spectral_detect

HF_ROWS_API = "https://datasets-server.huggingface.co/rows"
HF_INFO_API = "https://datasets-server.huggingface.co/info"
_MAX_ROWS = 1000  # cap the sample pulled for scanning


@dataclass
class DatasetScanResult:
    dataset: str
    config: str
    split: str
    rows_scanned: int
    feature_columns: list[str]
    label_column: str | None
    suspected_poison_rows: list[int] = field(default_factory=list)
    per_class_flagged: dict[int, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def poison_suspected(self) -> bool:
        return len(self.suspected_poison_rows) > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset": self.dataset,
            "config": self.config,
            "split": self.split,
            "rows_scanned": self.rows_scanned,
            "feature_columns": self.feature_columns,
            "label_column": self.label_column,
            "suspected_poison_count": len(self.suspected_poison_rows),
            "suspected_poison_rows": self.suspected_poison_rows[:50],
            "per_class_flagged": self.per_class_flagged,
            "verdict": "POISON_SUSPECTED" if self.poison_suspected else "clean",
            "errors": self.errors,
        }


def parse_hf_dataset_reference(url_or_id: str) -> str | None:
    """Extract an ``org/dataset`` id from a HuggingFace dataset URL or bare id."""
    s = url_or_id.strip()
    if "huggingface.co/datasets/" in s:
        after = s.split("huggingface.co/datasets/", 1)[1]
        parts = [p for p in after.split("/") if p]
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
    if s.startswith(("http://", "https://")):
        return None
    if "/" in s and " " not in s:
        return s
    return None


def _get_json(url: str, timeout: int = 30) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("URL must use http or https")
    req = urllib.request.Request(url, headers={"User-Agent": "poison-detector/0.2"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
        return json.loads(resp.read())


def _fetch_rows(dataset: str, config: str, split: str, n: int) -> list[dict[str, Any]]:
    """Pull up to ``n`` rows via the datasets-server rows API (paginated by 100)."""
    rows: list[dict[str, Any]] = []
    offset = 0
    while len(rows) < n:
        length = min(100, n - len(rows))
        q = urllib.parse.urlencode(
            {
                "dataset": dataset,
                "config": config,
                "split": split,
                "offset": offset,
                "length": length,
            }
        )
        data = _get_json(f"{HF_ROWS_API}?{q}")
        batch = data.get("rows", [])
        if not batch:
            break
        rows.extend(r.get("row", {}) for r in batch)
        offset += length
        if len(batch) < length:
            break
    return rows


def _numeric_matrix(
    rows: list[dict[str, Any]], label_col: str | None
) -> tuple[np.ndarray, np.ndarray | None, list[str]]:
    """Build a numeric feature matrix + optional integer labels from row dicts."""
    if not rows:
        return np.empty((0, 0)), None, []
    # Pick columns that are numeric across the sample.
    keys = list(rows[0].keys())
    feature_cols = []
    for k in keys:
        if k == label_col:
            continue
        vals = [r.get(k) for r in rows]
        if all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in vals):
            feature_cols.append(k)
    X = np.array([[float(r.get(c, 0.0)) for c in feature_cols] for r in rows], dtype=float)

    labels = None
    if label_col:
        raw = [r.get(label_col) for r in rows]
        # Map labels to integers (works for int labels or categorical strings).
        uniq = {v: i for i, v in enumerate(sorted({str(x) for x in raw}))}
        labels = np.array([uniq[str(x)] for x in raw], dtype=int)
    return X, labels, feature_cols


def scan_hf_dataset(
    url_or_id: str,
    *,
    config: str = "default",
    split: str = "train",
    label_column: str | None = None,
    max_rows: int = _MAX_ROWS,
    _rows_override: list[dict[str, Any]] | None = None,
) -> DatasetScanResult:
    """Scan a HuggingFace dataset for label-flip poisoning before training.

    Parameters
    ----------
    url_or_id : str
        HF dataset URL or ``org/dataset`` id.
    config, split : str
        Dataset config and split to sample.
    label_column : str, optional
        The label field. If None, we try to auto-detect a column named
        'label' or 'labels'. Spectral detection needs labels.
    max_rows : int
        Max rows to sample for scanning.
    _rows_override : list[dict], optional
        Injected rows for testing (bypasses network).
    """
    dataset = parse_hf_dataset_reference(url_or_id)
    if dataset is None:
        raise ValueError(f"Could not parse a HuggingFace dataset id from: {url_or_id!r}")

    result = DatasetScanResult(
        dataset=dataset,
        config=config,
        split=split,
        rows_scanned=0,
        feature_columns=[],
        label_column=label_column,
    )

    try:
        rows = (
            _rows_override
            if _rows_override is not None
            else _fetch_rows(dataset, config, split, max_rows)
        )
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, ValueError) as e:
        result.errors.append(f"failed to fetch rows: {e}")
        return result

    if not rows:
        result.errors.append("no rows returned")
        return result

    # Auto-detect label column if not given.
    if label_column is None:
        for candidate in ("label", "labels", "target", "class"):
            if candidate in rows[0]:
                label_column = candidate
                break
    result.label_column = label_column

    X, labels, feature_cols = _numeric_matrix(rows, label_column)
    result.rows_scanned = len(rows)
    result.feature_columns = feature_cols

    if labels is None:
        result.errors.append("no label column found; spectral label-flip detection needs labels")
        return result
    if X.shape[1] == 0:
        result.errors.append("no numeric feature columns to analyze")
        return result

    report = spectral_detect(X, labels)
    flagged = [r.sample_idx for r in report.results if r.is_poisoned]
    result.suspected_poison_rows = sorted(flagged)
    result.per_class_flagged = {
        int(k): v.get("flagged", 0)
        for k, v in report.per_class_stats.items()
        if isinstance(v, dict) and not v.get("skipped")
    }
    return result
