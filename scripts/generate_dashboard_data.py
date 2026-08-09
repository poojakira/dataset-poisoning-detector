"""Generate real dashboard data by running spectral_detect on a synthetic poisoned dataset.

Creates a reproducible 2-Gaussian-cluster dataset with 5% label flips (fixed seed),
runs the spectral detector, and writes results to dashboard/data.json.

Usage:
    py scripts/generate_dashboard_data.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np

# Ensure we can import from the src package
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from poison_detector.spectral import spectral_detect


def generate_synthetic_dataset(
    n_samples: int = 1000,
    n_features: int = 20,
    flip_rate: float = 0.05,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Generate a 2-Gaussian-cluster dataset with label flips.

    Parameters
    ----------
    n_samples : int
        Total number of samples (split evenly between classes).
    n_features : int
        Number of features per sample.
    flip_rate : float
        Fraction of samples whose labels are flipped (poisoned).
    seed : int
        Random seed for reproducibility.

    Returns
    -------
    X : ndarray of shape (n_samples, n_features)
    labels : ndarray of shape (n_samples,) — labels AFTER poisoning
    true_labels : ndarray of shape (n_samples,) — original correct labels
    poisoned_mask : ndarray of shape (n_samples,) — True where label was flipped
    """
    rng = np.random.default_rng(seed)

    n_per_class = n_samples // 2

    # Class 0: centered at -1 in all dimensions
    X0 = rng.normal(loc=-1.0, scale=1.0, size=(n_per_class, n_features))
    # Class 1: centered at +1 in all dimensions
    X1 = rng.normal(loc=1.0, scale=1.0, size=(n_samples - n_per_class, n_features))

    X = np.vstack([X0, X1])
    true_labels = np.array([0] * n_per_class + [1] * (n_samples - n_per_class), dtype=np.int64)

    # Apply label flips (poisoning)
    labels = true_labels.copy()
    n_flip = int(n_samples * flip_rate)
    flip_indices = rng.choice(n_samples, size=n_flip, replace=False)
    labels[flip_indices] = 1 - labels[flip_indices]

    poisoned_mask = np.zeros(n_samples, dtype=bool)
    poisoned_mask[flip_indices] = True

    return X, labels, true_labels, poisoned_mask


def main() -> None:
    print("Generating synthetic 2-Gaussian dataset (seed=42, 5% label flips)...")
    X, labels, true_labels, poisoned_mask = generate_synthetic_dataset(
        n_samples=1000,
        n_features=20,
        flip_rate=0.05,
        seed=42,
    )

    print(f"  Total samples: {len(X)}")
    print(f"  Poisoned (flipped): {poisoned_mask.sum()}")
    print(f"  Class 0: {(labels == 0).sum()}, Class 1: {(labels == 1).sum()}")

    print("\nRunning spectral_detect (n_components=1, iqr_multiplier=1.5)...")
    start_time = time.perf_counter()
    report = spectral_detect(X, labels, n_components=1, iqr_multiplier=1.5)
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    print(f"  Detection completed in {elapsed_ms:.1f} ms")
    print(f"  Samples flagged: {report.poisoned_count}")
    print(f"  Flag rate: {report.poisoned_count / report.total_samples * 100:.2f}%")

    # Compute detection quality metrics
    flagged_indices = {r.sample_idx for r in report.results if r.is_poisoned}
    true_positive = sum(1 for idx in flagged_indices if poisoned_mask[idx])
    false_positive = sum(1 for idx in flagged_indices if not poisoned_mask[idx])
    actual_poisoned = int(poisoned_mask.sum())
    false_negative = actual_poisoned - true_positive

    precision = true_positive / len(flagged_indices) if flagged_indices else 0.0
    recall = true_positive / actual_poisoned if actual_poisoned > 0 else 0.0
    fpr = false_positive / (len(X) - actual_poisoned) if (len(X) - actual_poisoned) > 0 else 0.0

    print(f"\n  True positives: {true_positive}")
    print(f"  False positives: {false_positive}")
    print(f"  False negatives: {false_negative}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall: {recall:.4f}")
    print(f"  FPR: {fpr:.4f}")

    # Build per-class summary
    per_class_summary = {}
    for class_label, stats in report.per_class_stats.items():
        if stats.get("skipped"):
            continue
        per_class_summary[str(class_label)] = {
            "size": stats["size"],
            "flagged": stats["flagged"],
            "threshold": stats["threshold"],
            "mean_score": stats["mean_score"],
            "max_score": stats["max_score"],
            "explained_variance_ratio": stats["explained_variance_ratio"],
        }

    # Build top flagged samples list (for triage table)
    top_flagged = []
    for r in report.results[:20]:  # top 20 by score
        top_flagged.append(
            {
                "sample_idx": r.sample_idx,
                "label": r.label,
                "projection_score": r.projection_score,
                "threshold": r.threshold,
                "is_poisoned": r.is_poisoned,
                "actually_poisoned": bool(poisoned_mask[r.sample_idx]),
                "rank_in_class": r.rank_in_class,
            }
        )

    # Assemble dashboard data
    dashboard_data = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "dataset": {
            "type": "synthetic_2_gaussian",
            "n_samples": int(len(X)),
            "n_features": int(X.shape[1]),
            "n_classes": 2,
            "flip_rate": 0.05,
            "actual_poisoned": actual_poisoned,
            "seed": 42,
        },
        "detection": {
            "method": "spectral_detect",
            "n_components": 1,
            "iqr_multiplier": 1.5,
            "total_samples": report.total_samples,
            "samples_flagged": report.poisoned_count,
            "flag_rate_pct": round(report.poisoned_count / report.total_samples * 100, 2),
            "detection_latency_ms": round(elapsed_ms, 1),
        },
        "quality": {
            "true_positives": true_positive,
            "false_positives": false_positive,
            "false_negatives": false_negative,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "false_positive_rate": round(fpr, 4),
        },
        "per_class": per_class_summary,
        "top_flagged_samples": top_flagged,
    }

    # Write output (custom encoder for numpy types)
    class NumpyEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, (np.bool_,)):
                return bool(obj)
            if isinstance(obj, (np.integer,)):
                return int(obj)
            if isinstance(obj, (np.floating,)):
                return float(obj)
            if isinstance(obj, np.ndarray):
                return obj.tolist()
            return super().default(obj)

    output_path = Path(__file__).resolve().parent.parent / "dashboard" / "data.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(dashboard_data, indent=2, cls=NumpyEncoder))
    print(f"\nDashboard data written to: {output_path}")


if __name__ == "__main__":
    main()
