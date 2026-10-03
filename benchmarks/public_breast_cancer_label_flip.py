"""Public real-dataset label-flip benchmark.

Uses scikit-learn's bundled Wisconsin Diagnostic Breast Cancer dataset. The dataset
is public and local to scikit-learn, so the benchmark is deterministic and does not
depend on a network service. We inject a controlled label-flip attack and measure
whether the label-aware spectral path identifies the corrupted samples.

This is a public-dataset experiment, not production efficacy.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from sklearn.datasets import load_breast_cancer
from sklearn.preprocessing import StandardScaler

from poison_detector.detector import detect


def f1_score(tp: int, fp: int, fn: int) -> float:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return 2 * precision * recall / (precision + recall) if precision + recall else 0.0


def run(seed: int = 20261003, poison_fraction: float = 0.10) -> dict:
    dataset = load_breast_cancer()
    X = StandardScaler().fit_transform(dataset.data).tolist()
    clean_labels = [int(v) for v in dataset.target.tolist()]
    poisoned_labels = clean_labels.copy()

    rng = random.Random(seed)
    poison_count = max(1, round(len(poisoned_labels) * poison_fraction))
    poisoned_indices = sorted(rng.sample(range(len(poisoned_labels)), poison_count))
    for idx in poisoned_indices:
        poisoned_labels[idx] = 1 - poisoned_labels[idx]

    report = detect(X, method="spectral", labels=poisoned_labels)
    flagged = {item.sample_idx for item in report.per_sample if item.is_poisoned}
    poisoned = set(poisoned_indices)
    tp = len(flagged & poisoned)
    fp = len(flagged - poisoned)
    fn = len(poisoned - flagged)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0

    return {
        "dataset": "sklearn.datasets.load_breast_cancer",
        "samples": len(X),
        "features": len(X[0]),
        "seed": seed,
        "poison_fraction": poison_fraction,
        "poisoned_samples": len(poisoned),
        "flagged_samples": len(flagged),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1_score(tp, fp, fn), 4),
        "claim_boundary": (
            "Controlled label flips on one public tabular dataset. This does not "
            "measure clean-label, backdoor, image-domain, or adaptive poisoning."
        ),
    }


def main() -> int:
    result = run()
    out = Path("results/public_breast_cancer_label_flip.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
