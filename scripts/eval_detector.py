"""Evaluate StreamingDetector on REAL CIFAR-10 label-flip poisoning.

Methodology (see task spec):
  - Label-flip poison samples have UNCHANGED features; they are only anomalous
    WITHIN their wrongly-assigned class. So detection is run PER CLASS.
  - For each flip_rate, build per-class groups (clean members of the class +
    flipped-in samples from other classes now labeled that class).
  - For each class, create a StreamingDetector, update_baseline on that class's
    (contaminated) members, then score every member, collecting
    (y_true=is_flipped, anomaly_score=res.score).
  - Pool across all 10 classes, compute sklearn roc_auc_score and roc_curve.
  - Pick the operating threshold from the ROC curve at a target FPR (5%) and
    report the ACTUAL FP rate on the clean subset at that threshold.

Feature choice: standardized raw pixels -> PCA(50), fit on the pooled sampled
data. Documented in make_labelflip_cifar.py.

Usage:
    python scripts/eval_detector.py --cifar-dir /path/to/cifar-10-batches-py
    python scripts/eval_detector.py --cifar-dir /data/cifar10 --output-dir ./results
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

import numpy as np
from sklearn.metrics import roc_auc_score, roc_curve

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from make_labelflip_cifar import (  # noqa: E402
    load_cifar_batches,
    build_features,
    build_labelflip_groups,
    NUM_CLASSES,
    get_cifar_dir,
)

from poison_detector.stream import StreamingDetector  # noqa: E402

SEED = 42
FLIP_RATES = [0.0, 0.05, 0.10, 0.25]
N_CLEAN_PER_CLASS = 450
TARGET_FPR = 0.05
PCA_DIMS = 50

# Size the sampled pool: need clean + poison headroom across all classes.
# Draw 900/class from CIFAR (9000 rows) to have room for disjoint poison picks.
N_SAMPLE_PER_CLASS_POOL = 900


def build_provenance(cifar_dir: str) -> dict:
    """Build the provenance record using the resolved cifar_dir (not hardcoded)."""
    return {
        "dataset": "CIFAR-10 (python batches)",
        "url": "https://www.cs.toronto.edu/~kriz/cifar-10-python.tar.gz",
        "sha256": "6D958BE074577803D12ECDEFD02955F39262C83C16FE9348329D7FE0B5C001CE",
        "size_bytes": 170498071,
        "downloaded_utc": "2026-07-13T19:36:25Z",
        # local_dir now comes from the CLI argument, not a hardcoded path.
        "local_dir": cifar_dir,
    }


def subsample_pool(X, y, per_class, seed):
    rng = np.random.default_rng(seed)
    idxs = []
    for c in range(NUM_CLASSES):
        ci = np.where(y == c)[0]
        rng.shuffle(ci)
        idxs.append(ci[:per_class])
    idxs = np.concatenate(idxs)
    rng.shuffle(idxs)
    return X[idxs], y[idxs]


def fp_rate_at_threshold(y_true, scores, threshold):
    """FP rate on the clean subset: fraction of clean (y_true=0) with score >= thr."""
    y_true = np.asarray(y_true)
    scores = np.asarray(scores)
    clean_mask = y_true == 0
    n_clean = int(clean_mask.sum())
    if n_clean == 0:
        return None, 0, 0
    fp = int(np.sum(scores[clean_mask] >= threshold))
    return fp / n_clean, fp, n_clean


def threshold_for_target_fpr(y_true, scores, target_fpr):
    """Pick threshold from ROC curve achieving FPR closest to (but <=) target."""
    fpr, tpr, thr = roc_curve(y_true, scores)
    # thr[i] corresponds to fpr[i]; find largest threshold with fpr <= target
    ok = np.where(fpr <= target_fpr)[0]
    if len(ok) == 0:
        idx = 0
    else:
        idx = ok[-1]  # largest index with fpr<=target => highest tpr at that constraint
    return float(thr[idx]), float(fpr[idx]), float(tpr[idx])


def evaluate_flip_rate(feats, y, flip_rate):
    groups = build_labelflip_groups(
        feats, y, flip_rate,
        n_clean_per_class=N_CLEAN_PER_CLASS, seed=SEED,
    )
    all_true = []
    all_scores = []
    per_class_summary = {}
    for c in range(NUM_CLASSES):
        g = groups[c]
        members = g["features"]
        is_flipped = g["is_flipped"]
        det = StreamingDetector(window_size=len(members) + 10, contamination=0.05)
        det.update_baseline(members)
        scores = []
        for row in members:
            res = det.score_sample(row)
            scores.append(float(res.score))
        scores = np.array(scores)
        all_true.append(is_flipped.astype(int))
        all_scores.append(scores)
        per_class_summary[c] = {
            "n_clean": g["n_clean"],
            "n_poison": g["n_poison"],
            "mean_score_clean": float(scores[~is_flipped].mean()) if (~is_flipped).any() else None,
            "mean_score_poison": float(scores[is_flipped].mean()) if is_flipped.any() else None,
        }
    y_true = np.concatenate(all_true)
    scores = np.concatenate(all_scores)

    result = {
        "flip_rate": flip_rate,
        "n_total": int(len(y_true)),
        "n_poison": int(y_true.sum()),
        "n_clean": int((y_true == 0).sum()),
        "per_class": per_class_summary,
    }

    if y_true.sum() == 0:
        # No positives: AUC undefined. Report FP rate at a threshold chosen on a
        # nonzero-rate run is not possible here; report score distribution + FP
        # rate at a couple of fixed thresholds so we NEVER claim zero FPs blindly.
        result["auc"] = None
        result["auc_note"] = "flip_rate=0: no poisoned samples, ROC-AUC undefined."
        # Report empirical FP rate at is_poisoned flag and at a nominal 0.5 thr.
        for thr in (0.3, 0.5):
            fpr_val, fp, n_clean = fp_rate_at_threshold(y_true, scores, thr)
            result[f"fp_rate_at_score_{thr}"] = fpr_val
            result[f"fp_count_at_score_{thr}"] = fp
        result["clean_score_mean"] = float(scores.mean())
        result["clean_score_max"] = float(scores.max())
        return result, (y_true, scores)

    auc = float(roc_auc_score(y_true, scores))
    thr, achieved_fpr, achieved_tpr = threshold_for_target_fpr(y_true, scores, TARGET_FPR)
    actual_fpr, fp, n_clean = fp_rate_at_threshold(y_true, scores, thr)

    result.update({
        "auc": auc,
        "target_fpr": TARGET_FPR,
        "operating_threshold": thr,
        "roc_curve_fpr_at_threshold": achieved_fpr,
        "roc_curve_tpr_at_threshold": achieved_tpr,
        "actual_fp_rate_on_clean": actual_fpr,
        "actual_fp_count": fp,
        "n_clean_evaluated": n_clean,
        "detection_rate_at_threshold": achieved_tpr,
    })
    return result, (y_true, scores)


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate StreamingDetector on CIFAR-10 label-flip poisoning."
    )
    parser.add_argument(
        "--cifar-dir",
        default=None,
        help=(
            "Path to the cifar-10-batches-py directory. "
            "If omitted, falls back to the CIFAR_DIR environment variable."
        ),
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help=(
            "Directory to write evaluation artifacts (report.json, RESULTS.md). "
            "Defaults to ./eval_artifacts/<timestamp> relative to the current "
            "working directory."
        ),
    )
    args = parser.parse_args()

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base_out = args.output_dir if args.output_dir else os.path.join("eval_artifacts", ts)
    out_dir = base_out if args.output_dir else base_out
    os.makedirs(out_dir, exist_ok=True)

    # Resolve the CIFAR directory from CLI arg or env var (fail-closed, no hardcoded path).
    cifar_dir: str = args.cifar_dir if args.cifar_dir else get_cifar_dir()

    print("Loading CIFAR-10...")
    X, y = load_cifar_batches(cifar_dir=cifar_dir)
    print(f"Loaded {X.shape[0]} samples, {X.shape[1]} features.")

    Xp, yp = subsample_pool(X, y, N_SAMPLE_PER_CLASS_POOL, SEED)
    print(f"Pooled subsample: {Xp.shape[0]} samples.")
    feats, scaler, pca = build_features(Xp, n_components=PCA_DIMS, seed=SEED)
    print(f"Features: PCA -> {feats.shape[1]} dims, "
          f"explained var={pca.explained_variance_ratio_.sum():.3f}")

    results = []
    for fr in FLIP_RATES:
        print(f"\n=== flip_rate={fr} ===")
        res, _ = evaluate_flip_rate(feats, yp, fr)
        if res["auc"] is not None:
            print(f"  AUC={res['auc']:.4f}  actual_FP_rate={res['actual_fp_rate_on_clean']:.4f} "
                  f"(target {TARGET_FPR})  TPR={res['detection_rate_at_threshold']:.4f}")
        else:
            print(f"  {res['auc_note']}  clean_score_mean={res['clean_score_mean']:.4f}")
        results.append(res)

    report = {
        "generated_utc": ts,
        "seed": SEED,
        "feature_extraction": {
            "method": "standardize raw pixels (StandardScaler) -> PCA(50)",
            "pca_dims": PCA_DIMS,
            "pca_explained_variance_ratio_sum": float(pca.explained_variance_ratio_.sum()),
            "note": "PCA fit on pooled sampled data.",
        },
        "methodology": (
            "PER-CLASS detection. For each class, a StreamingDetector baseline is "
            "built on that class's (contaminated) members; every member is scored; "
            "label-flip poison = samples from other classes assigned this class "
            "(features unchanged). Scores pooled across classes for ROC-AUC. "
            "Operating threshold chosen from ROC curve at target FPR=5%; the ACTUAL "
            "FP rate on the clean subset at that threshold is reported."
        ),
        "detector": "poison_detector.stream.StreamingDetector (contamination=0.05)",
        "n_clean_per_class": N_CLEAN_PER_CLASS,
        "flip_rates": FLIP_RATES,
        "target_fpr": TARGET_FPR,
        "provenance": build_provenance(cifar_dir),
        "results": results,
        "caveat": (
            "This measures LABEL-FLIP poisoning detection (wrong labels, unchanged "
            "features). It is NOT the same as detecting a stealthy clean-label "
            "backdoor, where features are subtly perturbed to remain within-class "
            "and would evade this within-class anomaly approach."
        ),
    }

    json_path = os.path.join(out_dir, "report.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nWrote {json_path}")

    write_results_md(report, os.path.join(out_dir, "RESULTS.md"))
    print(f"Wrote {os.path.join(out_dir, 'RESULTS.md')}")
    return out_dir


def write_results_md(report, path):
    lines = []
    lines.append("# Dataset Poisoning Detector — CIFAR-10 Label-Flip Evaluation\n")
    lines.append(f"Generated (UTC): {report['generated_utc']}  ")
    lines.append(f"Seed: {report['seed']}\n")

    lines.append("## What this tests\n")
    lines.append(report["methodology"] + "\n")
    lines.append("> **Caveat:** " + report["caveat"] + "\n")

    lines.append("## Feature extraction\n")
    fe = report["feature_extraction"]
    lines.append(f"- Method: {fe['method']}")
    lines.append(f"- PCA dims: {fe['pca_dims']} "
                 f"(explained variance sum = {fe['pca_explained_variance_ratio_sum']:.3f})")
    lines.append(f"- {fe['note']}\n")

    lines.append("## Results per flip-rate\n")
    lines.append("| flip_rate | ROC-AUC | target FPR | operating threshold | ACTUAL FP rate (clean) | FP count | TPR @ threshold |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in report["results"]:
        if r["auc"] is not None:
            lines.append(
                f"| {r['flip_rate']} | {r['auc']:.4f} | {r['target_fpr']:.2f} | "
                f"{r['operating_threshold']:.4f} | {r['actual_fp_rate_on_clean']:.4f} "
                f"({r['actual_fp_count']}/{r['n_clean_evaluated']}) | {r['actual_fp_count']} | "
                f"{r['detection_rate_at_threshold']:.4f} |"
            )
        else:
            lines.append(
                f"| {r['flip_rate']} | n/a (no positives) | — | — | "
                f"FP@0.5={r.get('fp_rate_at_score_0.5')} | "
                f"{r.get('fp_count_at_score_0.5')} | — |"
            )
    lines.append("")
    lines.append("Note: flip_rate=0.0 has no poisoned samples, so ROC-AUC is undefined. "
                 "We still report the empirical false-positive rate at fixed score "
                 "thresholds to avoid any implicit 'zero false positives' claim.\n")

    lines.append("## Provenance\n")
    p = report["provenance"]
    lines.append(f"- Dataset: {p['dataset']}")
    lines.append(f"- URL: {p['url']}")
    lines.append(f"- SHA-256: `{p['sha256']}`")
    lines.append(f"- Size: {p['size_bytes']} bytes")
    lines.append(f"- Downloaded (UTC): {p['downloaded_utc']}")
    lines.append(f"- Local dir: `{p['local_dir']}`\n")

    lines.append("## Honest gaps\n")
    lines.append("- Subsets are tractable (450 clean/class), not the full 50k train set.")
    lines.append("- Feature space is generic PCA of raw pixels, not learned deep features; "
                 "detection power on label-flips depends on class separability in this space.")
    lines.append("- StreamingDetector.score_sample updates internal window/statistics as it "
                 "scores; baseline is contaminated at the stated flip_rate (realistic).")
    lines.append("- This is LABEL-FLIP detection only; clean-label / stealthy backdoors are "
                 "out of scope and would not be caught by within-class anomaly scoring.")

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
