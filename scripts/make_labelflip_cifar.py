"""Build label-flip poisoned CIFAR-10 per-class groups.

Loads real CIFAR-10 python batches (pickle/numpy), standardizes pixels, fits a
PCA to 50 dims on the pooled sampled data, and constructs per-class groups where
a fraction of "members" of a class are actually samples flipped in from OTHER
classes (label-flip poisoning). Poisoned samples keep their ORIGINAL features;
only the assigned label is wrong -- so they are anomalous only WITHIN their
wrongly-assigned class.

Feature choice (documented): standardize the 3072 raw pixel values (mean/std
over the sampled pool) then reduce to 50 principal components via PCA fit on the
pooled sampled data. This is a generic, model-free feature space; label-flip
detection then reduces to "does this sample look like it belongs to the class it
claims to belong to?" in that space.
"""
from __future__ import annotations

import os
import pickle
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA

CIFAR_DIR = r"C:\Users\pooja\eval_work\cifar10\cifar-10-batches-py"
NUM_CLASSES = 10


def load_cifar_batches(cifar_dir: str = CIFAR_DIR):
    """Load and concatenate all training batches. Returns (X uint8 [N,3072], y int [N])."""
    if not os.path.isdir(cifar_dir):
        raise FileNotFoundError(
            f"CIFAR-10 batch dir not found: {cifar_dir}. Download/extract first (fail closed)."
        )
    xs, ys = [], []
    for i in range(1, 6):
        path = os.path.join(cifar_dir, f"data_batch_{i}")
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Missing CIFAR batch: {path} (fail closed).")
        with open(path, "rb") as f:
            d = pickle.load(f, encoding="bytes")
        xs.append(d[b"data"])
        ys.append(np.array(d[b"labels"], dtype=np.int64))
    X = np.concatenate(xs, axis=0)  # [50000, 3072] uint8
    y = np.concatenate(ys, axis=0)  # [50000]
    return X, y


def build_features(X_raw: np.ndarray, n_components: int = 50, seed: int = 42):
    """Standardize raw pixels then PCA to n_components. Fit on the pooled data.

    Returns (features [N, n_components] float64, scaler, pca).
    """
    Xf = X_raw.astype(np.float64)
    scaler = StandardScaler()
    Xs = scaler.fit_transform(Xf)
    pca = PCA(n_components=n_components, random_state=seed)
    feats = pca.fit_transform(Xs)
    return feats, scaler, pca


def build_labelflip_groups(
    feats: np.ndarray,
    y: np.ndarray,
    flip_rate: float,
    n_clean_per_class: int = 450,
    seed: int = 42,
):
    """Construct per-class groups with label-flip poisoning.

    For each class c:
      - take n_clean samples truly labeled c (the clean members)
      - add n_poison = round(flip_rate/(1-flip_rate) * n_clean) samples whose true
        label != c, drawn from the pool, now ASSIGNED to class c. Their features are
        unchanged (label-flip). So the poison fraction of the group ~= flip_rate.

    Returns dict: class -> {"features": [M, d], "is_flipped": [M] bool}.
    Sampling is disjoint across classes to avoid reusing the same rows.
    """
    rng = np.random.default_rng(seed)
    d = feats.shape[1]
    by_class = {c: np.where(y == c)[0] for c in range(NUM_CLASSES)}
    for c in range(NUM_CLASSES):
        rng.shuffle(by_class[c])

    # cursors to hand out disjoint indices per class as clean members
    clean_cursor = {c: 0 for c in range(NUM_CLASSES)}
    used = set()

    groups = {}
    # number of poison per class so that poison/(clean+poison) ~= flip_rate
    if flip_rate <= 0.0:
        n_poison_per_class = 0
    else:
        n_poison_per_class = int(round(flip_rate / (1.0 - flip_rate) * n_clean_per_class))

    # First pass: assign clean members per class (disjoint)
    clean_idx_by_class = {}
    for c in range(NUM_CLASSES):
        idxs = by_class[c][clean_cursor[c]: clean_cursor[c] + n_clean_per_class]
        clean_cursor[c] += n_clean_per_class
        if len(idxs) < n_clean_per_class:
            raise ValueError(f"Not enough samples for class {c}")
        clean_idx_by_class[c] = idxs
        used.update(idxs.tolist())

    # Second pass: assign poison (flipped-in) members from OTHER classes
    for c in range(NUM_CLASSES):
        clean_idxs = clean_idx_by_class[c]
        poison_idxs = []
        if n_poison_per_class > 0:
            other_classes = [oc for oc in range(NUM_CLASSES) if oc != c]
            attempts = 0
            while len(poison_idxs) < n_poison_per_class and attempts < 100000:
                oc = other_classes[rng.integers(0, len(other_classes))]
                pool = by_class[oc][clean_cursor[oc]:]
                if len(pool) == 0:
                    attempts += 1
                    continue
                pick = pool[rng.integers(0, len(pool))]
                if int(pick) in used:
                    attempts += 1
                    continue
                poison_idxs.append(int(pick))
                used.add(int(pick))
                attempts += 1
            if len(poison_idxs) < n_poison_per_class:
                raise ValueError(f"Could not gather enough poison for class {c}")

        member_idxs = np.concatenate(
            [clean_idxs, np.array(poison_idxs, dtype=np.int64)]
        ) if poison_idxs else clean_idxs
        is_flipped = np.concatenate(
            [np.zeros(len(clean_idxs), dtype=bool),
             np.ones(len(poison_idxs), dtype=bool)]
        ) if poison_idxs else np.zeros(len(clean_idxs), dtype=bool)

        # shuffle within group
        order = rng.permutation(len(member_idxs))
        member_idxs = member_idxs[order]
        is_flipped = is_flipped[order]

        groups[c] = {
            "features": feats[member_idxs],
            "is_flipped": is_flipped,
            "n_clean": int((~is_flipped).sum()),
            "n_poison": int(is_flipped.sum()),
        }
    return groups
