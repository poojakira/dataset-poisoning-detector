from benchmarks.public_breast_cancer_label_flip import run


def test_public_dataset_benchmark_is_deterministic_and_scoped():
    first = run(seed=20261003, poison_fraction=0.10)
    second = run(seed=20261003, poison_fraction=0.10)
    assert first == second
    assert first["dataset"] == "sklearn.datasets.load_breast_cancer"
    assert first["samples"] == 569
    assert first["features"] == 30
    assert first["poisoned_samples"] > 0
    assert 0 < first["flagged_samples"] < first["samples"]
    assert first["true_positives"] > 0
    assert first["f1"] >= 0.10
    assert 0.0 <= first["precision"] <= 1.0
    assert 0.0 <= first["recall"] <= 1.0
    assert 0.0 <= first["f1"] <= 1.0
    assert "Controlled label flips" in first["claim_boundary"]
