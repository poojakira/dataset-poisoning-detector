"""
Honest benchmark runner: real dataset, injected poison, measured metrics.

Runs the full benchmark grid (every detection method + calibrated ensemble,
every attack, several contamination levels) on a real scikit-learn dataset and
prints the scorecard. Optionally writes the raw metrics to JSON.

Usage:
    python examples/benchmark.py                     # breast_cancer, default grid
    python examples/benchmark.py --dataset digits    # different dataset
    python examples/benchmark.py --json out.json     # also dump JSON

Every number printed is computed against the KNOWN injected poison indices --
nothing here is a demo constant. Small bundled datasets mean the absolute
percentages differ from web-scale data; the RELATIVE ranking of methods and
attacks is the transferable result.
"""

from __future__ import annotations

import argparse

from poison_detector.benchmark import run_benchmark, format_scorecard
from poison_detector.datasets import available_datasets


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the poisoning-detection benchmark.")
    parser.add_argument(
        "--dataset",
        default="breast_cancer",
        choices=available_datasets(),
        help="Bundled scikit-learn dataset to benchmark against.",
    )
    parser.add_argument(
        "--json",
        default="",
        help="Optional path to write the raw metrics as JSON.",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="Optional cap on dataset rows (keeps the run fast).",
    )
    args = parser.parse_args()

    report = run_benchmark(dataset=args.dataset, max_samples=args.max_samples)
    print(format_scorecard(report))

    if args.json:
        with open(args.json, "w") as f:
            f.write(report.to_json())
        print(f"\nRaw metrics written to {args.json}")


if __name__ == "__main__":
    main()
