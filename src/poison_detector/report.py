"""
Report formatting and export for detection results.

Provides human-readable, JSON, and CSV output formats for DetectionReport
objects. Designed for integration into CI/CD pipelines and security dashboards.

Security Notes:
    - JSON export uses standard library json module only.
    - No eval(), no pickle, no dynamic deserialization.
    - CSV output is properly escaped for injection prevention.
    - All output is deterministic given the same input.
"""

from __future__ import annotations

import json
import csv
import io
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .detector import DetectionReport


def format_report(report: "DetectionReport", verbose: bool = False) -> str:
    """Format a detection report as a human-readable string.

    Args:
        report: DetectionReport instance from detect().
        verbose: If True, include per-sample details. If False, summary only.

    Returns:
        Formatted multi-line string suitable for terminal or log output.
    """
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("DATASET POISONING DETECTION REPORT")
    lines.append("=" * 60)
    lines.append(f"Total samples analyzed: {report.total_samples}")
    lines.append(f"Samples flagged as poisoned: {report.poisoned_count}")

    if report.total_samples > 0:
        pct = (report.poisoned_count / report.total_samples) * 100
        lines.append(f"Poison rate: {pct:.2f}%")

    lines.append("")
    lines.append("Method scores:")
    for method, score in sorted(report.method_scores.items()):
        lines.append(f"  {method}: {score}")

    if verbose and report.per_sample:
        lines.append("")
        lines.append("-" * 60)
        lines.append("Per-sample details:")
        lines.append("-" * 60)
        for result in report.per_sample:
            if result.is_poisoned:
                lines.append(
                    f"  [POISONED] Sample {result.sample_idx}: "
                    f"score={result.anomaly_score:.4f}, "
                    f"method={result.method}, "
                    f"features={result.features_flagged}"
                )

    lines.append("=" * 60)
    return "\n".join(lines)


def export_json(report: "DetectionReport") -> str:
    """Export detection report as a JSON string.

    Produces a JSON-serializable representation of the full report,
    including all per-sample results.

    Args:
        report: DetectionReport instance from detect().

    Returns:
        JSON string (pretty-printed with 2-space indent).
    """
    data = {
        "total_samples": report.total_samples,
        "poisoned_count": report.poisoned_count,
        "method_scores": report.method_scores,
        "per_sample": [
            {
                "sample_idx": r.sample_idx,
                "anomaly_score": r.anomaly_score,
                "method": r.method,
                "features_flagged": r.features_flagged,
                "is_poisoned": r.is_poisoned,
            }
            for r in report.per_sample
        ],
    }
    return json.dumps(data, indent=2)


def export_csv(report: "DetectionReport") -> str:
    """Export detection report as CSV string.

    Produces a CSV with columns: sample_idx, score, is_poisoned.
    Suitable for import into spreadsheets or downstream analysis pipelines.

    Args:
        report: DetectionReport instance from detect().

    Returns:
        CSV string with header row and one data row per sample.
    """
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["sample_idx", "score", "is_poisoned"])
    for result in report.per_sample:
        writer.writerow([
            result.sample_idx,
            f"{result.anomaly_score:.6f}",
            result.is_poisoned,
        ])
    return output.getvalue()
