"""Tests for report formatting and export (human-readable, JSON, CSV)."""

import csv
import io
import json

from poison_detector.detector import detect
from poison_detector.report import export_csv, export_json, format_report


def _sample_report():
    X = [[float(i) * 0.1, float(i) * 0.1] for i in range(60)]
    X += [[99.0, 99.0], [100.0, 100.0]]
    return detect(X, method="zscore")


def test_format_report_summary():
    report = _sample_report()
    text = format_report(report, verbose=False)
    assert "DATASET POISONING DETECTION REPORT" in text
    assert "Total samples analyzed" in text
    assert "Poison rate" in text
    assert "Method scores" in text


def test_format_report_verbose_lists_poisoned():
    report = _sample_report()
    text = format_report(report, verbose=True)
    assert "Per-sample details" in text
    # At least one poisoned line should appear.
    assert "[POISONED]" in text


def test_export_json_roundtrip():
    report = _sample_report()
    parsed = json.loads(export_json(report))
    assert parsed["total_samples"] == report.total_samples
    assert len(parsed["per_sample"]) == report.total_samples


def test_export_csv_structure():
    report = _sample_report()
    text = export_csv(report)
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0] == ["sample_idx", "score", "is_poisoned"]
    assert len(rows) == report.total_samples + 1
