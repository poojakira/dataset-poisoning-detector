"""
Dataset Poisoning Detector - Catch malicious training samples before they corrupt your model.

This library provides multiple anomaly detection methods (z-score, IQR, Isolation Forest)
and an ensemble approach that combines them via majority voting for robust detection of
poisoned training data.

Public API:
    - detect(): Main entry point for running detection
    - PoisonResult: Per-sample result dataclass
    - DetectionReport: Full scan report dataclass
    - zscore_detect(): Pure-Python z-score anomaly detection
    - iqr_detect(): Pure-Python IQR fencing
    - IsolationDetector: scikit-learn IsolationForest wrapper
    - feature_attribution(): Feature-level attribution for flagged samples
    - format_report(): Human-readable report formatting
    - export_json(): JSON export
    - export_csv(): CSV export
"""

from .detector import PoisonResult, DetectionReport, detect
from .statistical import zscore_detect, iqr_detect
from .isolation import IsolationDetector
from .attribution import feature_attribution
from .report import format_report, export_json, export_csv

__all__ = [
    "PoisonResult",
    "DetectionReport",
    "detect",
    "zscore_detect",
    "iqr_detect",
    "IsolationDetector",
    "feature_attribution",
    "format_report",
    "export_json",
    "export_csv",
]

__version__ = "0.1.0"
