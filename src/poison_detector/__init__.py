"""
Dataset Poisoning Detector - Catch malicious training samples before they corrupt your model.

This library provides multiple anomaly detection methods (z-score, IQR, Isolation Forest)
and an ensemble approach that combines them via majority voting for robust detection of
poisoned training data.

v0.2.0 adds real-time streaming detection, concept drift monitoring, sample fingerprinting,
quarantine storage, multi-channel alerting, and a FastAPI service for production deployment.

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

Real-Time API (requires `pip install -e ".[realtime]"`):
    - StreamingDetector: Online scoring with rolling statistics
    - ConceptDriftDetector: ADWIN + Page-Hinkley drift detection
    - SampleFingerprinter: Bloom filter + cosine similarity deduplication
    - QuarantineStore / SQLiteStore: Flagged sample storage
    - AlertDispatcher: Multi-channel alerting with deduplication
    - DetectorConfig: Pydantic-based configuration management
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

__version__ = "1.0.0"

# Conditional imports for real-time modules (require [realtime] extras)
try:
    from .stream import StreamingDetector
    from .drift import ConceptDriftDetector
    from .fingerprint import SampleFingerprinter
    from .config import DetectorConfig
    from .metrics import SAMPLES_PROCESSED, SAMPLES_POISONED, SCORING_LATENCY
    from .storage import QuarantineStore, SQLiteStore
    from .alerting import AlertDispatcher

    __all__ += [
        "StreamingDetector",
        "ConceptDriftDetector",
        "SampleFingerprinter",
        "DetectorConfig",
        "SAMPLES_PROCESSED",
        "SAMPLES_POISONED",
        "SCORING_LATENCY",
        "QuarantineStore",
        "SQLiteStore",
        "AlertDispatcher",
    ]
except ImportError:
    # Real-time dependencies not installed -- core API still works
    pass

# Conditional imports for security modules (require [security] extras: cryptography, PyJWT, bcrypt)
try:
    from .auth import JWTAuthenticator, APIKeyAuthenticator, MTLSValidator
    from .rbac import RBACEnforcer, Role, Permission
    from .crypto import DataEncryptor, IntegrityVerifier
    from .audit import AuditLogger
    from .input_sanitizer import InputSanitizer
    from .circuit_breaker import CircuitBreaker
    from .rate_limiter import SlidingWindowRateLimiter, TokenBucketRateLimiter, CompositeRateLimiter

    __all__ += [
        "JWTAuthenticator",
        "APIKeyAuthenticator",
        "MTLSValidator",
        "RBACEnforcer",
        "Role",
        "Permission",
        "DataEncryptor",
        "IntegrityVerifier",
        "AuditLogger",
        "InputSanitizer",
        "CircuitBreaker",
        "SlidingWindowRateLimiter",
        "TokenBucketRateLimiter",
        "CompositeRateLimiter",
    ]
except ImportError:
    # Security dependencies not installed -- core API still works
    pass
