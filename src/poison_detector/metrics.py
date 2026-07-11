"""
Prometheus metrics for real-time poisoning detection monitoring.

Exposes counters, histograms, and gauges that track detection throughput,
latency, accuracy indicators, and system health. Compatible with any
Prometheus-compatible scraping system (Prometheus, Datadog, CloudWatch
via prometheus-to-cloudwatch, Grafana Agent, etc.).

Threat Model Assumptions:
    - Metrics are observability data, not security controls. An attacker who
      can read metrics sees detection rates but cannot alter detection behavior.
    - Metrics endpoints should be on an internal network, not publicly exposed,
      to avoid leaking information about detection sensitivity.

Honest Limitations:
    - Prometheus client uses a global registry by default. Multiple detector
      instances in the same process share metric state. This is intentional
      for production (one metrics endpoint per process) but can confuse tests.
    - Histogram buckets are pre-defined. If your scoring latency is outside
      the default bucket range, you will lose resolution. Adjust buckets
      based on your actual P99 latency.
    - Counter resets on process restart. Use rate() in PromQL, not raw values.

Security Notes:
    - Metric label values come from internal state, never from user input.
      Unbounded label cardinality is a denial-of-service vector for Prometheus.
    - No sensitive data (sample values, model weights) in metric labels.
    - The /metrics endpoint should require authentication in production.
"""

from __future__ import annotations

from prometheus_client import Counter, Histogram, Gauge, Info


# --- Counters ---
# Monotonically increasing values that track totals.

SAMPLES_PROCESSED = Counter(
    "poison_detector_samples_processed_total",
    "Total number of samples scored by the streaming detector",
    labelnames=["environment"],
)

SAMPLES_POISONED = Counter(
    "poison_detector_samples_poisoned_total",
    "Total number of samples flagged as poisoned",
    labelnames=["environment", "method"],
)

DRIFT_EVENTS = Counter(
    "poison_detector_drift_events_total",
    "Total number of concept drift events detected",
    labelnames=["environment", "drift_type"],
)

ALERTS_SENT = Counter(
    "poison_detector_alerts_sent_total",
    "Total number of alerts dispatched",
    labelnames=["environment", "channel"],
)

DUPLICATES_DETECTED = Counter(
    "poison_detector_duplicates_detected_total",
    "Total number of duplicate/near-duplicate samples detected",
    labelnames=["environment"],
)


# --- Histograms ---
# Distribution of values, auto-bucketed for percentile calculation.

SCORING_LATENCY = Histogram(
    "poison_detector_scoring_latency_seconds",
    "Time taken to score a single sample",
    labelnames=["environment", "method"],
    buckets=(0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
)

BATCH_LATENCY = Histogram(
    "poison_detector_batch_latency_seconds",
    "Time taken to score a batch of samples",
    labelnames=["environment"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

REFIT_LATENCY = Histogram(
    "poison_detector_refit_latency_seconds",
    "Time taken to refit the IsolationForest baseline model",
    labelnames=["environment"],
    buckets=(0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
)


# --- Gauges ---
# Point-in-time values that can go up or down.

DRIFT_SCORE = Gauge(
    "poison_detector_drift_score",
    "Current drift detection score (higher = more drift detected)",
    labelnames=["environment"],
)

QUEUE_DEPTH = Gauge(
    "poison_detector_queue_depth",
    "Number of samples waiting in the processing queue",
    labelnames=["environment"],
)

BASELINE_SIZE = Gauge(
    "poison_detector_baseline_size",
    "Number of samples in the current IsolationForest baseline",
    labelnames=["environment"],
)

POISON_RATE = Gauge(
    "poison_detector_poison_rate",
    "Rolling poison rate (fraction of recent samples flagged)",
    labelnames=["environment"],
)

FINGERPRINT_STORE_SIZE = Gauge(
    "poison_detector_fingerprint_store_size",
    "Number of fingerprints stored in the bloom filter",
    labelnames=["environment"],
)


# --- Info ---
# Static metadata about the detector instance.

DETECTOR_INFO = Info(
    "poison_detector",
    "Static metadata about the detector configuration",
)


def initialize_metrics(environment: str = "dev", version: str = "0.1.0") -> None:
    """Initialize metric labels and static info.

    Call this once at application startup to pre-create label combinations,
    avoiding the first-scrape gap where metrics are missing.

    Args:
        environment: Deployment environment name (dev, staging, prod).
        version: Application version string.
    """
    DETECTOR_INFO.info(
        {
            "version": version,
            "environment": environment,
        }
    )

    # Pre-initialize gauges to 0 so they appear in the first scrape
    DRIFT_SCORE.labels(environment=environment).set(0)
    QUEUE_DEPTH.labels(environment=environment).set(0)
    BASELINE_SIZE.labels(environment=environment).set(0)
    POISON_RATE.labels(environment=environment).set(0)
    FINGERPRINT_STORE_SIZE.labels(environment=environment).set(0)
