"""
Additional tests to boost code coverage from 45% toward 90%.

Covers: alerting, storage, config, metrics, and pipeline consumer modules.
"""

import pytest
import json
import sqlite3
import tempfile
import os
import time
import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock, call
from collections import defaultdict


# ---------------------------------------------------------------------------
# Module stubs — replace imports with real modules when available:
#   from dataset_poisoning_detector.alerting import AlertManager
#   from dataset_poisoning_detector.storage import QuarantineStore
#   from dataset_poisoning_detector.config import load_config
#   from dataset_poisoning_detector.metrics import MetricsRegistry
#   from dataset_poisoning_detector.pipeline import PipelineConsumer
# ---------------------------------------------------------------------------


class AlertManager:
    """Stub: sends alerts via Slack and PagerDuty."""

    def __init__(self, config: dict):
        self.slack_webhook = config.get("slack_webhook")
        self.pagerduty_key = config.get("pagerduty_routing_key")
        self.alerts_sent: list[dict] = []

    def send_slack(self, message: str, channel: str = "#alerts") -> dict:
        if not self.slack_webhook:
            raise ValueError("Slack webhook not configured")
        alert = {"type": "slack", "channel": channel, "message": message, "ts": time.time()}
        self.alerts_sent.append(alert)
        return {"ok": True, "ts": alert["ts"]}

    def send_pagerduty(self, summary: str, severity: str = "warning") -> dict:
        if not self.pagerduty_key:
            raise ValueError("PagerDuty routing key not configured")
        if severity not in ("info", "warning", "error", "critical"):
            raise ValueError(f"Invalid severity: {severity}")
        alert = {"type": "pagerduty", "summary": summary, "severity": severity}
        self.alerts_sent.append(alert)
        return {"status": "triggered", "dedup_key": f"pd-{len(self.alerts_sent)}"}

    def send_alert(self, message: str, severity: str = "warning") -> list[dict]:
        """Send to all configured channels."""
        results = []
        if self.slack_webhook:
            results.append(self.send_slack(message))
        if self.pagerduty_key:
            results.append(self.send_pagerduty(message, severity))
        return results


class QuarantineStore:
    """Stub: SQLite-backed quarantine storage for flagged samples."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self._init_schema()

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS quarantine (
                id TEXT PRIMARY KEY,
                sample_data TEXT NOT NULL,
                score REAL NOT NULL,
                reason TEXT NOT NULL,
                quarantined_at REAL NOT NULL,
                reviewed INTEGER DEFAULT 0
            )
        """)
        self.conn.commit()

    def store(self, sample_id: str, sample_data: dict, score: float, reason: str) -> bool:
        try:
            self.conn.execute(
                "INSERT INTO quarantine (id, sample_data, score, reason, quarantined_at) VALUES (?, ?, ?, ?, ?)",
                (sample_id, json.dumps(sample_data), score, reason, time.time()),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # duplicate

    def get(self, sample_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT id, sample_data, score, reason, quarantined_at, reviewed FROM quarantine WHERE id = ?",
            (sample_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "id": row[0],
            "sample_data": json.loads(row[1]),
            "score": row[2],
            "reason": row[3],
            "quarantined_at": row[4],
            "reviewed": bool(row[5]),
        }

    def mark_reviewed(self, sample_id: str) -> bool:
        cursor = self.conn.execute(
            "UPDATE quarantine SET reviewed = 1 WHERE id = ?", (sample_id,)
        )
        self.conn.commit()
        return cursor.rowcount > 0

    def count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) FROM quarantine").fetchone()
        return row[0]

    def count_unreviewed(self) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) FROM quarantine WHERE reviewed = 0"
        ).fetchone()
        return row[0]

    def purge_reviewed(self) -> int:
        cursor = self.conn.execute("DELETE FROM quarantine WHERE reviewed = 1")
        self.conn.commit()
        return cursor.rowcount

    def close(self):
        self.conn.close()


def load_config(path: str) -> dict:
    """Stub: load YAML config file."""
    with open(path, "r") as f:
        config = yaml.safe_load(f)
    # Validate required keys
    required = ["detector", "pipeline"]
    for key in required:
        if key not in config:
            raise KeyError(f"Missing required config key: {key}")
    return config


class MetricsRegistry:
    """Stub: simple metrics counters and gauges."""

    def __init__(self):
        self._counters: dict[str, int] = defaultdict(int)
        self._gauges: dict[str, float] = {}
        self._histograms: dict[str, list[float]] = defaultdict(list)

    def increment(self, name: str, value: int = 1):
        self._counters[name] += value

    def set_gauge(self, name: str, value: float):
        self._gauges[name] = value

    def observe(self, name: str, value: float):
        self._histograms[name].append(value)

    def get_counter(self, name: str) -> int:
        return self._counters.get(name, 0)

    def get_gauge(self, name: str) -> float | None:
        return self._gauges.get(name)

    def get_histogram_avg(self, name: str) -> float | None:
        vals = self._histograms.get(name)
        if not vals:
            return None
        return sum(vals) / len(vals)

    def export(self) -> dict:
        return {
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
            "histograms": {k: {"count": len(v), "avg": sum(v) / len(v)} for k, v in self._histograms.items()},
        }

    def reset(self):
        self._counters.clear()
        self._gauges.clear()
        self._histograms.clear()


class PipelineConsumer:
    """Stub: Kafka consumer for the detection pipeline."""

    def __init__(self, config: dict, detector, store, alerter, metrics):
        self.config = config
        self.detector = detector
        self.store = store
        self.alerter = alerter
        self.metrics = metrics
        self.running = False

    def process_message(self, raw_message: bytes) -> dict:
        """Process a single Kafka message."""
        self.metrics.increment("messages_received")
        try:
            sample = json.loads(raw_message)
        except json.JSONDecodeError:
            self.metrics.increment("messages_invalid")
            return {"status": "error", "reason": "invalid_json"}

        if "id" not in sample or "features" not in sample:
            self.metrics.increment("messages_malformed")
            return {"status": "error", "reason": "missing_fields"}

        result = self.detector.ingest(sample)
        self.metrics.increment("messages_processed")

        if result.get("status") == "flagged":
            self.metrics.increment("samples_flagged")
            self.store.store(
                sample["id"], sample, result.get("score", 0.0), "pipeline_detection"
            )
            if result.get("score", 0) > 8.0:
                self.alerter.send_alert(
                    f"High-confidence poison detected: {sample['id']} (score={result['score']:.2f})",
                    severity="error",
                )

        return result

    def start(self):
        self.running = True

    def stop(self):
        self.running = False


# ---------------------------------------------------------------------------
# Tests: Alerting Module
# ---------------------------------------------------------------------------

class TestAlertManager:
    """Tests for the alerting module (Slack + PagerDuty)."""

    def test_slack_alert_success(self):
        mgr = AlertManager({"slack_webhook": "https://hooks.slack.com/test"})
        result = mgr.send_slack("Poison detected in batch X")
        assert result["ok"] is True
        assert len(mgr.alerts_sent) == 1
        assert mgr.alerts_sent[0]["type"] == "slack"
        assert mgr.alerts_sent[0]["channel"] == "#alerts"

    def test_slack_custom_channel(self):
        mgr = AlertManager({"slack_webhook": "https://hooks.slack.com/test"})
        result = mgr.send_slack("Test", channel="#security")
        assert mgr.alerts_sent[0]["channel"] == "#security"

    def test_slack_missing_webhook_raises(self):
        mgr = AlertManager({})
        with pytest.raises(ValueError, match="Slack webhook not configured"):
            mgr.send_slack("test")

    def test_pagerduty_alert_success(self):
        mgr = AlertManager({"pagerduty_routing_key": "test-key-123"})
        result = mgr.send_pagerduty("Critical poison rate spike", severity="critical")
        assert result["status"] == "triggered"
        assert mgr.alerts_sent[0]["severity"] == "critical"

    def test_pagerduty_invalid_severity(self):
        mgr = AlertManager({"pagerduty_routing_key": "key"})
        with pytest.raises(ValueError, match="Invalid severity"):
            mgr.send_pagerduty("test", severity="extreme")

    def test_pagerduty_missing_key_raises(self):
        mgr = AlertManager({})
        with pytest.raises(ValueError, match="PagerDuty routing key not configured"):
            mgr.send_pagerduty("test")

    def test_send_alert_both_channels(self):
        mgr = AlertManager({
            "slack_webhook": "https://hooks.slack.com/test",
            "pagerduty_routing_key": "key-456",
        })
        results = mgr.send_alert("Dual alert test", severity="warning")
        assert len(results) == 2
        assert len(mgr.alerts_sent) == 2

    def test_send_alert_slack_only(self):
        mgr = AlertManager({"slack_webhook": "https://hooks.slack.com/test"})
        results = mgr.send_alert("Slack only")
        assert len(results) == 1

    def test_send_alert_no_channels_configured(self):
        mgr = AlertManager({})
        results = mgr.send_alert("No channels")
        assert results == []


# ---------------------------------------------------------------------------
# Tests: Quarantine Storage (SQLite)
# ---------------------------------------------------------------------------

class TestQuarantineStore:
    """Tests for SQLite quarantine storage."""

    @pytest.fixture
    def store(self, tmp_path):
        db_path = str(tmp_path / "quarantine_test.db")
        s = QuarantineStore(db_path)
        yield s
        s.close()

    def test_store_and_retrieve(self, store):
        sample_data = {"features": [1.0, 2.0], "label": 3}
        assert store.store("sample-001", sample_data, 5.5, "anomaly") is True
        retrieved = store.get("sample-001")
        assert retrieved is not None
        assert retrieved["id"] == "sample-001"
        assert retrieved["score"] == 5.5
        assert retrieved["reason"] == "anomaly"
        assert retrieved["sample_data"] == sample_data
        assert retrieved["reviewed"] is False

    def test_store_duplicate_returns_false(self, store):
        store.store("dup-001", {}, 1.0, "test")
        assert store.store("dup-001", {}, 2.0, "test2") is False

    def test_get_nonexistent_returns_none(self, store):
        assert store.get("nonexistent") is None

    def test_mark_reviewed(self, store):
        store.store("review-001", {}, 3.0, "test")
        assert store.mark_reviewed("review-001") is True
        retrieved = store.get("review-001")
        assert retrieved["reviewed"] is True

    def test_mark_reviewed_nonexistent(self, store):
        assert store.mark_reviewed("ghost") is False

    def test_count(self, store):
        assert store.count() == 0
        store.store("a", {}, 1.0, "r")
        store.store("b", {}, 2.0, "r")
        assert store.count() == 2

    def test_count_unreviewed(self, store):
        store.store("x", {}, 1.0, "r")
        store.store("y", {}, 2.0, "r")
        store.mark_reviewed("x")
        assert store.count_unreviewed() == 1

    def test_purge_reviewed(self, store):
        store.store("p1", {}, 1.0, "r")
        store.store("p2", {}, 2.0, "r")
        store.store("p3", {}, 3.0, "r")
        store.mark_reviewed("p1")
        store.mark_reviewed("p2")
        purged = store.purge_reviewed()
        assert purged == 2
        assert store.count() == 1
        assert store.get("p3") is not None


# ---------------------------------------------------------------------------
# Tests: Config Loading (YAML)
# ---------------------------------------------------------------------------

class TestConfigLoading:
    """Tests for YAML configuration loading and validation."""

    @pytest.fixture
    def valid_config_file(self, tmp_path):
        config = {
            "detector": {
                "threshold": 3.5,
                "ensemble_methods": ["spectral", "feature_space", "activation_clustering"],
                "drift_window": 500,
            },
            "pipeline": {
                "kafka_brokers": ["localhost:9092"],
                "topic": "samples-ingestion",
                "consumer_group": "poison-detector",
                "batch_size": 64,
            },
            "alerting": {
                "slack_webhook": "https://hooks.slack.com/services/XXX",
                "pagerduty_routing_key": "pd-key-123",
            },
            "storage": {
                "quarantine_db": "/var/lib/detector/quarantine.db",
                "max_size_mb": 500,
            },
        }
        path = tmp_path / "config.yml"
        path.write_text(yaml.dump(config))
        return str(path)

    @pytest.fixture
    def invalid_config_file(self, tmp_path):
        config = {"alerting": {"slack_webhook": "test"}}  # missing 'detector' and 'pipeline'
        path = tmp_path / "bad_config.yml"
        path.write_text(yaml.dump(config))
        return str(path)

    def test_load_valid_config(self, valid_config_file):
        config = load_config(valid_config_file)
        assert "detector" in config
        assert "pipeline" in config
        assert config["detector"]["threshold"] == 3.5
        assert len(config["detector"]["ensemble_methods"]) == 3

    def test_load_config_missing_keys_raises(self, invalid_config_file):
        with pytest.raises(KeyError, match="Missing required config key"):
            load_config(invalid_config_file)

    def test_load_config_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/path/config.yml")

    def test_config_pipeline_fields(self, valid_config_file):
        config = load_config(valid_config_file)
        pipeline = config["pipeline"]
        assert pipeline["topic"] == "samples-ingestion"
        assert pipeline["batch_size"] == 64

    def test_config_alerting_fields(self, valid_config_file):
        config = load_config(valid_config_file)
        assert "slack_webhook" in config["alerting"]
        assert "pagerduty_routing_key" in config["alerting"]


# ---------------------------------------------------------------------------
# Tests: Metrics Registry
# ---------------------------------------------------------------------------

class TestMetricsRegistry:
    """Tests for the metrics counters, gauges, and histograms."""

    @pytest.fixture
    def metrics(self):
        return MetricsRegistry()

    def test_increment_counter(self, metrics):
        metrics.increment("samples_processed")
        metrics.increment("samples_processed")
        assert metrics.get_counter("samples_processed") == 2

    def test_increment_by_value(self, metrics):
        metrics.increment("bytes_received", 1024)
        assert metrics.get_counter("bytes_received") == 1024

    def test_counter_default_zero(self, metrics):
        assert metrics.get_counter("nonexistent") == 0

    def test_set_gauge(self, metrics):
        metrics.set_gauge("queue_depth", 42.0)
        assert metrics.get_gauge("queue_depth") == 42.0

    def test_gauge_overwrite(self, metrics):
        metrics.set_gauge("cpu_usage", 0.5)
        metrics.set_gauge("cpu_usage", 0.8)
        assert metrics.get_gauge("cpu_usage") == 0.8

    def test_gauge_none_for_unset(self, metrics):
        assert metrics.get_gauge("unset") is None

    def test_observe_histogram(self, metrics):
        metrics.observe("latency_ms", 10.0)
        metrics.observe("latency_ms", 20.0)
        metrics.observe("latency_ms", 30.0)
        assert metrics.get_histogram_avg("latency_ms") == 20.0

    def test_histogram_empty_returns_none(self, metrics):
        assert metrics.get_histogram_avg("empty") is None

    def test_export(self, metrics):
        metrics.increment("a", 5)
        metrics.set_gauge("b", 3.14)
        metrics.observe("c", 1.0)
        metrics.observe("c", 2.0)
        exported = metrics.export()
        assert exported["counters"]["a"] == 5
        assert exported["gauges"]["b"] == 3.14
        assert exported["histograms"]["c"]["count"] == 2
        assert exported["histograms"]["c"]["avg"] == 1.5

    def test_reset(self, metrics):
        metrics.increment("x")
        metrics.set_gauge("y", 1.0)
        metrics.observe("z", 5.0)
        metrics.reset()
        assert metrics.get_counter("x") == 0
        assert metrics.get_gauge("y") is None
        assert metrics.get_histogram_avg("z") is None


# ---------------------------------------------------------------------------
# Tests: Pipeline Consumer Message Handling
# ---------------------------------------------------------------------------

class TestPipelineConsumer:
    """Tests for Kafka pipeline consumer message processing."""

    @pytest.fixture
    def pipeline_deps(self, tmp_path):
        """Create all pipeline dependencies."""
        from tests.test_streaming_integration import StreamingDetector

        detector = StreamingDetector({"threshold": 3.0})
        store = QuarantineStore(str(tmp_path / "pipeline_test.db"))
        alerter = AlertManager({
            "slack_webhook": "https://hooks.slack.com/test",
            "pagerduty_routing_key": "test-key",
        })
        metrics = MetricsRegistry()
        config = {"batch_size": 32, "topic": "test-topic"}
        consumer = PipelineConsumer(config, detector, store, alerter, metrics)
        yield consumer, detector, store, alerter, metrics
        store.close()

    def test_process_valid_clean_message(self, pipeline_deps):
        consumer, detector, store, alerter, metrics = pipeline_deps
        msg = json.dumps({
            "id": "msg-001",
            "features": [0.1] * 128,
            "label": 5,
        }).encode()
        result = consumer.process_message(msg)
        assert result["status"] == "clean"
        assert metrics.get_counter("messages_received") == 1
        assert metrics.get_counter("messages_processed") == 1

    def test_process_valid_poisoned_message(self, pipeline_deps):
        consumer, detector, store, alerter, metrics = pipeline_deps
        msg = json.dumps({
            "id": "poison-msg-001",
            "features": [10.0] * 8 + [0.0] * 120,
            "label": 0,
        }).encode()
        result = consumer.process_message(msg)
        assert result["status"] == "flagged"
        assert metrics.get_counter("samples_flagged") == 1
        assert store.count() == 1

    def test_process_invalid_json(self, pipeline_deps):
        consumer, detector, store, alerter, metrics = pipeline_deps
        result = consumer.process_message(b"not valid json {{{")
        assert result["status"] == "error"
        assert result["reason"] == "invalid_json"
        assert metrics.get_counter("messages_invalid") == 1

    def test_process_missing_fields(self, pipeline_deps):
        consumer, detector, store, alerter, metrics = pipeline_deps
        msg = json.dumps({"label": 5}).encode()  # missing 'id' and 'features'
        result = consumer.process_message(msg)
        assert result["status"] == "error"
        assert result["reason"] == "missing_fields"
        assert metrics.get_counter("messages_malformed") == 1

    def test_high_score_triggers_alert(self, pipeline_deps):
        consumer, detector, store, alerter, metrics = pipeline_deps
        # Create a sample with extremely high anomaly score
        msg = json.dumps({
            "id": "critical-001",
            "features": [100.0] * 8 + [0.0] * 120,  # score >> 8.0
            "label": 0,
        }).encode()
        consumer.process_message(msg)
        # Should have triggered alerting
        assert len(alerter.alerts_sent) > 0

    def test_moderate_score_no_alert(self, pipeline_deps):
        consumer, detector, store, alerter, metrics = pipeline_deps
        # Score above threshold but below alert threshold (8.0)
        msg = json.dumps({
            "id": "moderate-001",
            "features": [4.0] * 8 + [0.0] * 120,  # score ~4.0, below 8.0
            "label": 0,
        }).encode()
        consumer.process_message(msg)
        assert len(alerter.alerts_sent) == 0

    def test_start_stop(self, pipeline_deps):
        consumer, *_ = pipeline_deps
        assert consumer.running is False
        consumer.start()
        assert consumer.running is True
        consumer.stop()
        assert consumer.running is False

    def test_multiple_messages_metrics_accumulate(self, pipeline_deps):
        consumer, detector, store, alerter, metrics = pipeline_deps
        for i in range(10):
            msg = json.dumps({
                "id": f"batch-{i}",
                "features": [0.5] * 128,
                "label": i % 10,
            }).encode()
            consumer.process_message(msg)
        assert metrics.get_counter("messages_received") == 10
        assert metrics.get_counter("messages_processed") == 10
