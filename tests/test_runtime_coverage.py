from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from poison_detector.alerting import (
    Alert,
    AlertDispatcher,
    AlertSeverity,
    AlertType,
    SlackChannel,
    WebhookChannel,
    _validate_http_url,
)
from poison_detector.config import DetectorConfig, _load_yaml_file
from poison_detector.detector import DetectionReport, PoisonResult
from poison_detector.pipeline import (
    KafkaConsumer,
    PipelineConsumer,
    PipelineMessage,
    ProcessingMode,
    ProcessingResult,
    RedisConsumer,
)
from poison_detector.report import export_csv, export_json, format_report
from poison_detector.storage import (
    PostgresStore,
    QuarantineStats,
    ResolutionStatus,
    S3Store,
    SQLiteStore,
)


class _DummyConsumer(PipelineConsumer):
    async def connect(self) -> None:
        self._running = True

    async def disconnect(self) -> None:
        self._running = False

    async def consume(self, handler, batch_size: int = 10) -> None:
        return None

    async def acknowledge(self, message_id: str) -> None:
        return None

    async def dead_letter(self, message: PipelineMessage, error: str) -> None:
        return None

    async def quarantine(self, message: PipelineMessage, score: float) -> None:
        return None


class _Channel:
    def __init__(self, result: bool = True, fail: bool = False):
        self.result = result
        self.fail = fail
        self.sent: list[Alert] = []

    def send(self, alert: Alert) -> bool:
        self.sent.append(alert)
        if self.fail:
            raise RuntimeError("channel failed")
        return self.result


def _report() -> DetectionReport:
    samples = [
        PoisonResult(
            sample_idx=0,
            anomaly_score=0.1,
            method="zscore",
            features_flagged=[],
            is_poisoned=False,
        ),
        PoisonResult(
            sample_idx=1,
            anomaly_score=0.95,
            method="ensemble",
            features_flagged=[2, 4],
            is_poisoned=True,
        ),
    ]
    return DetectionReport(
        total_samples=2,
        poisoned_count=1,
        method_scores={"zscore": 0.2, "ensemble": 0.9},
        per_sample=samples,
    )


def test_report_formats_cover_summary_verbose_json_csv():
    report = _report()
    summary = format_report(report)
    verbose = format_report(report, verbose=True)
    assert "Poison rate: 50.00%" in summary
    assert "[POISONED] Sample 1" in verbose

    data = json.loads(export_json(report))
    assert data["poisoned_count"] == 1
    assert data["per_sample"][1]["features_flagged"] == [2, 4]

    csv_text = export_csv(report)
    assert "sample_idx,score,is_poisoned" in csv_text
    assert "1,0.950000,True" in csv_text


def test_report_zero_samples_has_no_rate():
    empty = DetectionReport(total_samples=0, poisoned_count=0, method_scores={}, per_sample=[])
    assert "Poison rate:" not in format_report(empty)


def test_config_yaml_overrides_and_env_precedence(tmp_path, monkeypatch):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        """
environment: prod
thresholds:
  zscore_threshold: 4.5
streaming:
  max_batch_size: 64
features:
  enable_alerting: true
alerts:
  cooldown_seconds: 42
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("POISON_THRESHOLD_ZSCORE_THRESHOLD", "9.0")
    loaded = DetectorConfig.from_yaml(cfg)
    assert loaded.environment == "prod"
    assert loaded.thresholds.zscore_threshold == 9.0
    assert loaded.streaming.max_batch_size == 64
    assert loaded.features.enable_alerting is True
    assert loaded.alerts.cooldown_seconds == 42
    assert "POISON_CONFIG_FILE" not in __import__("os").environ


def test_config_loader_missing_invalid_and_non_mapping(tmp_path):
    assert _load_yaml_file(tmp_path / "missing.yaml") is None
    malformed = tmp_path / "bad.yaml"
    malformed.write_text("foo: [", encoding="utf-8")
    assert _load_yaml_file(malformed) is None
    sequence = tmp_path / "list.yaml"
    sequence.write_text("- a\n- b\n", encoding="utf-8")
    assert _load_yaml_file(sequence) is None


def test_sqlite_quarantine_round_trip_and_stats(tmp_path):
    store = SQLiteStore(str(tmp_path / "quarantine.db"))
    first = store.store_sample(
        [1.0, 2.0],
        {"ensemble": 0.9},
        timestamp="2026-01-01T00:00:00+00:00",
        source="test",
        metadata={"batch": "a"},
    )
    second = store.store_sample(
        {"x": 1},
        {"zscore": 0.8},
        timestamp="2026-01-02T00:00:00+00:00",
    )
    assert store.get_sample("missing") is None
    sample = store.get_sample(first)
    assert sample is not None
    assert sample.sample_data == [1.0, 2.0]
    assert sample.metadata == {"batch": "a"}
    assert [x.sample_id for x in store.get_pending_reviews(limit=1)] == [first]
    assert store.resolve(first, ResolutionStatus.CONFIRMED_POISON, "alice", "confirmed")
    assert not store.resolve("missing", ResolutionStatus.FALSE_POSITIVE)
    assert store.resolve(second, ResolutionStatus.FALSE_POSITIVE, "bob", "clean")
    stats = store.get_stats()
    assert stats.total_entries == 2
    assert stats.pending_reviews == 0
    assert stats.confirmed_poison == 1
    assert stats.false_positives == 1
    assert stats.oldest_pending == ""
    store.close()


def test_unimplemented_storage_backends_fail_explicitly():
    with pytest.raises(NotImplementedError):
        PostgresStore("postgresql://example.invalid/db")
    with pytest.raises(NotImplementedError):
        S3Store("bucket")

    pg = object.__new__(PostgresStore)
    s3 = object.__new__(S3Store)
    for backend in (pg, s3):
        with pytest.raises(NotImplementedError):
            backend.store_sample([], {})
        with pytest.raises(NotImplementedError):
            backend.get_sample("id")
        with pytest.raises(NotImplementedError):
            backend.get_pending_reviews()
        with pytest.raises(NotImplementedError):
            backend.resolve("id", ResolutionStatus.NEEDS_INVESTIGATION)
        with pytest.raises(NotImplementedError):
            backend.get_stats()


def test_alert_url_validation_and_payload_delivery(monkeypatch):
    assert _validate_http_url("https://example.com/hook") == "https://example.com/hook"
    for bad in ("file:///tmp/x", "example.com/no-scheme", "https://user:pass@example.com/x"):
        with pytest.raises(ValueError):
            _validate_http_url(bad)

    captured = {}

    def fake_send(url, payload, *, allowed_hosts, headers=None):
        captured["url"] = url
        captured["data"] = payload
        captured["hosts"] = allowed_hosts
        captured["headers"] = headers
        return 204

    monkeypatch.setenv("POISON_ALERT_WEBHOOK_HOSTS", "example.com")
    monkeypatch.setattr("poison_detector.alerting._send_alert_json", fake_send)
    alert = Alert(
        AlertType.SYSTEM_ERROR,
        AlertSeverity.CRITICAL,
        "failure",
        "details",
        {"component": "worker"},
    )
    webhook = WebhookChannel("https://example.com/hook", {"Authorization": "Bearer test"})
    assert webhook.send(alert)
    assert captured["data"]["severity"] == "critical"
    assert captured["hosts"] == {"example.com"}

    slack = SlackChannel("https://hooks.slack.com/services/mock", channel="#security")
    assert not slack.send(alert)  # Slack requires status == 200; fake response is 204.


def test_alert_dispatch_dedup_escalation_and_channel_failure(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("poison_detector.alerting.time.time", lambda: now[0])
    good = _Channel(True)
    bad = _Channel(fail=True)
    dispatcher = AlertDispatcher(cooldown_seconds=10, escalation_window=500)
    dispatcher.add_channel(good)
    dispatcher.add_channel(bad)
    base = Alert(
        AlertType.DRIFT_DETECTED, AlertSeverity.WARNING, "drift", "detected", timestamp=0.0
    )

    assert dispatcher.dispatch(base) is True
    now[0] = 101.0
    assert dispatcher.dispatch(base) is False
    now[0] = 700.0
    assert dispatcher.dispatch(base) is True
    assert good.sent[-1].severity is AlertSeverity.CRITICAL
    now[0] = 1200.0
    assert dispatcher.dispatch(base) is True
    assert good.sent[-1].severity is AlertSeverity.PAGE
    assert len(dispatcher.get_recent_alerts(limit=2)) == 2
    assert dispatcher.channel_count == 2
    dispatcher.clear_dedup_state()
    assert dispatcher._dedup_state == {}


@pytest.mark.asyncio
async def test_pipeline_base_backpressure_stats_and_stop():
    consumer = _DummyConsumer(backpressure_threshold=10, backpressure_recovery=3)
    assert consumer.processing_mode is ProcessingMode.FULL
    consumer.update_backpressure(11)
    assert consumer.processing_mode is ProcessingMode.STATISTICAL_ONLY
    consumer.update_backpressure(2)
    assert consumer.processing_mode is ProcessingMode.FULL
    consumer.record_processing(10.0)
    consumer.record_processing(30.0, quarantined=True)
    consumer.record_dead_letter()
    stats = consumer.stats
    assert stats.messages_processed == 2
    assert stats.messages_quarantined == 1
    assert stats.messages_dead_lettered == 1
    assert stats.avg_processing_ms == 20.0
    await consumer.connect()
    consumer.stop()
    assert consumer._running is False


@pytest.mark.asyncio
async def test_redis_message_helpers_with_fake_client():
    client = MagicMock()
    client.xack = MagicMock()
    client.xadd = MagicMock()

    async def xack(*args, **kwargs):
        return 1

    async def xadd(*args, **kwargs):
        return "1-0"

    client.xack.side_effect = xack
    client.xadd.side_effect = xadd

    consumer = RedisConsumer()
    consumer._client = client
    msg = PipelineMessage("1-0", [1.0], source="unit", timestamp="123", metadata={"k": "v"})
    await consumer.acknowledge("1-0")
    await consumer.dead_letter(msg, "bad")
    await consumer.quarantine(msg, 0.9)
    await consumer._dead_letter_raw("2-0", {"x": "y"}, "parse")
    assert client.xack.call_count == 1
    assert client.xadd.call_count == 3

    parsed = RedisConsumer._parse_message(
        "3-0", {"sample_data": "[1, 2]", "source": "redis", "timestamp": "t", "trace": "abc"}
    )
    assert parsed is not None and parsed.metadata == {"trace": "abc"}
    assert RedisConsumer._parse_message("x", {}) is None
    assert RedisConsumer._parse_message("x", {"sample_data": "{"}) is None


def test_kafka_message_parser_paths():
    msg = SimpleNamespace(
        value={"sample_data": [1, 2], "source": "kafka", "timestamp": "t", "trace": 1},
        topic="samples",
        partition=2,
        offset=9,
    )
    parsed = KafkaConsumer._parse_kafka_message(msg)
    assert parsed is not None
    assert parsed.message_id == "samples:2:9"
    assert parsed.metadata == {"trace": 1}

    missing = SimpleNamespace(value={"source": "x"}, topic="t", partition=0, offset=0)
    assert KafkaConsumer._parse_kafka_message(missing) is None
    non_dict = SimpleNamespace(value="bad", topic="t", partition=0, offset=0)
    assert KafkaConsumer._parse_kafka_message(non_dict) is None
    assert KafkaConsumer._parse_kafka_message(object()) is None
