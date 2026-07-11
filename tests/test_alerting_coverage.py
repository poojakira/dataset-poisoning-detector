"""Coverage tests for the alert dispatch system.

Exercises each delivery channel (Slack, PagerDuty, CloudWatch, generic webhook)
with mocked HTTP, and the dispatcher's deduplication + severity-escalation
logic. HTTP is mocked so no network calls are made.
"""

from contextlib import contextmanager
from unittest.mock import MagicMock, patch

from poison_detector.alerting import (
    Alert,
    AlertDispatcher,
    AlertSeverity,
    AlertType,
    CloudWatchChannel,
    PagerDutyChannel,
    SlackChannel,
    WebhookChannel,
)


@contextmanager
def _mock_urlopen(status=200, raise_exc=None):
    """Patch alerting.urlopen with a fake HTTP response context manager."""
    resp = MagicMock()
    resp.status = status
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    if raise_exc is not None:
        with patch("poison_detector.alerting.urlopen", side_effect=raise_exc) as m:
            yield m
    else:
        with patch("poison_detector.alerting.urlopen", return_value=resp) as m:
            yield m


def _alert(severity=AlertSeverity.WARNING, title="High poison rate"):
    return Alert(
        alert_type=AlertType.POISON_RATE_HIGH,
        severity=severity,
        title=title,
        message="rate 15% exceeds 10%",
        metadata={"rate": 0.15, "threshold": 0.10},
    )


def test_alert_autogenerates_dedup_key():
    """An Alert without an explicit dedup_key derives one from type + title."""
    alert = _alert()
    assert alert.dedup_key == "poison_rate_high:High poison rate"


def test_slack_channel_send_success_and_failure():
    """SlackChannel returns True on HTTP 200 and False when delivery raises."""
    channel = SlackChannel("https://hooks.slack.com/x", channel="#alerts")
    with _mock_urlopen(status=200) as m:
        assert channel.send(_alert()) is True
        m.assert_called_once()

    with _mock_urlopen(raise_exc=OSError("boom")):
        assert channel.send(_alert()) is False


def test_pagerduty_channel_send():
    """PagerDutyChannel posts a trigger event and reports success on 2xx."""
    channel = PagerDutyChannel("routing-key-123")
    with _mock_urlopen(status=202):
        assert channel.send(_alert(AlertSeverity.CRITICAL)) is True

    with _mock_urlopen(raise_exc=ValueError("bad")):
        assert channel.send(_alert(AlertSeverity.PAGE)) is False


def test_cloudwatch_channel_without_boto3_logs_and_succeeds():
    """CloudWatchChannel degrades gracefully to logging when boto3 is absent."""
    channel = CloudWatchChannel(namespace="Test", region="us-west-2")
    # boto3 is not installed in this environment -> ImportError branch -> True
    assert channel.send(_alert()) is True


def test_webhook_channel_send():
    """WebhookChannel posts JSON and honors custom headers."""
    channel = WebhookChannel("https://example.com/hook", headers={"Authorization": "Bearer x"})
    with _mock_urlopen(status=200):
        assert channel.send(_alert()) is True

    with _mock_urlopen(raise_exc=OSError("down")):
        assert channel.send(_alert()) is False


class _RecordingChannel:
    """Test channel that records every alert it receives."""

    def __init__(self, succeed=True):
        self.sent = []
        self._succeed = succeed

    def send(self, alert):
        self.sent.append(alert)
        return self._succeed


def test_dispatcher_deduplicates_within_cooldown():
    """A repeated alert within the cooldown window is suppressed."""
    channel = _RecordingChannel()
    dispatcher = AlertDispatcher(cooldown_seconds=300, escalation_window=900)
    dispatcher.add_channel(channel)
    assert dispatcher.channel_count == 1

    assert dispatcher.dispatch(_alert()) is True  # first send
    assert dispatcher.dispatch(_alert()) is False  # suppressed by dedup
    assert len(channel.sent) == 1


def test_dispatcher_escalates_persistent_alerts():
    """Sustained alerts escalate WARNING -> CRITICAL -> PAGE over time."""
    channel = _RecordingChannel()
    dispatcher = AlertDispatcher(cooldown_seconds=0, escalation_window=1)
    dispatcher.add_channel(channel)

    dispatcher.dispatch(_alert(AlertSeverity.WARNING))
    key = _alert().dedup_key

    # Force the "first seen" far into the past so escalation logic engages.
    dispatcher._dedup_state[key].first_seen -= 5  # > 2 * escalation_window
    dispatcher.dispatch(_alert(AlertSeverity.WARNING))

    last = channel.sent[-1]
    assert last.severity == AlertSeverity.PAGE
    assert "ESCALATED" in last.title
    assert last.metadata["escalated_from"] == "warning"


def test_dispatcher_escalates_to_critical():
    """A moderately persistent alert escalates to CRITICAL (not yet PAGE)."""
    channel = _RecordingChannel()
    dispatcher = AlertDispatcher(cooldown_seconds=0, escalation_window=10)
    dispatcher.add_channel(channel)

    dispatcher.dispatch(_alert(AlertSeverity.WARNING))
    key = _alert().dedup_key
    # 15s since first: between escalation_window (10) and 2x (20) -> CRITICAL
    dispatcher._dedup_state[key].first_seen -= 15
    dispatcher.dispatch(_alert(AlertSeverity.WARNING))
    assert channel.sent[-1].severity == AlertSeverity.CRITICAL


def test_dispatcher_channel_exception_is_isolated():
    """A channel raising during send does not prevent other channels or crash."""
    bad = MagicMock()
    bad.send.side_effect = RuntimeError("channel down")
    good = _RecordingChannel()
    dispatcher = AlertDispatcher(cooldown_seconds=0)
    dispatcher.add_channel(bad)
    dispatcher.add_channel(good)

    result = dispatcher.dispatch(_alert())
    assert result is True  # good channel succeeded
    assert len(good.sent) == 1


def test_dispatcher_no_channels_reports_sent():
    """With no channels configured, dispatch reports True (nothing to fail)."""
    dispatcher = AlertDispatcher(cooldown_seconds=0)
    assert dispatcher.dispatch(_alert()) is True


def test_dispatcher_recent_alerts_and_clear_state():
    """get_recent_alerts returns newest-first; clear_dedup_state resets dedup."""
    channel = _RecordingChannel()
    dispatcher = AlertDispatcher(cooldown_seconds=300)
    dispatcher.add_channel(channel)

    dispatcher.dispatch(_alert(title="A"))
    dispatcher.dispatch(_alert(title="B"))
    recent = dispatcher.get_recent_alerts(limit=10)
    assert [a.title for a in recent][:2] == ["B", "A"]

    # Same "A" is suppressed until dedup state cleared
    assert dispatcher.dispatch(_alert(title="A")) is False
    dispatcher.clear_dedup_state()
    assert dispatcher.dispatch(_alert(title="A")) is True


def test_alert_severity_level_ordering():
    """AlertSeverity.level provides a monotonic ordering for escalation."""
    assert AlertSeverity.INFO.level < AlertSeverity.WARNING.level
    assert AlertSeverity.WARNING.level < AlertSeverity.CRITICAL.level
    assert AlertSeverity.CRITICAL.level < AlertSeverity.PAGE.level
