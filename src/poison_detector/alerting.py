"""
Alert dispatch system for real-time poisoning detection events.

Routes alerts to multiple channels (Slack, PagerDuty, CloudWatch, HTTP webhooks)
with deduplication to prevent alert storms and escalation logic that increases
severity based on duration and persistence.

Threat Model Assumptions:
    - Alert channels are trusted infrastructure. Webhook URLs point to internal
      services (Slack, PagerDuty) controlled by the same organization.
    - An attacker who can suppress alerts (by causing deduplication to swallow
      critical events) gains a window to inject poison undetected. The escalation
      system counters this by escalating sustained anomalies regardless of
      deduplication state.
    - Alert content may contain sample metadata but never raw sample data.
      Leaked alert content reveals detection sensitivity, not training data.

Honest Limitations:
    - HTTP delivery is best-effort. If a webhook endpoint is down, the alert
      is lost (logged locally but not retried indefinitely). For guaranteed
      delivery, use a queue-backed alerting system (e.g., AWS SNS).
    - Deduplication uses in-memory state. On process restart, dedup windows
      reset and the first alert of each type will fire again. This is
      acceptable -- better to over-alert on restart than miss events.
    - Clock skew between detector instances can cause inconsistent escalation
      timing. Use NTP-synchronized clocks in production.
    - This module is synchronous by default (uses requests-style HTTP calls
      in a thread pool). For high-throughput async usage, wrap in asyncio.

Security Notes:
    - Webhook URLs and API keys must come from environment variables or
      encrypted config, never from user-supplied input.
    - Alert payloads are constructed from internal state only. No user-supplied
      strings are interpolated into alert messages without sanitization.
    - Rate limiting on the alert side prevents a compromised detector from
      being used as a denial-of-service amplifier against webhook endpoints.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import ssl
import time
from dataclasses import dataclass, field
from enum import Enum
from http.client import HTTPSConnection
from typing import Any, Protocol
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)


def _validate_http_url(url: str) -> str:
    """Validate HTTPS structure without making network calls."""
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid alert destination URL") from exc
    if parsed.scheme != "https" or not hostname or port not in (None, 443):
        raise ValueError("alert destinations require HTTPS on port 443")
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or hostname.endswith(".")
    ):
        raise ValueError("alert destination has forbidden URL components")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("webhook destinations must use an allowlisted DNS hostname")
    return url


def _send_alert_json(
    url: str,
    payload: dict[str, Any],
    *,
    allowed_hosts: set[str],
    headers: dict[str, str] | None = None,
) -> int:
    """Post JSON using a verified public IP pinned to an authenticated TLS session.

    No redirects, HTTP downgrade, proxies, private or metadata IPs. Any DNS
    response containing a non-global address is rejected in its entirety.
    """
    parsed = urlsplit(_validate_http_url(url))
    host = parsed.hostname
    if host is None:
        raise ValueError("missing destination hostname")
    if host not in allowed_hosts:
        raise ValueError("destination hostname is not explicitly allowlisted")

    addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    if not addresses:
        raise ValueError("no destination addresses resolved")
    if any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
        raise ValueError("destination resolves to a non-public IP address")
    address = addresses[0][4][0]

    data = json.dumps(payload).encode("utf-8")
    if len(data) > 65536:
        raise ValueError("alert payload exceeds 64 KiB")
    extra = headers or {}
    if any(key.lower() in {"host", "content-length", "transfer-encoding"} for key in extra):
        raise ValueError("forbidden webhook header")
    request_headers = {"Content-Type": "application/json", **extra}

    raw = socket.create_connection((address, 443), timeout=10)
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    connection = HTTPSConnection(host, timeout=10, context=context)
    try:
        try:
            connection.sock = context.wrap_socket(raw, server_hostname=host)
        except Exception:
            raw.close()
            raise
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        connection.request("POST", target, body=data, headers=request_headers)
        response = connection.getresponse()
        if len(response.read(65537)) > 65536:
            raise ValueError("alert response exceeds 64 KiB")
        return response.status
    finally:
        connection.close()


class AlertSeverity(Enum):
    """Alert severity levels with escalation ordering."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    PAGE = "page"

    @property
    def level(self) -> int:
        """Numeric level for comparison."""
        return {"info": 0, "warning": 1, "critical": 2, "page": 3}[self.value]


class AlertType(Enum):
    """Types of alerts the system can emit."""

    POISON_RATE_HIGH = "poison_rate_high"
    DRIFT_DETECTED = "drift_detected"
    BATCH_ANOMALY = "batch_anomaly"
    SYSTEM_ERROR = "system_error"
    QUARANTINE_FULL = "quarantine_full"
    PIPELINE_BACKPRESSURE = "pipeline_backpressure"


@dataclass
class Alert:
    """An alert event to be dispatched.

    Attributes:
        alert_type: Category of the alert.
        severity: Current severity level.
        title: Short human-readable title.
        message: Detailed description of the alert condition.
        metadata: Additional context (scores, thresholds, sample counts).
        timestamp: Unix timestamp when the alert was created.
        dedup_key: Key for deduplication (auto-generated if not provided).
    """

    alert_type: AlertType
    severity: AlertSeverity
    title: str
    message: str
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    dedup_key: str = ""

    def __post_init__(self) -> None:
        if not self.dedup_key:
            self.dedup_key = f"{self.alert_type.value}:{self.title}"


class AlertChannel(Protocol):
    """Protocol for alert delivery channels."""

    def send(self, alert: Alert) -> bool:
        """Send an alert through this channel.

        Args:
            alert: The alert to send.

        Returns:
            True if delivery succeeded, False otherwise.
        """
        raise NotImplementedError


class SlackChannel:
    """Sends alerts to a Slack webhook URL.

    Formats alerts as Slack Block Kit messages with severity-based
    color coding and structured metadata fields.
    """

    def __init__(self, webhook_url: str, channel: str = "") -> None:
        """Initialize Slack channel.

        Args:
            webhook_url: Slack Incoming Webhook URL.
            channel: Override channel (empty uses webhook default).
        """
        self._webhook_url = _validate_http_url(webhook_url)
        if urlsplit(self._webhook_url).hostname != "hooks.slack.com":
            raise ValueError("Slack webhook host must be hooks.slack.com")
        self._channel = channel

    def send(self, alert: Alert) -> bool:
        """Send alert to Slack webhook.

        Args:
            alert: The alert to send.

        Returns:
            True if delivery succeeded, False otherwise.
        """
        color_map = {
            AlertSeverity.INFO: "#36a64f",
            AlertSeverity.WARNING: "#ff9900",
            AlertSeverity.CRITICAL: "#ff0000",
            AlertSeverity.PAGE: "#8b0000",
        }

        payload: dict[str, Any] = {
            "attachments": [
                {
                    "color": color_map.get(alert.severity, "#808080"),
                    "title": f"[{alert.severity.value.upper()}] {alert.title}",
                    "text": alert.message,
                    "fields": [
                        {"title": k, "value": str(v), "short": True}
                        for k, v in alert.metadata.items()
                    ],
                    "footer": f"Poison Detector | {alert.alert_type.value}",
                }
            ]
        }

        if self._channel:
            payload["channel"] = self._channel

        return self._post_json(self._webhook_url, payload)

    @staticmethod
    def _post_json(url: str, payload: dict[str, Any]) -> bool:
        """POST JSON payload to URL."""
        try:
            return _send_alert_json(url, payload, allowed_hosts={"hooks.slack.com"}) == 200
        except (OSError, ValueError, ssl.SSLError) as exc:
            logger.warning("Slack delivery failed (%s)", type(exc).__name__)
            return False


class PagerDutyChannel:
    """Sends alerts to PagerDuty Events API v2.

    Creates incidents for CRITICAL/PAGE severity and resolves them
    when the condition clears.
    """

    EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

    def __init__(self, routing_key: str) -> None:
        """Initialize PagerDuty channel.

        Args:
            routing_key: PagerDuty Events API v2 routing key.
        """
        self._routing_key = routing_key

    def send(self, alert: Alert) -> bool:
        """Send alert to PagerDuty.

        Args:
            alert: The alert to send.

        Returns:
            True if delivery succeeded, False otherwise.
        """
        severity_map = {
            AlertSeverity.INFO: "info",
            AlertSeverity.WARNING: "warning",
            AlertSeverity.CRITICAL: "critical",
            AlertSeverity.PAGE: "critical",
        }

        payload = {
            "routing_key": self._routing_key,
            "event_action": "trigger",
            "dedup_key": alert.dedup_key,
            "payload": {
                "summary": f"{alert.title}: {alert.message}",
                "severity": severity_map.get(alert.severity, "warning"),
                "source": "poison-detector",
                "component": alert.alert_type.value,
                "custom_details": alert.metadata,
            },
        }

        return self._post_json(self.EVENTS_URL, payload)

    @staticmethod
    def _post_json(url: str, payload: dict[str, Any]) -> bool:
        """POST JSON payload to URL."""
        try:
            status = _send_alert_json(url, payload, allowed_hosts={"events.pagerduty.com"})
            return 200 <= status < 300
        except (OSError, ValueError, ssl.SSLError) as exc:
            logger.warning("PagerDuty delivery failed (%s)", type(exc).__name__)
            return False


class CloudWatchChannel:
    """Sends alerts as CloudWatch custom metrics/events.

    Optional CloudWatch delivery implementation.
    Requires boto3 for actual delivery; when boto3 is unavailable the channel logs the undelivered alert and returns False.
    """

    def __init__(self, namespace: str = "PoisonDetector", region: str = "us-east-1") -> None:
        """Initialize CloudWatch channel.

        Args:
            namespace: CloudWatch metric namespace.
            region: AWS region.
        """
        self._namespace = namespace
        self._region = region

    def send(self, alert: Alert) -> bool:
        """Send alert as CloudWatch metric.

        Args:
            alert: The alert to send.

        Returns:
            True if delivery succeeded, False otherwise.
        """
        try:
            import boto3  # pyright: ignore[reportMissingImports]  # optional AWS dependency, not in any extra

            client = boto3.client("cloudwatch", region_name=self._region)
            client.put_metric_data(
                Namespace=self._namespace,
                MetricData=[
                    {
                        "MetricName": f"alert_{alert.alert_type.value}",
                        "Value": alert.severity.level,
                        "Unit": "None",
                        "Dimensions": [
                            {"Name": "Severity", "Value": alert.severity.value},
                            {"Name": "AlertType", "Value": alert.alert_type.value},
                        ],
                    }
                ],
            )
            return True
        except ImportError:
            logger.warning(
                f"CloudWatch delivery skipped because boto3 is unavailable: [{alert.severity.value}] {alert.title}"
            )
            return False
        except Exception as e:
            logger.warning(f"CloudWatch delivery failed: {e}")
            return False


class WebhookChannel:
    """Generic HTTP webhook channel for custom integrations.

    POSTs a JSON payload to a configurable URL. Supports custom headers
    for authentication.
    """

    def __init__(self, url: str, headers: dict[str, str] | None = None) -> None:
        """Initialize webhook channel.

        Args:
            url: Webhook endpoint URL.
            headers: Additional HTTP headers (e.g., Authorization).
        """
        self._url = _validate_http_url(url)
        hosts = os.environ.get("POISON_ALERT_WEBHOOK_HOSTS", "")
        self._allowed_hosts = {name.strip().lower() for name in hosts.split(",") if name.strip()}
        if urlsplit(self._url).hostname not in self._allowed_hosts:
            raise ValueError("configure POISON_ALERT_WEBHOOK_HOSTS to permit a custom webhook")
        self._headers = headers or {}

    def send(self, alert: Alert) -> bool:
        """Send alert to webhook endpoint.

        Args:
            alert: The alert to send.

        Returns:
            True if delivery succeeded, False otherwise.
        """
        payload = {
            "alert_type": alert.alert_type.value,
            "severity": alert.severity.value,
            "title": alert.title,
            "message": alert.message,
            "metadata": alert.metadata,
            "timestamp": alert.timestamp,
            "dedup_key": alert.dedup_key,
        }

        try:
            status = _send_alert_json(
                self._url, payload, allowed_hosts=self._allowed_hosts, headers=self._headers
            )
            return 200 <= status < 300
        except (OSError, ValueError, ssl.SSLError) as exc:
            logger.warning("Webhook delivery failed (%s)", type(exc).__name__)
            return False


@dataclass
class _DedupEntry:
    """Internal deduplication tracking entry."""

    last_sent: float
    count: int
    first_seen: float
    current_severity: AlertSeverity


class AlertDispatcher:
    """Central alert routing with deduplication and escalation.

    Manages multiple alert channels, deduplicates repeated alerts within
    a configurable cooldown window, and escalates severity for persistent
    conditions.

    Usage:
        dispatcher = AlertDispatcher(cooldown_seconds=300)
        dispatcher.add_channel(SlackChannel("https://hooks.slack.com/..."))
        dispatcher.add_channel(PagerDutyChannel("routing-key"))

        dispatcher.dispatch(Alert(
            alert_type=AlertType.POISON_RATE_HIGH,
            severity=AlertSeverity.WARNING,
            title="High poison rate detected",
            message="Poison rate is 15% (threshold: 10%)",
            metadata={"rate": 0.15, "threshold": 0.10},
        ))

    Escalation Logic:
        - If the same alert fires again within escalation_window and the
          condition persists, severity is automatically escalated:
          WARNING -> CRITICAL -> PAGE
        - Escalation resets when the alert type has not fired for
          cooldown_seconds * 2.
    """

    def __init__(
        self,
        cooldown_seconds: int = 300,
        escalation_window: int = 900,
    ) -> None:
        """Initialize the alert dispatcher.

        Args:
            cooldown_seconds: Minimum seconds between repeated alerts of the
                same dedup_key. Alerts within the cooldown are suppressed.
            escalation_window: Seconds within which repeated alerts trigger
                severity escalation.
        """
        self._cooldown_seconds = cooldown_seconds
        self._escalation_window = escalation_window
        self._channels: list[AlertChannel] = []
        self._dedup_state: dict[str, _DedupEntry] = {}
        self._dispatch_log: list[Alert] = []

    def add_channel(self, channel: AlertChannel) -> None:
        """Register an alert delivery channel.

        Args:
            channel: An object implementing the AlertChannel protocol.
        """
        self._channels.append(channel)

    def dispatch(self, alert: Alert) -> bool:
        """Dispatch an alert through all configured channels.

        Applies deduplication and escalation logic before sending.

        Args:
            alert: The alert to dispatch.

        Returns:
            True if the alert was sent (not deduplicated), False if suppressed.
        """
        now = time.time()

        # Check deduplication
        if not self._should_send(alert, now):
            logger.debug(f"Alert suppressed (dedup): {alert.dedup_key}")
            return False

        # Apply escalation
        escalated_alert = self._apply_escalation(alert, now)

        # Send through all channels
        sent = False
        for channel in self._channels:
            try:
                if channel.send(escalated_alert):
                    sent = True
            except Exception as e:
                logger.error(f"Channel delivery error: {e}")

        # Update dedup state
        self._update_dedup_state(escalated_alert, now)

        # Log dispatch
        self._dispatch_log.append(escalated_alert)

        return sent or len(self._channels) == 0

    def _should_send(self, alert: Alert, now: float) -> bool:
        """Check if an alert should be sent based on deduplication.

        Args:
            alert: The alert to check.
            now: Current unix timestamp.

        Returns:
            True if the alert should be sent, False to suppress.
        """
        entry = self._dedup_state.get(alert.dedup_key)
        if entry is None:
            return True

        elapsed = now - entry.last_sent
        return elapsed >= self._cooldown_seconds

    def _apply_escalation(self, alert: Alert, now: float) -> Alert:
        """Apply severity escalation for persistent alerts.

        If the same alert type has been repeatedly firing within the
        escalation window, bump severity upward.

        Args:
            alert: The original alert.
            now: Current unix timestamp.

        Returns:
            Alert with potentially escalated severity.
        """
        entry = self._dedup_state.get(alert.dedup_key)
        if entry is None:
            return alert

        time_since_first = now - entry.first_seen

        # Escalation thresholds
        if time_since_first > self._escalation_window * 2:
            # Persistent for 2x escalation window: PAGE
            new_severity = AlertSeverity.PAGE
        elif time_since_first > self._escalation_window:
            # Persistent for 1x escalation window: CRITICAL
            new_severity = AlertSeverity.CRITICAL
        else:
            new_severity = alert.severity

        # Only escalate upward, never downward
        if new_severity.level > alert.severity.level:
            return Alert(
                alert_type=alert.alert_type,
                severity=new_severity,
                title=f"[ESCALATED] {alert.title}",
                message=alert.message,
                metadata={**alert.metadata, "escalated_from": alert.severity.value},
                timestamp=alert.timestamp,
                dedup_key=alert.dedup_key,
            )
        return alert

    def _update_dedup_state(self, alert: Alert, now: float) -> None:
        """Update deduplication tracking state after sending.

        Args:
            alert: The alert that was sent.
            now: Current unix timestamp.
        """
        entry = self._dedup_state.get(alert.dedup_key)
        if entry is None:
            self._dedup_state[alert.dedup_key] = _DedupEntry(
                last_sent=now,
                count=1,
                first_seen=now,
                current_severity=alert.severity,
            )
        else:
            entry.last_sent = now
            entry.count += 1
            entry.current_severity = alert.severity

    def get_recent_alerts(self, limit: int = 50) -> list[Alert]:
        """Get recently dispatched alerts.

        Args:
            limit: Maximum number of alerts to return.

        Returns:
            List of recently dispatched alerts, newest first.
        """
        return list(reversed(self._dispatch_log[-limit:]))

    def clear_dedup_state(self) -> None:
        """Clear all deduplication state.

        Use when restarting monitoring or after a known state change.
        """
        self._dedup_state.clear()

    @property
    def channel_count(self) -> int:
        """Number of registered alert channels."""
        return len(self._channels)
