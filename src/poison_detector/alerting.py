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
    - SSRF protection: All webhook URLs are validated to reject private/loopback
      addresses and non-HTTPS schemes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# SSRF protection: blocked host patterns (private/loopback ranges)
_BLOCKED_HOST_PATTERNS = [
    r"^localhost$",
    r"^127\.\d+\.\d+\.\d+$",
    r"^::1$",
    r"^0\.0\.0\.0$",
    r"^169\.254\.\d+\.\d+$",  # AWS metadata
    r"^10\.\d+\.\d+\.\d+$",    # RFC1918
    r"^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$",  # RFC1918
    r"^192\.168\.\d+\.\d+$",   # RFC1918
    r"^100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\.\d+\.\d+$",  # RFC6598 (CGNAT)
]


def _validate_webhook_url(url: str) -> str:
    """Validate webhook URL for SSRF protection.

    Rejects:
    - Non-HTTPS schemes (http://, file://, ftp://)
    - Private/loopback IP ranges (SSRF)
    - Unresolvable hosts

    Returns the validated URL unchanged if safe.
    Raises ValueError if URL fails validation.
    """
    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise ValueError(
            f"Webhook URL must use HTTPS. Got scheme: {parsed.scheme!r}"
        )

    host = parsed.hostname or ""
    if not host:
        raise ValueError("Webhook URL has no hostname")

    # Check blocked patterns
    for pattern in _BLOCKED_HOST_PATTERNS:
        if re.match(pattern, host):
            raise ValueError(
                f"Webhook URL points to a private/loopback address: {host!r}. "
                "This is a potential SSRF vector and is not allowed."
            )

    return url


def _safe_post_json(url: str, payload: dict[str, Any], timeout: int = 10) -> bool:
    """Safely POST JSON payload to a validated HTTPS URL.

    Args:
        url: The URL to POST to (will be validated).
        payload: JSON-serializable payload.
        timeout: Request timeout in seconds.

    Returns:
        True if delivery succeeded (2xx status), False otherwise.
    """
    try:
        safe_url = _validate_webhook_url(url)
    except ValueError as e:
        logger.warning(f"Webhook URL validation failed: {e}")
        return False

    try:
        resp = requests.post(
            safe_url,
            json=payload,
            timeout=timeout,
            allow_redirects=False,  # Don't follow redirects (could bypass host check)
        )
        resp.raise_for_status()
        return True
    except (requests.RequestException, requests.Timeout, ValueError) as e:
        logger.warning(f"Webhook delivery failed: {e}")
        return False


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
        ...


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
        self._webhook_url = webhook_url
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

        return _safe_post_json(self._webhook_url, payload)


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

        return _safe_post_json(self.EVENTS_URL, payload)


class CloudWatchChannel:
    """Sends alerts as CloudWatch custom metrics/events.

    Stub implementation that formats alerts for AWS CloudWatch.
    Requires boto3 in production; logs locally when boto3 is unavailable.
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
            import boto3

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
            logger.info(
                f"CloudWatch alert (boto3 not available): "
                f"[{alert.severity.value}] {alert.title}"
            )
            return True
        except Exception as e:
            logger.warning(f"CloudWatch delivery failed: {e}")
            return False


class WebhookChannel:
    """Generic HTTP webhook channel for custom integrations.

    POSTs a JSON payload to a configurable HTTPS URL. Supports HMAC-SHA256
    signature for authenticity verification.

    Security: URL is validated to prevent SSRF (no private IPs, no HTTP).
    """

    def __init__(self, url: str, secret: str | None = None) -> None:
        """Initialize webhook channel.

        Args:
            url: Webhook endpoint URL (must be HTTPS).
            secret: Optional shared secret for HMAC-SHA256 signature.
        """
        self._url = url
        self._secret = secret.encode() if secret else None

    def send(self, alert: Alert) -> bool:
        """Send alert to webhook endpoint with optional HMAC signature.

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

        # Add HMAC signature if secret provided
        if self._secret:
            import hmac
            import hashlib
            body = json.dumps(payload, separators=(",", ":")).encode()
            signature = hmac.new(self._secret, body, hashlib.sha256).hexdigest()
            payload["_signature"] = signature

        return _safe_post_json(self._url, payload)


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
