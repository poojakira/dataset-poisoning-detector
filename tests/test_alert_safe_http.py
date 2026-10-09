"""Network-free SSRF regression tests for the alert dispatcher."""

import socket
import ssl
from http.client import BadStatusLine

import pytest

from poison_detector import alerting


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/hook",
        "file:///etc/passwd",
        "https://user:pass@example.com/hook",
        "https://127.0.0.1/hook",
        "https://169.254.169.254/latest/meta-data",
        "https://example.com:8443/hook",
        "https://example.com./hook",
        "https://example.com/hook#fragment",
    ],
)
def test_rejects_untrusted_webhook_url(url):
    with pytest.raises(ValueError):
        alerting._validate_http_url(url)


def test_generic_webhook_requires_explicit_allowlist(monkeypatch):
    monkeypatch.delenv("POISON_ALERT_WEBHOOK_HOSTS", raising=False)
    with pytest.raises(ValueError, match="POISON_ALERT_WEBHOOK_HOSTS"):
        alerting.WebhookChannel("https://example.com/hook")


def test_slack_host_cannot_be_replaced():
    with pytest.raises(ValueError, match="hooks.slack.com"):
        alerting.SlackChannel("https://other.example/hook")


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "192.168.1.1", "10.0.0.2", "169.254.169.254", "::1"],
)
def test_rejects_nonpublic_resolved_addresses(monkeypatch, address):
    def fake_resolver(_host, _port, *, type):
        assert type == socket.SOCK_STREAM
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]

    monkeypatch.setattr(alerting.socket, "getaddrinfo", fake_resolver)
    with pytest.raises(ValueError, match="non-public"):
        alerting._send_alert_json(
            "https://hooks.slack.com/services/fake",
            {"test": "event"},
            allowed_hosts={"hooks.slack.com"},
        )


@pytest.mark.parametrize("status", [204, 302])
def test_public_ip_is_pinned_to_verified_tls_hostname(monkeypatch, status):
    targets = []

    def fake_resolver(_host, _port, *, type):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]

    class FakeRaw:
        def close(self):
            pass

    class FakeTLS:
        minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED

        def wrap_socket(self, raw, *, server_hostname):
            assert self.minimum_version == ssl.TLSVersion.TLSv1_2
            targets.append(("sni", server_hostname))
            return raw

    class FakeResponse:
        def __init__(self):
            self.status = status

        def read(self, _size):
            return b"{}"

    class FakeConnection:
        def __init__(self, host, timeout, context):
            targets.append(("host", host))
            self.sock = None

        def request(self, method, path, body, headers):
            targets.append(("request", (method, path, headers["Content-Type"])))

        def getresponse(self):
            return FakeResponse()

        def close(self):
            pass

    def fake_connect(address, timeout):
        targets.append(("connect", address))
        return FakeRaw()

    monkeypatch.setattr(alerting.socket, "getaddrinfo", fake_resolver)
    monkeypatch.setattr(alerting.socket, "create_connection", fake_connect)
    monkeypatch.setattr(alerting.ssl, "create_default_context", FakeTLS)
    monkeypatch.setattr(alerting, "HTTPSConnection", FakeConnection)
    code = alerting._send_alert_json(
        "https://hooks.slack.com/abcd?x=1",
        {"type": "alert"},
        allowed_hosts={"hooks.slack.com"},
    )
    assert code == status
    assert len([target for target in targets if target[0] == "connect"]) == 1
    assert ("connect", ("8.8.8.8", 443)) in targets
    assert ("sni", "hooks.slack.com") in targets
    assert ("request", ("POST", "/abcd?x=1", "application/json")) in targets


def test_unallowlisted_host_is_rejected_before_dns(monkeypatch):
    def unexpected_dns(*args, **kwargs):
        pytest.fail("unallowlisted destination must not be resolved")

    monkeypatch.setattr(alerting.socket, "getaddrinfo", unexpected_dns)
    with pytest.raises(ValueError, match="allowlisted"):
        alerting._send_alert_json("https://evil.example/hook", {}, allowed_hosts={"example.com"})


def test_mixed_public_private_dns_is_rejected_before_connect(monkeypatch):
    monkeypatch.setattr(
        alerting.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in ["8.8.8.8", "10.0.0.1"]
        ],
    )

    def unexpected_connect(*args, **kwargs):
        pytest.fail("mixed DNS answer must not be connected")

    monkeypatch.setattr(alerting.socket, "create_connection", unexpected_connect)
    with pytest.raises(ValueError, match="non-public"):
        alerting._send_alert_json("https://example.com/hook", {}, allowed_hosts={"example.com"})


@pytest.mark.parametrize(
    "headers",
    [{"Host": "evil.example"}, {"Authorization": "secret\r\nInjected: yes"}],
)
def test_invalid_headers_rejected_before_connect(monkeypatch, headers):
    monkeypatch.setattr(
        alerting.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))],
    )

    def unexpected_connect(*args, **kwargs):
        pytest.fail("invalid headers must not be sent")

    monkeypatch.setattr(alerting.socket, "create_connection", unexpected_connect)
    with pytest.raises(ValueError, match="header"):
        alerting._send_alert_json(
            "https://example.com/hook", {}, allowed_hosts={"example.com"}, headers=headers
        )


@pytest.mark.parametrize("kind", ["slack", "pagerduty", "webhook"])
def test_protocol_errors_fail_closed_without_logging_secrets(monkeypatch, caplog, kind):
    def failed_send(*args, **kwargs):
        raise BadStatusLine("SECRET_TOKEN")

    monkeypatch.setattr(alerting, "_send_alert_json", failed_send)
    monkeypatch.setenv("POISON_ALERT_WEBHOOK_HOSTS", "example.com")
    channels = {
        "slack": alerting.SlackChannel("https://hooks.slack.com/services/mock"),
        "pagerduty": alerting.PagerDutyChannel("fake-key"),
        "webhook": alerting.WebhookChannel("https://example.com/hook"),
    }
    event = alerting.Alert(alerting.AlertType.SYSTEM_ERROR, alerting.AlertSeverity.PAGE, "T", "M")
    assert not channels[kind].send(event)
    assert "SECRET_TOKEN" not in caplog.text
    assert "BadStatusLine" in caplog.text
