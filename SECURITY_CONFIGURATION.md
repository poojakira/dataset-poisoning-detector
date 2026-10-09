# Security configuration

## WebSocket authentication

The current `/stream` implementation requires `X-API-Key` during the WebSocket
upgrade. Missing or invalid credentials are rejected with WebSocket policy
close code `1008` before the connection is added to the broadcast manager.

This means detection events are not intentionally exposed anonymously by the
current implementation.

## Deployment limitation

Rate limiting is in-memory and per process. A multi-replica deployment needs a
shared rate-limit store or an upstream distributed control.

The service also broadcasts detection events to every authenticated connected
client. It does not currently implement per-client or per-tenant event
filtering, so authenticated clients should still be treated as sharing the
same event stream.

## AlertDispatcher webhook destinations

`SlackChannel` permits only `https://hooks.slack.com` and `PagerDutyChannel`
permits only `https://events.pagerduty.com`. Generic `WebhookChannel` requires
an exact hostname in the operator-controlled, comma-separated
`POISON_ALERT_WEBHOOK_HOSTS` environment variable. An empty variable disables
all custom webhook destinations.

Each delivery requires HTTPS on port 443, rejects URL credentials and literal
IP destinations, and rejects the entire DNS result if any address is non-public.
The connection uses the validated IP with certificate verification and TLS SNI
for the original hostname, with TLS 1.2 or later. Redirects are not followed,
including redirects to another approved host, so credentials cannot be forwarded
to a redirect target. Request and response bodies are limited to 64 KiB.

This policy intentionally replaces arbitrary HTTP and trusted private-network
webhooks. An internal DNS name resolving to private IP space fails closed even
if explicitly listed. If internal delivery is required, use a separately reviewed
queue-backed channel or an approved public HTTPS integration; do not bypass the
IP checks. Configuration remains trusted operator input; this is defense against
misconfiguration and DNS changes, not proof of universal SSRF resistance or
guaranteed delivery.
