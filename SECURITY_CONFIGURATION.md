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
