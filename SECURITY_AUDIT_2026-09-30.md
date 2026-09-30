# Security Audit — 2026-09-30

## Scope
Initial pre-remediation review of the current `main` branch.

## Runtime surface
FastAPI scoring/batch API, authenticated WebSocket stream, Redis production rate limiter, Kafka/Redis integration, dashboard/monitoring assets.

## Verified controls
- API-key authentication fails closed in production.
- Constant-time API-key comparison is used.
- Request body limits and Pydantic numeric validation are present.
- Production rate limiting requires Redis and fails closed on limiter errors.
- WebSocket upgrade requires the API key.
- Production readiness checks baseline state and rate-limit backend.
- Model baseline loading uses `allow_pickle=False`.
- No confirmed live API key was found in the current main branch.

## Findings to remediate/verify
1. Remove any traceback/debug imports or code paths not required in production.
2. Ensure error responses remain generic and do not disclose exception values.
3. Bound WebSocket client count/message size and rate-limit inbound WebSocket messages.
4. Verify broadcast events cannot leak one tenant/source's sensitive sample metadata to unrelated consumers.
5. Validate Redis/Kafka are TLS/authenticated for production and not publicly bound.
6. Verify critical poison-rate/latency/readiness alerts and health-gated rollback.

## Not applicable
Password reset and browser XSS unless a user-account web UI is introduced.
