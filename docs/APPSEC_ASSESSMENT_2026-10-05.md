# White-Box Application Security Assessment — Dataset Poisoning Detector

**Assessment date:** 2026-10-05  
**Scope:** FastAPI/ASGI request boundary, authenticated scoring endpoints, WebSocket stream, readiness behavior, rate limiting, and public error handling.  
**Authorization:** Owner-authorized review of this repository.  
**Claim boundary:** Source-assisted application-security assessment of the repository. Not an independent penetration test and not a production-customer assessment.

## Reviewed surface

- `GET /health`
- `GET /ready`
- `POST /score`
- `POST /batch`
- `GET /stats`
- `GET /metrics`
- `WebSocket /stream`
- startup baseline loading
- API-key authentication
- request-body and feature validation
- rate limiting / Redis production dependency
- scoring concurrency and timeout behavior

## Security controls verified from source and tests

| Area | Result | Evidence |
|---|---|---|
| Missing API key | PASS | Protected HTTP endpoints fail closed when authentication is not configured. |
| Invalid API key | PASS | Constant-time comparison; invalid credentials return an authentication failure. |
| Production key strength | PASS for configured policy | Production readiness requires an adequately long key. |
| Request body size | PASS | ASGI middleware bounds bytes before parsing, including streamed/chunked bodies. |
| Invalid numeric input | PASS | Request validation rejects unsafe/invalid feature values. |
| Baseline readiness | PASS | Scoring fails closed until a known-clean startup baseline is loaded. |
| Error disclosure | PASS for reviewed paths | Validation/scoring/readiness responses avoid echoing raw rejected payloads or private baseline paths. |
| Rate-limit backend | PASS with deployment dependency | Production requires Redis and fails closed if the backend is unavailable. |
| WebSocket authentication | PASS | Upgrade requires authentication and has bounded connections/message size/rate. |
| Tenant authorization | LIMITATION | One shared API key establishes one trust domain; there is no per-tenant resource authorization. |
| WebSocket event isolation | LIMITATION | Authenticated clients share the event stream. |
| TLS | DEPLOYMENT CONTROL | TLS must be provided by ingress/deployment infrastructure. |

## Focused test evidence

Existing tests directly exercise the public security boundary:

- `tests/test_api.py` covers health, scoring, batch behavior, WebSocket behavior, and API-key authentication.
- `tests/test_api_security_hardening.py` covers request-size enforcement, non-disclosure of rejected payloads, and readiness privacy.
- `tests/test_release_coverage_paths.py` covers fail-closed readiness branches.

The current repository verification records **200 passing tests at 91.20% statement coverage**. This assessment does not reinterpret that figure as penetration-test coverage.

## Findings

### APPSEC-DATA-01 — Shared authenticated trust domain
**Severity:** Medium if used for mutually untrusted tenants; otherwise architectural limitation

A shared `API_KEY` authenticates callers into one trust domain. The service does not implement per-tenant identity or per-resource authorization.

**Impact:** One deployment/key should not be shared by mutually untrusted tenants.

**Treatment:** isolate tenants by deployment/key or add tenant-aware identity, routing, and authorization before multi-tenant use.

### APPSEC-DATA-02 — Shared WebSocket event stream
**Severity:** Medium in a multi-tenant deployment

Authenticated WebSocket clients receive the shared detection event stream.

**Impact:** Cross-tenant metadata exposure is possible if mutually untrusted tenants share an instance.

**Treatment:** keep one trust domain per instance or implement tenant-scoped event filtering.

### APPSEC-DATA-03 — TLS is external
**Severity:** Informational

The application assumes transport security is provided at ingress. Local compose assets are explicitly not production-hardened.

**Treatment:** enforce TLS, private service bindings, broker authentication, and network segmentation in production.

### APPSEC-DATA-04 — Stateful scaling requires coordination
**Severity:** Informational

Detector and some rate-limit state are process-local; production rate limiting uses Redis, but multi-replica detector state still requires deliberate distribution/partition ownership.

**Treatment:** ensure each dataset has one authoritative baseline/state owner or externalize/coordinate state before scaling horizontally.

### APPSEC-DATA-05 — Timed-out scoring work can continue
**Severity:** Low / availability consideration

A timed-out thread can continue until completion; the implementation intentionally retains its concurrency slot and returns 503 when capacity is saturated.

**Treatment:** keep bounded concurrency, monitor saturation, and consider process isolation/cancellable workloads if untrusted scoring functions become more expensive.

## Result

The API has strong fail-closed behavior for authentication, trusted-baseline readiness, request sizing, validation, and production rate limiting. The primary residual risk is **tenant isolation**, which the repository correctly documents as out of scope for the current shared-key architecture.

This supports the statement **"performed a white-box AppSec assessment of my own FastAPI ML-security service and documented authentication, request-boundary, readiness, WebSocket, and tenant-isolation risks."**
