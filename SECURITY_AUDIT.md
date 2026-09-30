# Security Audit — dataset-poisoning-detector

**Audit date:** 2026-09-29  
**Scope:** FastAPI service, WebSocket boundary, dataset URL scanning, Redis/rate limiting, request validation, alerts, containers, and CI.

## Findings captured before this remediation pass

| ID | Severity | Finding | Status |
|---|---|---|---|
| DPD-001 | Low | Public scoring failures now return the generic `Scoring failed` response without exception class or traceback details. | Fixed |
| DPD-002 | Low | The unused `traceback` import is no longer present in the API module. | Fixed |
| DPD-003 | Info | Dataset URL scanning resolves only Hugging Face dataset IDs into fixed datasets-server endpoints; arbitrary caller URLs are not fetched. | Verified |

## Existing controls verified

- Fail-closed API-key middleware.
- 32+ character production key requirement.
- Raw request-size checks.
- Redis-backed production rate limiting with fail-closed backend behavior.
- Concurrency and scoring timeouts.
- Pydantic finite-numeric and bounded input validation.
- WebSocket authentication.
- Readiness checks.
- Alerting hook.
- Non-root container.
- Secret-hygiene CI.

## Verification plan

Sanitize remaining 500 responses, run full CI, and re-check the WebSocket/API error surface and alerting behavior.
