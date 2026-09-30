# Security review, 2026-09-30

Reviewed checkout: `b91a6d8415385eab90b0830af275eebede8f16e6`.

## Implemented controls

- Actual ASGI request bytes are bounded before parsing, including authenticated requests without Content-Length or with chunked transfer encoding. Existing declared-size checks remain.
- Batch feature values reject NaN and infinity before scoring. Invalid request responses do not echo rejected feature vectors or metadata.
- Invalid API keys share a peer rate-limit bucket, preventing attacker-selected header values from creating unlimited buckets. The development limiter bounds the number of retained identities and cleans stale entries. Production continues to require Redis and fails closed on backend failure.
- Scoring timeouts retain worker capacity until the thread exits; saturated service capacity returns 503. A response timeout does not terminate the underlying thread.
- Public readiness failures no longer expose the baseline's filesystem path or parser exception text. Existing public health telemetry remains intentional; limit probe access at ingress if operational counts are sensitive.
- Production WebSocket access applies the same minimum key length as HTTP. Constant-time comparisons use encoded bytes and tolerate non-ASCII input without raising a server error.
- Dataset URL fetching limits HTTPS requests and redirects to `datasets-server.huggingface.co` on port 443, bounds each response to 10 MiB, and bounds requested samples to 1–1000. Failed/incomplete scans now return verdict `ERROR`, rather than `clean`.

## Authentication is separate from authorization

A shared `API_KEY` authenticates into a single trust domain. All authenticated callers can score and read operational endpoints; WebSocket events are shared across connected callers. There is no tenant identity or per-resource policy. Do not share an instance/key across mutually untrusted tenants; deploy separate detectors and baselines, or implement tenant-aware routing and policy before doing so. A deployment must also enforce transport-level WebSocket frame limits, connection timeouts, and TLS at ingress.

## Files and secrets

There is no HTTP file-upload route. Startup baseline artifacts are operator-selected NPZ files loaded with `allow_pickle=False`; they should be provisioned from trusted storage, with ownership and filesystem permissions enforced by the deployment. The baseline loader is not an untrusted upload sandbox and does not enforce a compressed-archive expansion budget.

The coordinator's full reachable Git-history Gitleaks scan found six generic matches, all in formerly committed NumPy test fixtures under `.venv-test/`. They are SHA-256 values for PRNG test state, not provider API credentials. Historical path inspection found no project `.env`, private-key containers, or credential filenames outside virtual environments. Neither scan proves every credential absent or covers unreachable objects and external artifacts; no live credential revocation was performed. Local `.env` and `*.env` files are ignored; reviewed placeholder examples may remain tracked.

## Validation and remaining work

`OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 python -m pytest -q`: **162 passed**. Three warnings: one TestClient deprecation and two existing NumPy empty-feature warnings. New tests cover actual body budgets, finite batch input, validation redaction, readiness path suppression, trusted dataset origins, row budgets, incomplete verdicts, and worker capacity after timeout.

Live Redis/Kafka deployments, shared limiter performance, baseline archive expansion limits, tenant authorization, and exhaustive review of all algorithm/library behavior remain unverified. This review fixes specific defects and does not certify that all possible security issues are resolved.

## Installed dependency advisory check

The combined isolated environment containing both projects and their service/development extras was checked with `pip-audit --format json`. The report lists 70 dependencies and zero known vulnerabilities; the two local editable project packages were skipped because they are not PyPI packages. This verifies the resolved installed versions at audit time, not every version allowed by dependency ranges, future advisories, or undeployed lockfiles. No paid provider APIs were used.
