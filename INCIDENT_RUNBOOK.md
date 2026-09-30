# Incident Runbook — Dataset Poisoning Detector

This runbook covers only behavior implemented in the current repository. It is a research/portfolio project, not an operated production service: there is no on-call rotation, pager, SLA, or managed deployment behind these instructions.

## Implemented operational surfaces

The FastAPI service currently exposes:

- `GET /health` — unauthenticated process health
- `GET /ready` — unauthenticated readiness; requires a valid startup baseline
- `POST /score` — authenticated single-sample scoring
- `POST /batch` — authenticated batch scoring
- `GET /stats` — authenticated detector statistics
- `GET /metrics` — authenticated Prometheus output
- `WS /stream` — authenticated WebSocket stream

Protected endpoints require `X-API-Key`. There is **no** runtime `/config`, alert-pause, drift-reset/suppress, quarantine-management, or bulk-review API in the current code.

## Local demo prerequisites

Copy the environment template and provide your own values:

```bash
cp .env.example .env
```

At minimum, set a strong local `API_KEY` and `GRAFANA_ADMIN_PASSWORD`. Never commit `.env`.

Start the checked-in demo stack:

```bash
docker compose config
docker compose up -d --build
docker compose ps
```

The API is exposed on `http://127.0.0.1:8000`.

## 1. API process is unhealthy

Check the process and recent logs:

```bash
curl -fsS http://127.0.0.1:8000/health
docker compose ps api
docker compose logs --since=10m api
```

If the container is stopped or crash-looping, inspect the logs before restarting:

```bash
docker compose restart api
docker compose logs --since=5m api
```

Do not treat a successful `/health` response as proof that scoring is ready.

## 2. Readiness fails

Readiness depends on a known-clean startup baseline. Check:

```bash
curl -i http://127.0.0.1:8000/ready
```

If readiness reports a baseline problem, configure `POISON_BASELINE_PATH` to an immutable NPZ artifact containing a numeric 2D array named `features`. The service rejects pickled object arrays and invalid/non-finite baselines.

After changing the baseline configuration, rebuild/restart the API and re-check `/ready`.

## 3. Protected requests return 401/503/429

Verify the local key is set in your shell and matches the key supplied to Compose:

```bash
export API_KEY="<your-own-strong-api-key>"
curl -i -H "X-API-Key: $API_KEY" http://127.0.0.1:8000/stats
```

A 401 means the key is absent or invalid. In production mode, an insecurely short key causes the service to fail closed. A 429 means the configured rate limit was exceeded.

Check metrics with authentication:

```bash
curl -fsS -H "X-API-Key: $API_KEY" http://127.0.0.1:8000/metrics
```

Do not place API keys in command history, screenshots, tickets, or committed files in a real deployment; prefer your environment/secret manager.

## 4. Scoring looks abnormal or drift is reported

Inspect detector state:

```bash
curl -fsS -H "X-API-Key: $API_KEY" http://127.0.0.1:8000/stats
```

The current API does not implement a remote threshold-change or drift-reset endpoint. If tuning is required, change the checked-in/configured detector settings through the supported configuration path, review the change, run tests, and restart the service. Do not use undocumented `POST /config` or `/drift/*` commands.

For a controlled smoke test after `/ready` succeeds:

```bash
curl -fsS -X POST \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  http://127.0.0.1:8000/score \
  -d '{"features":[0.1,0.2,0.3],"source":"runbook-smoke-test"}'
```

Use a feature vector compatible with the configured baseline dimension.

## 5. Redis or demo dependencies fail

The checked-in Compose stack includes Redis, Kafka, Prometheus, and Grafana for local evaluation. Check container state first:

```bash
docker compose ps
docker compose logs --since=10m redis
docker compose logs --since=10m kafka
docker compose logs --since=10m prometheus
docker compose logs --since=10m grafana
```

For Redis connectivity from the host:

```bash
redis-cli -h 127.0.0.1 -p 6379 ping
```

The current FastAPI service does not expose Kafka consumer-lag, quarantine-database, alert-pause, or retention-management endpoints. Any such operational procedures must be added only when corresponding implementation exists.

## Recovery validation

After any change or restart:

```bash
curl -fsS http://127.0.0.1:8000/health
curl -i http://127.0.0.1:8000/ready
curl -fsS -H "X-API-Key: $API_KEY" http://127.0.0.1:8000/stats
```

Then run the repository test suite before promoting a code/configuration change:

```bash
python -m pytest tests -q
```

Document the exact commit, configuration change, observed error, and validation evidence for any real incident.
