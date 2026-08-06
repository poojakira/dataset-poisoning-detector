# Security Audit — dataset-poisoning-detector

Audit performed by: automated security-hardening agent  
Date: 2026-08-06  
Branch: agent/security-hardening-v1

---

## 1. Hardcoded Absolute Paths

### What was found

| File | Line | Hardcoded Path | Status |
|------|------|----------------|--------|
| `scripts/eval_detector.py` | 177–179 | `r"C:\Users\pooja\eval_artifacts\dataset-poisoning-detector"` — output directory in `main()` | **Fixed** |
| `scripts/eval_detector.py` | 224 | `PROVENANCE` — bare name reference to an undefined variable (was a module-level constant that had been removed from `make_labelflip_cifar.py`) | **Fixed** |

### What was already clean

- `scripts/make_labelflip_cifar.py` — `get_cifar_dir()` reads from the `CIFAR_DIR` environment variable; raises `FileNotFoundError` with a clear message if unset. No hardcoded path.
- All other `.py` files — no hardcoded absolute paths found by `Select-String -Pattern 'C:[/\\]|/home/|/Users/'`.

### Changes made

#### `scripts/eval_detector.py`

`main()` now accepts CLI arguments via `argparse`:

| Argument | Default | Description |
|----------|---------|-------------|
| `--cifar-dir` | `None` → `CIFAR_DIR` env var | Path to the `cifar-10-batches-py` directory |
| `--output-dir` | `./eval_artifacts/<timestamp>` | Where to write `report.json` and `RESULTS.md` |

The `PROVENANCE` reference was replaced with a call to the existing `build_provenance(cifar_dir)` function, which populates `local_dir` from the resolved CLI argument at runtime.

**Verification:** `Select-String -Pattern 'C:[/\\]|/home/|/Users/|pooja'` across all `*.py` files returns zero matches.

---

## 2. API Authentication

### Before this change

`src/poison_detector/api.py` contained a `rate_limit_middleware` that extracted `X-API-Key` for **rate-limit bucketing only**. The middleware docstring explicitly stated:

> "The X-API-Key header is used for rate-limit bucketing only, not for authentication."

Any request — with or without a key — was served. There was no 401 path.

### After this change

A dedicated `api_key_auth_middleware` is registered **before** the rate-limit middleware. It enforces the following:

| Condition | Response |
|-----------|----------|
| `API_KEY` env var not set | HTTP 401 — fail-closed, no implicit open access |
| `X-API-Key` header absent | HTTP 401 |
| `X-API-Key` header present but wrong | HTTP 401 |
| `X-API-Key` matches `os.environ["API_KEY"]` | Request proceeds |
| Path is `/health`, `/stats`, or `/metrics` | Auth skipped (monitoring endpoints) |

Security properties:
- Key is never hardcoded — **must** be supplied via `API_KEY` environment variable.
- Key is compared using `hmac.compare_digest` to prevent timing side-channel attacks.
- Key is never logged or echoed in response bodies.
- Service starts fail-closed: if `API_KEY` is not set, all protected endpoints return 401.

### Test coverage

`tests/test_api.py` was updated with three new tests:

- `test_score_returns_401_when_no_api_key` — verifies 401 when header is absent.
- `test_score_returns_401_when_wrong_api_key` — verifies 401 when header is present but wrong.
- `test_health_does_not_require_api_key` — verifies `/health` returns 200 without a key.

Existing functional tests were updated to supply `X-API-Key: test-secret` (via `monkeypatch.setenv` + module reload) so they still pass.

---

## 3. Benchmark Performance — Honest Record

The following are the actual measured benchmark numbers. They are reproduced here verbatim for auditability. **Do not substitute higher numbers without re-running `scripts/eval_detector.py` and committing the new artifact.**

| Benchmark | Value | Notes |
|-----------|-------|-------|
| ROC-AUC (CIFAR-10 label-flip, flip_rate 0.05–0.25) | **~0.53–0.56** | Near-chance baseline. Only modestly above random (0.50). |
| Detection methodology | Per-class `StreamingDetector`, PCA-50 features | Label-flip only; clean-label attacks not in scope |
| False-positive rate at 5% target FPR | ~5% on clean samples | Expected — calibrated at that threshold |
| Throughput | 12,400 samples/sec | Single-threaded, 10-dim features, microbenchmark |
| Latency p50 | 0.08 ms | Steady-state |
| Latency p99 | 0.31 ms | During IsoForest refit |

**Important:** ROC-AUC of 0.53–0.56 means the detector performs only marginally better than random guessing. This is a **research baseline**, not a production-grade detector. Do not deploy without significant improvement to the detection algorithm.

Any claim of "zero false positives" or AUC above 0.60 from this tool without a committed evidence artifact is a reporting error. Run `scripts/eval_detector.py --cifar-dir <path>` to reproduce.

---

## 4. Hardcoded Credentials

**None found.**

- No API keys, passwords, tokens, or secrets are hardcoded in any Python file.
- Alert channel credentials (Slack webhook URL, PagerDuty routing key) are loaded from `pydantic-settings` via `POISON_ALERT_*` environment variables with empty string defaults — no real values committed.
- The `API_KEY` check in `api.py` reads exclusively from `os.environ["API_KEY"]`; there is no hardcoded fallback.

---

## 5. CI / Workflow Hardening

File: `.github/workflows/ci.yml`

### Current state

- Top-level `permissions: contents: read, security-events: write, actions: read` is already set.
- Actions are tag-pinned (`@v4`, `@v5`, `@v3`). **Tags are mutable.** For supply-chain hardening, pin to immutable commit SHAs.
- Individual jobs (`lint`, `test`) did not have explicit `permissions` blocks before this change — they inherited the top-level permissive set. Explicit per-job minimums reduce blast radius.

### Changes made

- Added `permissions: contents: read` blocks to the `lint` and `test` jobs.
- Pinned all `actions/checkout`, `actions/setup-python`, `actions/upload-artifact`, and `github/codeql-action/*` steps to their immutable commit SHAs (as of 2026-08-06).

---

## 6. Summary of All Files Changed

| File | Change |
|------|--------|
| `scripts/eval_detector.py` | Remove hardcoded output path; add `--cifar-dir`/`--output-dir` argparse; replace bare `PROVENANCE` with `build_provenance(cifar_dir)` call |
| `src/poison_detector/api.py` | Add `api_key_auth_middleware` (HTTP 401 on missing/wrong `X-API-Key`); import `os` at top; update module docstring; update rate-limit middleware docstring |
| `tests/test_api.py` | Add three 401 auth tests; update functional tests to supply API key via `monkeypatch` |
| `.github/workflows/ci.yml` | Add per-job `permissions` blocks; pin action SHAs |
| `SECURITY_AUDIT.md` | This file — authoritative security findings record |
| `evidence_policy.json` | New — honest metrics and provenance record for CI evidence |
