# Local remediation verification: 2026-10-09

Base main: `e98bcff7bc252e6334bc6e27bedf3bd57ba21cfb`.
Imported PR 83 head: `ce508e6c2c25d1d22b5c7c9db52c400afbdde238`, followed by
the transport error handling, header validation, regression tests, documentation,
whole-repository lint gates, and helper formatting in this change.

## Results and evidence boundaries

- Python 3.12.14, Linux, fresh isolated dependency environment.
- Entire suite: **226 passed**, 0 skipped, 3 warnings, 9.51 seconds.
- Excluding `tests/test_coverage_boost.py`: **186 passed**, 0 skipped,
  3 warnings, 10.46 seconds. The excluded 40 tests exercise local stub classes,
  not the packaged production modules. They must not inflate a production-test claim.
- Both runs: **2080/2267** package statements executed, **91.7512%** coverage.
- Alert transport and runtime regression subset: **35 passed**, 0.93 seconds.
- Ruff **0.8.4** whole-repository lint and formatting pass.
- Final repeat after adding optional Kafka/AWS dependencies: **226 passed**,
  0 skipped, 3 warnings, 9.76 seconds, with unchanged coverage.
- Declared Pyright **1.1.388**: 0 errors, 0 warnings.
- `python -m build` successfully produced the wheel and source distribution.

An external pytest autouse fixture blocked real IPv4/IPv6 socket connections
through `socket.socket.connect`; test mocks remained enabled. No live alert
delivery, production credentials, deployment edits, or detector-effectiveness
evaluation occurred. This is local test evidence, not remote CI or production
security certification. The warnings comprise one Starlette deprecation and
NumPy empty-slice warnings exercised by a streaming edge-case test.

The transport tests verify HTTPS-only destinations, exact host allowlists,
private and mixed public/private DNS rejection, public-IP pinning with original
TLS hostname and minimum TLS 1.2, no follow-up connection for redirects, forbidden
headers and header newlines, and protocol-error logs that omit secret-bearing
exception text. Body limits and TLS are implementation controls; these tests
do not prove every network attack is prevented.

## Reproduction

```bash
python -m pip install -e ".[dev,realtime,kafka]"
python -m pip install ruff==0.8.4
PYTHONPATH=src python -m pytest tests -q --timeout=120 --cov=poison_detector
PYTHONPATH=src python -m pytest tests -q --timeout=120 \
  --ignore=tests/test_coverage_boost.py --cov=poison_detector
python -m ruff check .
python -m ruff format --check .
```

Local versions included pytest 9.1.1, pytest-asyncio 1.4.0, pytest-timeout 2.4.0,
pytest-cov 7.1.0, numpy 2.5.3, scikit-learn 1.9.1, fastapi 0.143.0, httpx 0.28.1,
redis 8.1.0, pydantic-settings 2.15.0, prometheus-client 0.26.0, and pyyaml 6.0.3.
The first two runs did not install optional Kafka/AWS clients. The final full-suite
repeat added aiokafka 0.14.0 and boto3 1.43.111; their delivery paths still were
not tested against a live service. Exact current remote CI status must be checked
separately after publishing.

Poster artifacts and efficacy numbers remain dated historical snapshots; this
change does not relabel the 2026-10-04 measurements as current detector efficacy.
