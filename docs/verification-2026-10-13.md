# Local verification — 2026-10-13

Status: PARTIALLY COMPLETE. Independent functional review performed by a separate agent; remote CI, Docker, exhaustive file-by-file review, dependency vulnerability scans, and poster regeneration are not established by these local tests.

- Starting revision: `97e2c49f79792352482b7b93137067de22da9e99` plus the remediation diff committed with this record.
- Environment: Linux, Python 3.12.14, pytest 9.1.1, pytest-cov 7.1.0, coverage 7.16.2.
- Local suite: **232 passed, 0 skipped (including 40 legacy stub tests; 192 excluding those)**.
- Statement coverage: **91.7766% (2087/2274)**; not branch coverage.
- Command: `OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m pytest --cov=poison_detector --cov-report=term --cov-report=json`.
- UTC execution date: 2026-10-13. Exact start time was not captured; do not infer it from commit time.
- No production traffic or external paid services were used. No effectiveness benchmark was rerun.

## Remediation

Dataset URL screening now reports ERROR when a requested label column is missing/null or numeric features are nonfinite, instead of producing a misleading clean verdict or propagating a numerical exception. Six new cases exercise those boundaries. Dependabot groups CodeQL action updates so init/analyze versions update together.

## Evidence limitations

Full test logs and coverage JSON were retained in the audit execution workspace. This document records their summary; it does not claim CI passed on this revision. Existing dated benchmark artifacts and posters remain historical snapshots, not current reruns. See [historical runs](../previos_runs.md).
