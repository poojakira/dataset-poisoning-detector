# Contributing

Contributions should preserve the repository's evidence-first standard.

1. Create a focused branch and keep unrelated changes separate.
2. Add or update tests for behavior changes.
3. Run `ruff check src/poison_detector tests`, `ruff format --check src/poison_detector tests`, `pyright src/poison_detector tests`, and `pytest tests/`.
4. If a change affects a public number, regenerate the corresponding benchmark artifact and update its methodology/limitations in the same pull request.
5. Do not add performance, detection-rate, or production-readiness claims based on synthetic fixtures without clearly stating the scope.

Security-sensitive findings should follow [SECURITY.md](SECURITY.md) rather than being disclosed in a public issue before remediation is available.
