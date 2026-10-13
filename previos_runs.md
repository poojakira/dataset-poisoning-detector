# Historical runs

The following sections were moved verbatim from the starting README during the 2026-10-13 audit. Confidence: partially verified as committed documentation; underlying run logs were not independently recovered. Missing commands, environments, dates or commits remain unknown unless included in each entry. None is a current execution claim.

## Verified Snapshot

Local remediation verification on Python 3.12.14 on 2026-10-09, based on main `e98bcff7bc252e6334bc6e27bedf3bd57ba21cfb` plus PR 83 and the follow-up fixes. This is not a claim that the new branch has passed remote CI. Legacy stub-only tests are excluded from the production-facing count; see [commands and limitations](docs/verification-2026-10-09.md). Label-flip F1 is transcribed from the committed `results/spectral_benchmark.json` and was not rerun during this verification.

| Metric | Dated verified result |
|---|---:|
| Production-facing tests | 186 passing, 0 skipped (226 including 40 legacy stub tests) |
| Statement coverage | 91.7512% (2080/2267 statements; CI gate 90%) |
| Detection methods | z-score, IQR, Isolation Forest, ensemble, spectral top-1, cross-class centroid, streaming |
| Cross-class label-flip F1 | 0.55 / 0.60 / 0.70 @ 5% / 10% / 20% poison |
| Feature-space ensemble (CIFAR-10 raw pixels) | AUC ~0.53–0.56 (near-random — documented limitation) |


## Verification update — 2026-09-30

- **Scope:** Account-wide `poojakira` repository pass covering source/configuration, CI/release workflows, security-hygiene gates, dependency/SAST controls, and documentation consistency.
- **Remediation:** Pinned the PyPI publish action to an immutable commit and rechecked the repository security posture without weakening API-key, rate-limit, or validation controls.
- **Verification state:** The latest completed core CI, Production Gate, Security Hygiene, and Documentation Integrity checks were green before the release-workflow pin; the pin itself is repository-only hardening.
- **Security note:** Production rate limiting and authentication remain fail-closed as documented; no synthetic benchmark result is presented as production efficacy.
- **Evidence boundary:** This update records repository and GitHub Actions evidence observed during the pass. It is not a claim of independent penetration testing, production deployment, or zero residual risk.
<!-- repo-verification:end -->


## Verification checkpoint — 2026-09-30

- **Checked snapshot:** `7e1efe303174d67cf7b82368d151d8a7f421743b`
- **Status:** VERIFIED GREEN
- **Evidence:** CI, Production Gate, Security Hygiene, and Documentation Integrity completed successfully for the cited checked snapshot.
- This record is immutable and date-bounded. Later `main` commits may be newer; consult GitHub Actions for the latest run state. It does not claim zero vulnerabilities or universal production readiness.
