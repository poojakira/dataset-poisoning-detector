> **READ [LICENSE](LICENSE) BEFORE COPYING OR CHANGING ANYTHING.** This is an owner-maintained, proprietary repository. **Unsolicited code/documentation contributions are not accepted.** The development instructions below apply **only to people who have received prior written authorization** from Pooja Kiran. Public viewing/forking under GitHub's Terms, applicable law, third-party rights, and prior valid licenses remain unaffected. Any accepted external work requires an agreed written copyright license or assignment; a PR alone does not transfer ownership. For permission contact poojakiranbhardwaj@gmail.com.

# Contributing

Contributions require prior written authorization from the maintainer.

## Before opening a pull request

1. Keep changes scoped and explain the security or engineering reason for them.
2. Add or update tests for behavior changes. Prefer tests that exercise a real failure mode over tests added only to increase a count.
3. Update documentation when a public claim, CLI contract, schema, benchmark, or limitation changes.
4. Do not weaken validation, authentication, or CI checks to make a test pass.

## Local verification

Run:

```bash
python -m pytest tests -q
ruff check src tests
```

If an optional dependency or external service is required, state that explicitly in the pull request.

## Benchmarks and metrics

Do not update a published metric from a README alone. Include the command, environment, commit, dataset/fixture scope, and raw result or CI evidence needed to reproduce it.

## Security-sensitive changes

For parser, authentication, authorization, sandbox, deserialization, policy, or detection changes, include at least one negative/adversarial test that demonstrates the failure mode being fixed.
