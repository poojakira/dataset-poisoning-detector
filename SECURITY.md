# Security Policy

## Scope

Input validation, API/streaming behavior, quarantine/storage paths, benchmark integrity, and detector failure modes are in scope. This project is a screening layer, not a complete poisoning defense.

This is an open-source production-oriented security system. Security claims remain limited to behavior demonstrated by the repository, its CI, and committed evidence; production orientation does not imply third-party certification or a deployment history that is not evidenced here.

## Reporting a vulnerability

Please do not publish exploit details in a public issue before the maintainer has had a reasonable opportunity to review them.

Send a concise report to the maintainer contact listed on https://github.com/poojakira with:
- affected version/commit;
- reproduction steps;
- impact and preconditions;
- suggested mitigation, if known.

## Supported versions

Only the current default branch is actively maintained unless a release explicitly states otherwise.

## Disclosure

After a fix is available, a public issue or advisory may document the affected scope, remediation, and any claim changes required by the finding.

<!-- credential-response:start -->
## Credential and secret handling

- Real API keys, tokens, passwords, private keys, cloud credentials, and populated environment files must never be committed.
- Local users must create their own `.env` from the repository's safe template when environment variables are needed, and must supply **their own** credentials. CI/CD credentials belong in GitHub repository/environment secrets or an external secret manager, not in source or workflow YAML.
- If a real credential is exposed, treat it as compromised even if the commit is quickly deleted. **Revoke or rotate the credential at its provider first.** Then remove it from the current tree, reachable Git history, logs/artifacts, examples, screenshots, and documentation as applicable.
- Rewriting Git history or deleting a file does **not** revoke a credential. Provider-side rotation/revocation is required.
- Placeholder/test credentials must be clearly marked and must not be valid for real services.
<!-- credential-response:end -->
