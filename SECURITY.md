# Security Policy

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in this
project, please report it responsibly.

### Contact

- **Email**: security@example.com
- **PGP Key**: Available at https://keys.openpgp.org (search for security@example.com)

Please encrypt sensitive vulnerability details using our PGP key.

### Scope

The following are in scope for security reports:

- Authentication and authorization bypass
- Cryptographic weaknesses or implementation flaws
- Injection vulnerabilities (SQL, command, path traversal)
- Data leakage or exposure of sensitive information
- Denial of service vulnerabilities in the detection pipeline
- Supply chain attacks via dependencies
- Container escape or privilege escalation in deployment configurations

### Out of Scope

The following are out of scope:

- Vulnerabilities in third-party dependencies (report to the upstream project)
- Social engineering attacks
- Physical security issues
- Denial of service via volumetric attacks (infrastructure-level concern)
- Issues in example or demo code not intended for production use
- Reports without a clear security impact

### Response Timeline

- **Acknowledgment**: Within 48 hours of receiving your report
- **Initial Assessment**: Within 5 business days
- **Fix Development**: Within 90 days for confirmed vulnerabilities
- **Public Disclosure**: Coordinated with the reporter after a fix is available

### Safe Harbor

We consider security research conducted in good faith to be authorized. We will not
pursue legal action against researchers who:

- Make a good faith effort to avoid privacy violations, data destruction, and
  service disruption
- Only interact with accounts they own or with explicit permission of the account holder
- Do not exploit a vulnerability beyond what is necessary to confirm its existence
- Report vulnerabilities promptly and do not disclose them publicly before a fix is
  available
- Provide sufficient detail for us to reproduce and address the issue

### Recognition

We maintain a security acknowledgments page for researchers who responsibly disclose
vulnerabilities. If you would like to be credited, please let us know in your report.
