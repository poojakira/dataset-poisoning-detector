# Security Model

## Overview

The Dataset Poisoning Detector implements defense-in-depth with multiple security layers:
authentication, authorization, encryption, audit logging, input validation, and rate limiting.
This document describes each layer, its guarantees, and its known limitations.

---

## Authentication Mechanisms

### mTLS (Mutual TLS) -- Service-to-Service

Used for service-to-service communication within the internal network (e.g., ML pipelines
calling the scoring API).

| Property | Value |
|----------|-------|
| Protocol | TLS 1.3 with mutual authentication |
| Certificate Authority | Internal PKI (dedicated CA) |
| Identity extraction | Subject CN or Subject Alternative Name (SAN) |
| Revocation | Not implemented (rely on short-lived certs) |
| Validation | Chain verification, expiry check, CN/SAN allowlist |

**Trust model**: The internal CA is the root of trust. Only certificates signed by this CA
are accepted. A compromised CA would allow forged client certificates; use a dedicated CA
separate from the public TLS certificate chain.

**Limitations**:
- No CRL/OCSP revocation checking. Revoked certificates remain valid until expiry.
- For high-security environments, use short-lived certificates (24h) via cert-manager with auto-renewal.

### JWT RS256 -- User and Service Identity

Used for user-facing authentication and cross-service identity propagation.

| Property | Value |
|----------|-------|
| Algorithm | RS256 (RSA 2048-bit minimum, 4096-bit recommended) |
| Token lifetime | 5-15 minutes (short-lived) |
| Refresh mechanism | Refresh token rotation (external IdP) |
| Claims validated | iss, aud, exp, sub, roles, jti |
| Symmetric algorithms | Explicitly rejected (HS256/HS384/HS512 blocked) |
| Revocation | **Supported (v1.1.0)** — `jti`-based TTL-bounded denylist |

**Trust model**: The identity provider holds the private key. This service only has the
public key and can validate tokens but cannot issue them. Compromise of the public key
does not allow token forgery.

**Revocation (v1.1.0)**: `auth.TokenDenylist` + `JWTAuthenticator.revoke(jti, exp)`
add revocation on top of stateless validation. When a token's `jti` is on the
denylist, a signature-valid token is denied; entries are TTL-bounded (only kept
until the token would expire anyway). Supply a `jti` claim in issued tokens for
this to apply.

**Limitations**:
- The denylist is in-memory and per-process. For multi-replica deployments, back
  it with a shared store (Redis) so a revocation on one replica is honored by all;
  short token lifetimes (5-15 minutes) bound the exposure in the meantime.
- Tokens minted without a `jti` claim cannot be individually revoked.
- No JWKS endpoint rotation support (public key is configured at deployment).

### API Keys -- Programmatic Access

Used for automated pipelines and third-party integrations.

| Property | Value |
|----------|-------|
| Key entropy | 32 bytes (256 bits), generated via CSPRNG |
| Storage | bcrypt hash (work factor 12) |
| Rotation | Configurable (default 90 days), with overlap period |
| Scoping | Per-key roles and permissions |
| Rate limiting | Per-key rate limiting buckets |

**Trust model**: API keys are bearer tokens. Possession implies authentication. Keys are
stored as bcrypt hashes; compromise of the hash store does not reveal original keys.

**Limitations**:
- No key hierarchy or key families.
- Rotation requires coordination (both old and new keys valid during overlap).
- Keys do not expire by default (configurable via expiry_days).

---

## Authorization: RBAC Matrix

The system enforces Role-Based Access Control with a static permission matrix.
All decisions follow a default-deny policy.

### Role Definitions

| Role | Description | Use Case |
|------|-------------|----------|
| `admin` | Full system access | System administrators, SRE team |
| `analyst` | Investigation and remediation | Security analysts, data scientists |
| `readonly` | View-only access | Monitoring dashboards, reporting tools |
| `service` | Scoring capabilities only | Automated ML pipelines, data ingestion |

### Permission Matrix

| Permission | admin | analyst | readonly | service |
|-----------|:-----:|:-------:|:--------:|:-------:|
| `score` | Yes | Yes | No | Yes |
| `batch_score` | Yes | Yes | No | Yes |
| `view_quarantine` | Yes | Yes | Yes | No |
| `resolve_quarantine` | Yes | Yes | No | No |
| `modify_config` | Yes | No | No | No |
| `view_audit` | Yes | No | No | No |
| `export_data` | Yes | Yes | Yes | No |

### Role Resolution Priority

1. JWT claims (`roles` field) take precedence
2. Local role assignment (programmatic via RBACEnforcer)
3. Custom per-identity permission overrides (use sparingly)
4. Default: deny

### Enforcement Points

- API middleware checks permissions before routing to handlers
- All denials are logged at WARNING level for security monitoring
- Role names are case-sensitive enums to prevent typo-based escalation

---

## Encryption

### At Rest

| Data | Algorithm | Key Management |
|------|-----------|---------------|
| Quarantined samples | AES-256-GCM | Envelope encryption via KMS |
| Audit log entries | Integrity only (hash chain) | N/A |
| Database records | AES-256 (RDS/Cloud SQL native) | AWS KMS / Cloud KMS |
| S3 audit archives | AES-256 (SSE-S3 or SSE-KMS) | AWS KMS |

**Envelope Encryption Pattern**:
1. Master key resides in KMS (AWS KMS, Cloud KMS, Azure Key Vault)
2. A unique data encryption key (DEK) is generated per record
3. DEK encrypts the data (AES-256-GCM with random 12-byte nonce)
4. Master key encrypts the DEK
5. Encrypted DEK is stored alongside the ciphertext

**Nonce safety**: AES-256-GCM nonces are 12 bytes from os.urandom (CSPRNG). Safe for up to
2^32 encryptions per key. Key rotation is recommended before this limit.

### In Transit

| Connection | Protocol | Minimum Version |
|-----------|----------|----------------|
| Client to API | TLS | 1.3 |
| Service to Service | mTLS | 1.3 |
| API to Redis | TLS | 1.2 |
| API to PostgreSQL | TLS | 1.2 |
| API to S3 | HTTPS (TLS 1.2+) | 1.2 |

**Cipher suites**: Only AEAD cipher suites are permitted (GCM, ChaCha20-Poly1305).
CBC-mode ciphers are disabled.

---

## Audit Logging

### What Is Logged

| Event Type | Fields Recorded |
|-----------|----------------|
| Authentication attempt | method, decision, identity, client_ip, resource, timestamp |
| Detection decision | event_type, user_id, sample_id, sample_hash, score, decision |
| Configuration change | user_id, old_value (hashed), new_value (hashed), timestamp |
| Quarantine action | sample_id, action (quarantine/release), user_id, reason |
| Export operation | user_id, time_range, format, record_count |

### What Is NOT Logged

- Raw sample data (prevents data leakage via audit log access)
- Full API keys or JWT tokens (only key_id or subject claim)
- Passwords or cryptographic key material

### Retention

| Tier | Duration | Storage | Access |
|------|----------|---------|--------|
| Hot | 30 days | Local filesystem / EBS | Immediate query |
| Warm | 1 year | S3 Standard | Minutes to retrieve |
| Cold | 7 years (SOC2/ISO27001) | S3 Glacier | Hours to retrieve |

### Tamper Detection

- SHA-256 hash chain links each entry to its predecessor
- Any modification, deletion, or reordering breaks the chain
- `verify_integrity()` performs full chain traversal and recomputation
- Genesis entry uses well-known previous hash (64 zero characters)
- File locking (fcntl) serializes concurrent writers

---

## Input Validation

### Sanitization Rules

| Check | Rejection Criteria | Rationale |
|-------|-------------------|-----------|
| Dimension bounds | features.length > 100,000 | Prevent OOM in numpy/sklearn |
| Dimension bounds | features.length < 1 | Invalid input |
| NaN detection | Any feature is NaN | sklearn crashes on NaN |
| Infinity detection | Any feature is +/- Inf | Overflow in Welford accumulator |
| Value range | abs(feature) > 1e15 | Float64 precision degradation |
| Batch size | batch.samples.length > 1000 | Prevent request timeout |
| Source length | source.length > 256 | Prevent log injection |
| Metadata size | metadata > 4096 bytes | Prevent payload bloat |

### Rate Limiting Headers

Responses include rate limit information:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests per window |
| `X-RateLimit-Remaining` | Remaining requests in current window |
| `X-RateLimit-Reset` | Unix timestamp when the window resets |
| `Retry-After` | Seconds to wait (only on 429 responses) |

---

## Compliance Mapping

### SOC2 Trust Service Criteria

| TSC | Requirement | Implementation |
|-----|-------------|----------------|
| CC1.1 | COSO Principle 1: Demonstrates commitment to integrity | Code review policy, security-focused docstrings, threat model documentation |
| CC5.1 | Logical access security | JWT RS256 + mTLS + API key authentication |
| CC5.2 | Access control over system boundaries | Network policies, VPC isolation, ingress rules |
| CC5.3 | Registration and authorization | RBAC with 4 roles, 7 permissions, default-deny |
| CC6.1 | Logical access controls | Permission matrix enforcement at API boundary |
| CC6.2 | Access credentials | bcrypt-hashed API keys, RS256 JWT (no symmetric), 90-day rotation |
| CC6.3 | Access removal | Key revocation API, role revocation, immediate effect |
| CC6.6 | Encryption | AES-256-GCM at rest, TLS 1.3 in transit, KMS envelope encryption |
| CC6.7 | Data transmission protection | mTLS for service-to-service, TLS 1.3 for external |
| CC7.1 | Detection of anomalies | The system IS the anomaly detection system |
| CC7.2 | Monitoring activities | Prometheus metrics, Grafana dashboards, PagerDuty alerts |
| CC7.3 | Evaluation of events | Automated scoring + human analyst workflow for quarantined samples |
| CC7.4 | Incident response | Severity-based escalation (P1-P4), runbooks, communication templates |
| CC8.1 | Change management | Git-based deployment, Terraform IaC, immutable containers |
| CC9.1 | Risk mitigation | Circuit breaker, rate limiting, input sanitization, defense-in-depth |
| A1.1 | Availability commitments | 99.95% SLO, HPA (3-20 replicas), multi-AZ, PDB |
| A1.2 | Environmental protections | Kubernetes resource limits, network policies, pod security |

### ISO 27001 Annex A Controls

| Control | Requirement | Implementation |
|---------|-------------|----------------|
| A.5.15 | Access control | RBAC with principle of least privilege |
| A.5.17 | Authentication information | bcrypt hashed keys, RS256 JWT, mTLS certs |
| A.5.23 | Information security for cloud services | AWS security groups, KMS, IAM roles |
| A.5.33 | Protection of records | Append-only audit log with hash chain, 7-year retention |
| A.5.34 | Privacy and PII protection | No raw sample data in logs, RBAC on quarantine access |
| A.8.1 | User endpoint devices | Not applicable (server-side system) |
| A.8.3 | Information access restriction | RBAC permission matrix, network policies |
| A.8.5 | Secure authentication | mTLS + JWT RS256 + API keys with rotation |
| A.8.9 | Configuration management | Terraform IaC, Kubernetes ConfigMaps, environment variables |
| A.8.10 | Information deletion | S3 lifecycle policies, configurable retention periods |
| A.8.12 | Data leakage prevention | No raw data in responses, audit log sanitization, RBAC |
| A.8.15 | Logging | Tamper-evident audit trail, structured JSON Lines format |
| A.8.16 | Monitoring activities | Prometheus + Grafana + PagerDuty alerting |
| A.8.20 | Networks security | VPC isolation, network policies, mTLS, TLS 1.3 |
| A.8.24 | Use of cryptography | AES-256-GCM, SHA-256, RSA-2048+, CSPRNG nonces |
| A.8.25 | Secure development lifecycle | Threat model, security tests, input validation |
| A.8.26 | Application security requirements | Input sanitization, Pydantic validation, RBAC enforcement |
| A.8.28 | Secure coding | No eval/exec, parameterized queries, type hints, security docstrings |
| A.8.31 | Separation of environments | Namespace isolation, separate Terraform workspaces per environment |
| A.8.32 | Change management | Terraform plan/apply, kubectl rollout, rollback procedures |
| A.8.33 | Test information | Separate test fixtures, no production data in tests |

---

## Security Controls Summary

```
+------------------------------------------------------------------+
|                    Defense-in-Depth Layers                        |
+------------------------------------------------------------------+
| Layer 1: Network        | VPC, Security Groups, Network Policies |
| Layer 2: Transport      | TLS 1.3, mTLS                          |
| Layer 3: Authentication | JWT RS256, API Keys, mTLS Certs        |
| Layer 4: Authorization  | RBAC (4 roles, 7 permissions)          |
| Layer 5: Input Valid.   | Sanitization, bounds, NaN/Inf checks   |
| Layer 6: Rate Limiting  | Per-key sliding window (Redis-backed)  |
| Layer 7: Circuit Break  | Graceful degradation on failure        |
| Layer 8: Encryption     | AES-256-GCM at rest, TLS in transit    |
| Layer 9: Audit          | Hash-chained append-only log           |
| Layer 10: Monitoring    | Prometheus, Grafana, PagerDuty         |
+------------------------------------------------------------------+
```
