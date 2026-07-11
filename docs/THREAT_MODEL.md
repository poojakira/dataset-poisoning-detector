# Threat Model (STRIDE)

## Overview

This document applies the STRIDE threat modeling framework to the Dataset Poisoning
Detector itself. While the system detects poisoning in training data, the system itself
is a target for attackers who want to:

1. Evade detection (get poisoned samples past the detector)
2. Disable detection (take the system offline)
3. Corrupt detection (manipulate the detector's baseline)
4. Exfiltrate data (steal training samples or model parameters)
5. Gain unauthorized access (bypass authentication and authorization)

---

## System Boundary Diagram

```
+===========================================================================+
|                          TRUST BOUNDARY                                     |
|                                                                            |
|  External (Untrusted)        |  Internal (Partially Trusted)              |
|                              |                                             |
|  +-------------------+       |  +-----------------------------------+      |
|  | ML Pipeline       |       |  |  Poison Detector Service          |      |
|  | (Data Source)     +------>|  |                                   |      |
|  +-------------------+  API  |  |  +--------+  +-----------+       |      |
|                              |  |  | Auth   |  | Sanitizer |       |      |
|  +-------------------+       |  |  +--------+  +-----------+       |      |
|  | Analyst           |       |  |                                   |      |
|  | (Human User)      +------>|  |  +--------+  +-----------+       |      |
|  +-------------------+  JWT  |  |  | RBAC   |  | Detector  |       |      |
|                              |  |  +--------+  +-----------+       |      |
|  +-------------------+       |  |                                   |      |
|  | External Attacker |       |  |  +--------+  +-----------+       |      |
|  | (Threat Actor)    +--X--->|  |  | Audit  |  | Quarantine|       |      |
|  +-------------------+       |  |  +--------+  +-----------+       |      |
|                              |  +-----------------------------------+      |
|                              |                                             |
|                              |  +-----------------------------------+      |
|                              |  |  Data Stores                       |     |
|                              |  |  +-------+ +-------+ +---------+  |     |
|                              |  |  | Redis | | RDS   | | S3      |  |     |
|                              |  |  +-------+ +-------+ +---------+  |     |
|                              |  +-----------------------------------+      |
+===========================================================================+
```

**Trust Levels**:
- **Untrusted**: External clients, ML pipelines (sample data is untrusted)
- **Partially Trusted**: Internal services with valid mTLS certs (trusted identity, untrusted data)
- **Trusted**: KMS, identity provider signing keys, CA certificates

---

## S - Spoofing (Identity)

### Threat S1: Authentication Bypass

**Attack**: An attacker bypasses authentication to access scoring or admin endpoints
without valid credentials.

**Attack Vectors**:
- JWT token forgery (using HS256 algorithm confusion)
- API key brute force
- mTLS certificate forgery (compromised CA)
- Replay attacks with stolen tokens

**Mitigations**:
| Mitigation | Implementation |
|-----------|----------------|
| Algorithm restriction | RS256 only; HS256/HS384/HS512 explicitly rejected |
| Key entropy | API keys: 32 bytes (256 bits) from CSPRNG |
| Rate limiting on auth failures | 5 failures per client triggers lockout with exponential backoff |
| Short token lifetime | JWT expiry: 5-15 minutes |
| Certificate validation | Chain verification + CN/SAN allowlist + expiry check |

**Residual Risk**: A compromised identity provider private key allows forged JWTs. Mitigated
by regular key rotation and monitoring of the IdP.

### Threat S2: API Key Theft

**Attack**: An attacker steals a valid API key through log exposure, network interception,
or code repository scanning.

**Mitigations**:
| Mitigation | Implementation |
|-----------|----------------|
| TLS everywhere | All API communication over TLS 1.3 |
| No keys in logs | Only key_id logged, never the raw key |
| Key rotation | 90-day rotation schedule with overlap period |
| Key revocation | Immediate revocation API for compromised keys |
| Scoped permissions | Per-key role assignment limits blast radius |

---

## T - Tampering (Data Integrity)

### Threat T1: Audit Log Modification

**Attack**: An attacker with filesystem access modifies or deletes audit entries to
cover their tracks after a breach.

**Attack Vectors**:
- Direct file modification (requires filesystem access)
- Log truncation (delete recent entries)
- Entry insertion (add fake entries to confuse investigation)

**Mitigations**:
| Mitigation | Implementation |
|-----------|----------------|
| Hash chain | SHA-256 chain links each entry to predecessor |
| Integrity verification | verify_integrity() detects any modification |
| Remote shipping | Logs replicated to immutable remote storage (S3 Object Lock) |
| File permissions | 0600 (owner read/write only) |
| File locking | fcntl advisory locks prevent concurrent corruption |
| Append-only FS | Linux chattr +a attribute prevents modification/deletion |

**Residual Risk**: An attacker who can delete the entire log file and recreate it with a
valid new chain from genesis. Mitigated by remote log shipping and integrity checks
against the remote copy.

### Threat T2: Baseline Poisoning ("Boiling Frog")

**Attack**: An attacker slowly shifts the detector's baseline by sending many borderline
samples that pass detection but gradually move the statistical center, eventually making
overtly poisoned samples appear normal.

**Attack Vectors**:
- Slow drift injection (samples just below threshold)
- Window filling (fill the rolling window with subtly shifted data)
- Welford accumulator manipulation (shift mean/variance gradually)

**Mitigations**:
| Mitigation | Implementation |
|-----------|----------------|
| Clean-only updates | Only non-flagged samples update Welford stats and window |
| Concept drift detection | ADWIN + Page-Hinkley monitor for distribution shifts |
| Periodic baseline refresh | Manual refresh from known-clean data warehouse |
| IsolationForest refit interval | Periodic refit limits exposure to window contamination |
| Input sanitization | Value range bounds prevent extreme outliers from corrupting stats |

**Residual Risk**: Samples that are adversarial but within detection bounds will update
the baseline. This is a fundamental limitation of any adaptive detector. Mitigated by
combining automated detection with periodic human review of the baseline distribution.

### Threat T3: Configuration Tampering

**Attack**: An attacker modifies detection thresholds to make the detector blind to
poisoned samples (e.g., setting vote_threshold to 99).

**Mitigations**:
| Mitigation | Implementation |
|-----------|----------------|
| RBAC restriction | Only admin role can modify_config |
| Audit logging | All config changes logged with user_id and old/new values |
| Immutable containers | Config is baked at deploy time, not runtime-mutable |
| GitOps workflow | Changes require PR review and CI/CD pipeline |

---

## R - Repudiation (Non-repudiation)

### Threat R1: Unlogged Actions

**Attack**: An attacker performs actions that are not recorded in the audit trail,
making forensic investigation impossible.

**Attack Vectors**:
- Direct database access bypassing the application layer
- Exploiting code paths that skip audit logging
- Clock manipulation to create timestamp gaps

**Mitigations**:
| Mitigation | Implementation |
|-----------|----------------|
| Comprehensive audit | Every detection decision, auth event, and config change logged |
| Database audit | RDS audit logging enabled at the database level |
| Network policies | Only the application can access data stores (no direct DB access) |
| UTC timestamps | All timestamps in UTC ISO 8601 (immune to timezone manipulation) |
| Entry IDs | UUID4 per entry prevents gap injection |
| Hash chain | Missing entries break the chain and are immediately detectable |

**Residual Risk**: Actions taken during the window between log file rotation and upload
to remote storage could be lost if the local disk fails. Mitigated by flush_on_write
with fsync and short upload intervals.

### Threat R2: Identity Ambiguity

**Attack**: Actions are attributed to generic identities (e.g., "service-account")
making it impossible to determine which specific service or user performed an action.

**Mitigations**:
| Mitigation | Implementation |
|-----------|----------------|
| Unique service accounts | Each pipeline/service has its own API key or certificate |
| JWT subject claims | User actions attributed to specific user identities |
| Client IP logging | Source IP recorded alongside identity |
| Metadata tracking | Request source and batch_id recorded for traceability |

---

## I - Information Disclosure (Confidentiality)

### Threat I1: Sample Data Leakage

**Attack**: An attacker gains access to training sample data through the detector system
(the detector sees all training data flowing through it).

**Attack Vectors**:
- Querying quarantine store without authorization
- Extracting samples from error messages or logs
- Memory dump of the running process (contains rolling window)
- Intercepting WebSocket broadcasts (contain score but not sample data)

**Mitigations**:
| Mitigation | Implementation |
|-----------|----------------|
| RBAC on quarantine | view_quarantine permission required |
| No raw data in responses | API responses return scores, never sample features |
| No raw data in logs | Only metadata logged (dimensions, source, not values) |
| Encryption at rest | Quarantined samples encrypted with AES-256-GCM |
| Memory limits | Pod resource limits prevent excessive data accumulation |
| Network policies | Only authorized pods can access data stores |

**Residual Risk**: An attacker with pod exec access can dump process memory and extract
the rolling window. Mitigated by pod security policies preventing exec and host
namespace access.

### Threat I2: Model Inversion

**Attack**: An attacker queries the scoring API many times with crafted inputs to
reconstruct the baseline distribution or decision boundaries.

**Attack Vectors**:
- Binary search on thresholds (find exact boundary)
- Statistical reconstruction of mean/variance from z-scores
- IsolationForest decision boundary mapping

**Mitigations**:
| Mitigation | Implementation |
|-----------|----------------|
| Rate limiting | 100 requests/minute per key limits query volume |
| Score quantization | Scores returned as float (not full precision) |
| No threshold exposure | Exact thresholds not revealed in responses |
| Audit trail | Unusual query patterns detectable in logs |

**Residual Risk**: A patient attacker within rate limits can eventually map the decision
boundary. This is acceptable because knowing the boundary does not help them modify
the boundary; it only helps them craft samples that evade detection. Defense: periodic
baseline refresh changes the boundary.

### Threat I3: Side-Channel Timing

**Attack**: An attacker measures response timing to infer whether a sample triggered
the IsolationForest path (slower) or was rejected by statistics alone (faster).

**Mitigations**:
| Mitigation | Implementation |
|-----------|----------------|
| Constant-time aspiration | latency_ms is returned in response (not hidden) |
| Combined scoring | Both methods always run when available |
| Noise addition | Natural variance in network latency masks scoring differences |

**Residual Risk**: Accepted. The latency difference between paths (1-5ms) is below
network noise for remote clients.

---

## D - Denial of Service (Availability)

### Threat D1: Flood Attack

**Attack**: An attacker sends a large volume of requests to overwhelm the detector,
causing legitimate samples to be dropped or delayed.

**Attack Vectors**:
- HTTP request flooding (high volume of /score requests)
- Large batch requests (1000 samples per request)
- WebSocket connection exhaustion
- Slowloris-style connection holding

**Mitigations**:
| Mitigation | Implementation |
|-----------|----------------|
| Rate limiting | Per-key sliding window (100 req/min default) |
| Distributed rate limiting | Redis-backed for multi-replica enforcement |
| Batch size limits | Maximum 1000 samples per batch request |
| Connection limits | Ingress controller connection limits |
| HPA auto-scaling | Scales from 3 to 20 replicas on load |
| Resource limits | Pod CPU/memory limits prevent single-pod resource exhaustion |
| Network policies | Only authorized sources can reach the service |

### Threat D2: Resource Exhaustion

**Attack**: An attacker crafts inputs that consume disproportionate resources
(CPU, memory, disk) relative to request size.

**Attack Vectors**:
- High-dimensional samples (100,000 features) consuming memory in numpy/sklearn
- Triggering frequent IsolationForest refits via specific sample patterns
- Filling quarantine storage to exhaust disk
- Redis memory exhaustion via rate limit key proliferation

**Mitigations**:
| Mitigation | Implementation |
|-----------|----------------|
| Dimension limits | InputSanitizer rejects >100,000 features |
| Value bounds | Feature values bounded to prevent accumulator overflow |
| Circuit breaker | Opens on repeated failures, prevents retry storms |
| Disk monitoring | Alert on quarantine storage growth |
| Redis maxmemory | Redis configured with LRU eviction policy |
| PDB | Pod Disruption Budget ensures minimum 2 pods always available |

### Threat D3: Dependency Failure Cascade

**Attack**: An attacker targets a dependency (Redis, PostgreSQL) to degrade the detector
indirectly, exploiting the circuit breaker to force degraded mode.

**Mitigations**:
| Mitigation | Implementation |
|-----------|----------------|
| Circuit breaker | Graceful degradation to statistical-only scoring |
| Fallback scoring | Z-score works without Redis or IsolationForest |
| Multi-AZ dependencies | RDS Multi-AZ, Redis cluster with replicas |
| Independent health | Each component fails independently |
| Recovery automation | Half-open state periodically tests recovery |

**Residual Risk**: During circuit breaker open state, detection capability is reduced
(statistical-only). An attacker who can keep the circuit open has a window of reduced
detection. Mitigated by alerting on circuit state changes and aggressive recovery testing.

---

## E - Elevation of Privilege

### Threat E1: RBAC Bypass

**Attack**: An attacker with a low-privilege role (service, readonly) gains access to
admin-level operations (modify_config, view_audit).

**Attack Vectors**:
- JWT claim manipulation (adding "admin" to roles array)
- Role assignment via unprotected endpoint
- Permission matrix bypass through code vulnerability
- Default role fallback exploitation

**Mitigations**:
| Mitigation | Implementation |
|-----------|----------------|
| RS256 JWT signatures | Token integrity verified with public key; claims cannot be modified without the private key |
| Static permission matrix | Compiled into the application; no runtime modification API |
| Default deny | No role = no permissions (explicit assignment required) |
| Case-sensitive enums | Role("Admin") fails; only Role("admin") is valid |
| Code audit | Permission checks at every API boundary |
| No role self-service | Roles assigned by admin or JWT issuer only |

### Threat E2: JWT Token Manipulation

**Attack**: An attacker modifies JWT claims (roles, permissions, sub) to gain elevated
access.

**Attack Vectors**:
- Algorithm confusion (change alg header to HS256 and sign with public key)
- Token rewriting (modify claims and re-sign with a different key)
- Null algorithm attack (set alg to "none")
- Key injection via JKU/X5U headers

**Mitigations**:
| Mitigation | Implementation |
|-----------|----------------|
| Algorithm allowlist | Only RS256/RS384/RS512/ES256/ES384/ES512 accepted |
| HS256 rejection | Symmetric algorithms explicitly blocked with error |
| Static public key | Key configured at deployment, not from token headers |
| No JKU/X5U trust | Key source headers ignored; only configured key used |
| Signature verification | PyJWT library with strict algorithm enforcement |

### Threat E3: Container Escape

**Attack**: An attacker exploiting a vulnerability in the application gains access to the
host node or other containers.

**Mitigations**:
| Mitigation | Implementation |
|-----------|----------------|
| Non-root execution | SecurityContext: runAsNonRoot: true |
| Read-only filesystem | readOnlyRootFilesystem: true |
| No privilege escalation | allowPrivilegeEscalation: false |
| Dropped capabilities | All capabilities dropped (drop: ["ALL"]) |
| Network policies | Pod-to-pod traffic restricted to declared dependencies |
| Resource limits | Prevents resource abuse even if compromised |
| No host namespace | hostNetwork/hostPID/hostIPC all false |

---

## Residual Risks and Accepted Trade-offs

| Risk | Severity | Likelihood | Mitigation Status | Acceptance Rationale |
|------|----------|-----------|-------------------|---------------------|
| Patient model inversion via scoring API | Medium | Medium | Partially mitigated (rate limiting) | Knowing the boundary helps evasion but not corruption; periodic refresh changes boundary |
| Boiling frog baseline drift | High | Low | Partially mitigated (drift detection) | Fundamental limitation of adaptive systems; human review compensates |
| JWT revocation gap (token valid until expiry) | Medium | Low | Accepted (short-lived tokens) | Complexity of revocation infrastructure outweighs 5-15 min exposure window |
| Redis failure degrades rate limiting | Medium | Low | Accepted (fallback to in-memory) | Graceful degradation preferred over hard failure |
| Circuit breaker open reduces detection | High | Low | Accepted (alerting on state change) | Some detection better than no detection; alerts trigger human response |
| Audit log deletion with filesystem access | High | Very Low | Partially mitigated (remote shipping) | Requires root/elevated access to the host; defense-in-depth with remote copies |
| Side-channel timing of scoring paths | Low | Low | Accepted | Latency difference below network noise for remote clients |

---

## Threat Model Review Schedule

| Activity | Frequency | Responsible |
|----------|-----------|-------------|
| Full STRIDE review | Annually | Security team + engineering leads |
| New feature threat assessment | Per feature (during design) | Feature author + security reviewer |
| Penetration testing | Semi-annually | External security firm |
| Dependency vulnerability scan | Weekly (automated) | CI/CD pipeline (Dependabot/Snyk) |
| Access review | Quarterly | Engineering manager + security team |
| Incident-driven review | After any P1/P2 security incident | Incident response team |
