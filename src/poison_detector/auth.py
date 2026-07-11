"""
Authentication module for the dataset poisoning detection system.

Provides JWT (RS256), API key, and mTLS authentication mechanisms for
securing access to the detection API. All auth decisions are logged to
an audit trail for forensic analysis and compliance.

Threat Model Assumptions:
    - JWT tokens are signed with RS256 (asymmetric). The private key is held
      only by the token issuer (identity provider). This service validates
      tokens using the public key only. Compromise of the public key does
      not allow token forgery.
    - API keys are opaque bearer tokens with scoped permissions. They are
      stored as bcrypt hashes; compromise of the hash store does not reveal
      the original keys (assuming sufficient work factor).
    - mTLS validation trusts the CA certificate chain configured at startup.
      A compromised CA can issue fraudulent client certificates. Use a
      dedicated internal CA, not a public CA, for service-to-service auth.
    - Auth failure rate limiting prevents online brute-force attacks against
      API keys and JWT tokens. It does not prevent offline attacks against
      stolen hash databases.

Honest Limitations:
    - JWT revocation is not implemented (stateless validation only). A
      compromised token remains valid until expiry. Use short-lived tokens
      (5-15 minutes) with refresh token rotation to mitigate.
    - API key rotation requires coordination between key issuance and
      deployment. During rotation, both old and new keys are valid for
      the overlap period. This is intentional to prevent outages.
    - mTLS certificate revocation checking (CRL/OCSP) is not implemented.
      Revoked certificates will be accepted until they expire. For high-
      security environments, implement CRL checking externally.
    - The audit log is append-only in memory. For production, integrate
      with an external audit log service (CloudTrail, audit log DB).

Security Notes:
    - NEVER use HS256 for JWT. Symmetric signing means the validation key
      can forge tokens. Always use RS256/ES256 (asymmetric).
    - API keys must come from environment variables or a secrets manager,
      never from config files committed to version control.
    - All authentication failures are logged with client identifiers but
      without sensitive material (no passwords, no full tokens in logs).
    - Rate limiting on auth failures prevents brute force but does not
      replace proper key entropy (minimum 32 bytes of randomness).
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


class AuthMethod(Enum):
    """Authentication method used for a request."""

    JWT = "jwt"
    API_KEY = "api_key"
    MTLS = "mtls"


class AuthDecision(Enum):
    """Outcome of an authentication attempt."""

    ALLOWED = "allowed"
    DENIED = "denied"
    RATE_LIMITED = "rate_limited"


@dataclass
class AuthResult:
    """Result of an authentication attempt.

    Attributes:
        decision: Whether the request was allowed, denied, or rate limited.
        identity: Authenticated identity (subject claim, key ID, or cert CN).
        method: Which authentication method was used.
        roles: Roles associated with the identity (from JWT claims or key config).
        permissions: Specific permissions granted to this identity.
        metadata: Additional context (issuer, expiry, cert serial, etc.).
        error: Human-readable error message if denied.
    """

    decision: AuthDecision
    identity: str = ""
    method: AuthMethod = AuthMethod.JWT
    roles: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str = ""


@dataclass
class AuditEntry:
    """Audit log entry for an authentication event.

    Attributes:
        timestamp: Unix timestamp of the event.
        method: Authentication method attempted.
        decision: Outcome of the attempt.
        identity: Claimed or verified identity.
        client_ip: Client IP address (if available).
        resource: Resource being accessed.
        detail: Additional details about the decision.
    """

    timestamp: float
    method: AuthMethod
    decision: AuthDecision
    identity: str
    client_ip: str = ""
    resource: str = ""
    detail: str = ""


@dataclass
class APIKeyRecord:
    """Stored API key record with scoped permissions.

    Attributes:
        key_id: Unique identifier for the key (safe to log).
        key_hash: bcrypt hash of the actual key value.
        owner: Human-readable owner identifier.
        roles: Roles assigned to this key.
        permissions: Explicit permissions for this key.
        created_at: Unix timestamp when key was created.
        expires_at: Unix timestamp when key expires (0 = no expiry).
        rotation_due_at: Unix timestamp when key should be rotated.
        active: Whether the key is currently active.
    """

    key_id: str
    key_hash: str
    owner: str
    roles: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    rotation_due_at: float = 0.0
    active: bool = True


# ---------------------------------------------------------------------------
# Audit Trail
# ---------------------------------------------------------------------------


class AuditLog:
    """Thread-safe append-only audit log for authentication events.

    Stores entries in memory with a configurable maximum size. In production,
    this should be backed by a persistent store (database, CloudTrail, etc.).
    """

    def __init__(self, max_entries: int = 10000) -> None:
        self._entries: list[AuditEntry] = []
        self._lock = threading.Lock()
        self._max_entries = max_entries

    def record(
        self,
        method: AuthMethod,
        decision: AuthDecision,
        identity: str,
        client_ip: str = "",
        resource: str = "",
        detail: str = "",
    ) -> None:
        """Record an authentication event."""
        entry = AuditEntry(
            timestamp=time.time(),
            method=method,
            decision=decision,
            identity=identity,
            client_ip=client_ip,
            resource=resource,
            detail=detail,
        )
        with self._lock:
            self._entries.append(entry)
            if len(self._entries) > self._max_entries:
                self._entries = self._entries[-self._max_entries:]

        log_level = logging.INFO if decision == AuthDecision.ALLOWED else logging.WARNING
        logger.log(
            log_level,
            "AUTH %s: method=%s identity=%s ip=%s resource=%s detail=%s",
            decision.value,
            method.value,
            identity,
            client_ip,
            resource,
            detail,
        )

    def get_entries(self, limit: int = 100) -> list[AuditEntry]:
        """Get recent audit entries."""
        with self._lock:
            return list(reversed(self._entries[-limit:]))

    def get_failures(self, since: float = 0.0) -> list[AuditEntry]:
        """Get failed auth attempts since a given timestamp."""
        with self._lock:
            return [
                e for e in self._entries
                if e.decision != AuthDecision.ALLOWED and e.timestamp >= since
            ]

    @property
    def total_entries(self) -> int:
        with self._lock:
            return len(self._entries)


# ---------------------------------------------------------------------------
# Auth Failure Rate Limiter
# ---------------------------------------------------------------------------


class AuthFailureRateLimiter:
    """Rate limiter for authentication failures to prevent brute force.

    Tracks failed authentication attempts per client identifier and
    temporarily blocks clients that exceed the failure threshold.
    Uses exponential backoff for repeated offenders.
    """

    def __init__(
        self,
        max_failures: int = 5,
        lockout_seconds: float = 300.0,
        decay_seconds: float = 3600.0,
    ) -> None:
        """Initialize the auth failure rate limiter.

        Args:
            max_failures: Number of failures before lockout.
            lockout_seconds: Base lockout duration in seconds.
            decay_seconds: Time after which failure count decays.
        """
        self._max_failures = max_failures
        self._lockout_seconds = lockout_seconds
        self._decay_seconds = decay_seconds
        self._failures: dict[str, list[float]] = {}
        self._lockouts: dict[str, float] = {}
        self._lock = threading.Lock()

    def is_locked_out(self, client_id: str) -> bool:
        """Check if a client is currently locked out."""
        with self._lock:
            lockout_until = self._lockouts.get(client_id, 0.0)
            if lockout_until > time.time():
                return True
            if lockout_until > 0:
                del self._lockouts[client_id]
            return False

    def record_failure(self, client_id: str) -> None:
        """Record an authentication failure for a client."""
        now = time.time()
        with self._lock:
            if client_id not in self._failures:
                self._failures[client_id] = []

            # Prune old failures
            cutoff = now - self._decay_seconds
            self._failures[client_id] = [
                t for t in self._failures[client_id] if t > cutoff
            ]
            self._failures[client_id].append(now)

            # Check threshold
            if len(self._failures[client_id]) >= self._max_failures:
                consecutive = len(self._failures[client_id]) - self._max_failures + 1
                backoff = self._lockout_seconds * (2 ** min(consecutive - 1, 5))
                self._lockouts[client_id] = now + backoff
                logger.warning(
                    "Client %s locked out for %.0fs after %d failures",
                    client_id, backoff, len(self._failures[client_id]),
                )

    def record_success(self, client_id: str) -> None:
        """Record a successful auth, resetting failure count."""
        with self._lock:
            self._failures.pop(client_id, None)
            self._lockouts.pop(client_id, None)

    def get_lockout_remaining(self, client_id: str) -> float:
        """Get remaining lockout time in seconds (0 if not locked out)."""
        with self._lock:
            lockout_until = self._lockouts.get(client_id, 0.0)
            remaining = lockout_until - time.time()
            return max(0.0, remaining)


# ---------------------------------------------------------------------------
# JWT Authenticator (RS256)
# ---------------------------------------------------------------------------


class JWTAuthenticator:
    """JWT token validator using RS256 (asymmetric) signatures.

    Validates JWT tokens against a configured RSA public key with
    configurable issuer and audience claims. Rejects HS256 and other
    symmetric algorithms to prevent key confusion attacks.

    Usage:
        authenticator = JWTAuthenticator(
            public_key_pem=os.environ["JWT_PUBLIC_KEY"],
            issuer="https://auth.example.com",
            audience="poison-detector-api",
        )
        result = authenticator.authenticate(token)
        if result.decision == AuthDecision.ALLOWED:
            print(f"Authenticated: {result.identity}")
    """

    # Only allow asymmetric algorithms
    ALLOWED_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]

    def __init__(
        self,
        public_key_pem: str,
        issuer: str = "",
        audience: str = "",
        allowed_algorithms: list[str] | None = None,
        rate_limiter: AuthFailureRateLimiter | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        """Initialize the JWT authenticator.

        Args:
            public_key_pem: RSA/EC public key in PEM format for verification.
            issuer: Expected 'iss' claim. Empty string skips issuer validation.
            audience: Expected 'aud' claim. Empty string skips audience validation.
            allowed_algorithms: Algorithms to accept. Defaults to RS256 only.
            rate_limiter: Optional rate limiter for auth failures.
            audit_log: Optional audit log for recording decisions.

        Raises:
            ValueError: If public_key_pem is empty or algorithms include symmetric ones.
        """
        if not public_key_pem or not public_key_pem.strip():
            raise ValueError("public_key_pem must not be empty")

        algorithms = allowed_algorithms or ["RS256"]
        # Reject symmetric algorithms to prevent key confusion attacks
        forbidden = {"HS256", "HS384", "HS512"}
        if set(algorithms) & forbidden:
            raise ValueError(
                "Symmetric algorithms (HS256/HS384/HS512) are not allowed. "
                "Use RS256 or ES256 for asymmetric signature verification."
            )

        self._public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8")
        )
        self._issuer = issuer
        self._audience = audience
        self._algorithms = algorithms
        self._rate_limiter = rate_limiter
        self._audit_log = audit_log

    def authenticate(
        self,
        token: str,
        client_ip: str = "",
        resource: str = "",
    ) -> AuthResult:
        """Validate a JWT token and extract claims.

        Args:
            token: The JWT token string (without Bearer prefix).
            client_ip: Client IP for audit logging and rate limiting.
            resource: Resource being accessed (for audit logging).

        Returns:
            AuthResult with the authentication decision and extracted claims.
        """
        client_id = client_ip or "unknown"

        # Check rate limiting
        if self._rate_limiter and self._rate_limiter.is_locked_out(client_id):
            remaining = self._rate_limiter.get_lockout_remaining(client_id)
            self._log_decision(
                AuthDecision.RATE_LIMITED, client_id, client_ip, resource,
                f"locked out for {remaining:.0f}s",
            )
            return AuthResult(
                decision=AuthDecision.RATE_LIMITED,
                method=AuthMethod.JWT,
                error=f"Too many auth failures. Retry after {remaining:.0f}s.",
            )

        try:
            decode_options: dict[str, Any] = {}
            kwargs: dict[str, Any] = {"algorithms": self._algorithms}
            if self._issuer:
                kwargs["issuer"] = self._issuer
            if self._audience:
                kwargs["audience"] = self._audience

            payload = jwt.decode(
                token,
                self._public_key,
                **kwargs,
            )

            identity = payload.get("sub", "")
            roles = payload.get("roles", [])
            permissions = payload.get("permissions", [])

            if not identity:
                raise jwt.InvalidTokenError("Token missing 'sub' claim")

            if self._rate_limiter:
                self._rate_limiter.record_success(client_id)

            self._log_decision(
                AuthDecision.ALLOWED, identity, client_ip, resource,
                f"issuer={payload.get('iss', '')}",
            )

            return AuthResult(
                decision=AuthDecision.ALLOWED,
                identity=identity,
                method=AuthMethod.JWT,
                roles=roles if isinstance(roles, list) else [roles],
                permissions=permissions if isinstance(permissions, list) else [permissions],
                metadata={
                    "issuer": payload.get("iss", ""),
                    "audience": payload.get("aud", ""),
                    "expires_at": payload.get("exp", 0),
                    "issued_at": payload.get("iat", 0),
                },
            )

        except jwt.ExpiredSignatureError:
            error = "Token has expired"
        except jwt.InvalidAudienceError:
            error = "Invalid audience claim"
        except jwt.InvalidIssuerError:
            error = "Invalid issuer claim"
        except jwt.InvalidSignatureError:
            error = "Invalid signature"
        except jwt.DecodeError as e:
            error = f"Token decode error: {e}"
        except jwt.InvalidTokenError as e:
            error = f"Invalid token: {e}"
        except Exception as e:
            error = f"Authentication error: {type(e).__name__}"

        # Auth failed
        if self._rate_limiter:
            self._rate_limiter.record_failure(client_id)

        self._log_decision(
            AuthDecision.DENIED, client_id, client_ip, resource, error,
        )

        return AuthResult(
            decision=AuthDecision.DENIED,
            method=AuthMethod.JWT,
            error=error,
        )

    def _log_decision(
        self,
        decision: AuthDecision,
        identity: str,
        client_ip: str,
        resource: str,
        detail: str,
    ) -> None:
        """Log an auth decision to the audit trail."""
        if self._audit_log:
            self._audit_log.record(
                method=AuthMethod.JWT,
                decision=decision,
                identity=identity,
                client_ip=client_ip,
                resource=resource,
                detail=detail,
            )


# ---------------------------------------------------------------------------
# API Key Authenticator
# ---------------------------------------------------------------------------


class APIKeyAuthenticator:
    """API key authentication with scoped permissions and rotation.

    Validates API keys against bcrypt-hashed records with per-key
    permission scoping. Supports automatic rotation scheduling and
    key lifecycle management.

    Keys are stored as bcrypt hashes for security. Even if the key
    store is compromised, the original keys cannot be recovered.

    Usage:
        auth = APIKeyAuthenticator(audit_log=audit_log)
        key_id, raw_key = auth.create_key(
            owner="ml-pipeline",
            roles=["service"],
            permissions=["score", "batch_score"],
            rotation_days=90,
        )
        # Store raw_key securely, distribute to client

        result = auth.authenticate(raw_key)
        if result.decision == AuthDecision.ALLOWED:
            print(f"Key {result.identity} authenticated")
    """

    def __init__(
        self,
        rate_limiter: AuthFailureRateLimiter | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        """Initialize the API key authenticator.

        Args:
            rate_limiter: Optional rate limiter for auth failures.
            audit_log: Optional audit log for recording decisions.
        """
        self._keys: dict[str, APIKeyRecord] = {}
        self._lock = threading.Lock()
        self._rate_limiter = rate_limiter
        self._audit_log = audit_log

    def create_key(
        self,
        owner: str,
        roles: list[str] | None = None,
        permissions: list[str] | None = None,
        rotation_days: int = 90,
        expiry_days: int = 0,
    ) -> tuple[str, str]:
        """Create a new API key with scoped permissions.

        Args:
            owner: Human-readable owner identifier.
            roles: Roles to assign to this key.
            permissions: Explicit permissions for this key.
            rotation_days: Days until rotation is recommended.
            expiry_days: Days until key expires (0 = no expiry).

        Returns:
            Tuple of (key_id, raw_key). The raw_key is only returned once
            and must be stored securely by the caller.
        """
        import bcrypt

        # Generate cryptographically secure key
        raw_key = secrets.token_urlsafe(32)
        key_id = f"pk_{secrets.token_hex(8)}"

        # Hash with bcrypt (work factor 12)
        key_hash = bcrypt.hashpw(
            raw_key.encode("utf-8"), bcrypt.gensalt(rounds=12)
        ).decode("utf-8")

        now = time.time()
        record = APIKeyRecord(
            key_id=key_id,
            key_hash=key_hash,
            owner=owner,
            roles=roles or [],
            permissions=permissions or [],
            created_at=now,
            expires_at=now + (expiry_days * 86400) if expiry_days > 0 else 0.0,
            rotation_due_at=now + (rotation_days * 86400),
            active=True,
        )

        with self._lock:
            self._keys[key_id] = record

        logger.info("API key created: key_id=%s owner=%s", key_id, owner)
        return key_id, raw_key

    def authenticate(
        self,
        raw_key: str,
        client_ip: str = "",
        resource: str = "",
    ) -> AuthResult:
        """Authenticate a request using an API key.

        Args:
            raw_key: The raw API key value from the request.
            client_ip: Client IP for audit logging.
            resource: Resource being accessed.

        Returns:
            AuthResult with authentication decision.
        """
        import bcrypt

        client_id = client_ip or "unknown"

        # Check rate limiting
        if self._rate_limiter and self._rate_limiter.is_locked_out(client_id):
            remaining = self._rate_limiter.get_lockout_remaining(client_id)
            self._log_decision(
                AuthDecision.RATE_LIMITED, client_id, client_ip, resource,
                f"locked out for {remaining:.0f}s",
            )
            return AuthResult(
                decision=AuthDecision.RATE_LIMITED,
                method=AuthMethod.API_KEY,
                error=f"Too many auth failures. Retry after {remaining:.0f}s.",
            )

        if not raw_key:
            self._log_decision(
                AuthDecision.DENIED, client_id, client_ip, resource,
                "empty key",
            )
            return AuthResult(
                decision=AuthDecision.DENIED,
                method=AuthMethod.API_KEY,
                error="API key is required",
            )

        # Search for matching key (constant-time comparison via bcrypt)
        matched_record: APIKeyRecord | None = None
        with self._lock:
            for record in self._keys.values():
                if not record.active:
                    continue
                try:
                    if bcrypt.checkpw(
                        raw_key.encode("utf-8"),
                        record.key_hash.encode("utf-8"),
                    ):
                        matched_record = record
                        break
                except (ValueError, TypeError):
                    continue

        if matched_record is None:
            if self._rate_limiter:
                self._rate_limiter.record_failure(client_id)
            self._log_decision(
                AuthDecision.DENIED, client_id, client_ip, resource,
                "no matching key",
            )
            return AuthResult(
                decision=AuthDecision.DENIED,
                method=AuthMethod.API_KEY,
                error="Invalid API key",
            )

        # Check expiry
        if matched_record.expires_at > 0 and time.time() > matched_record.expires_at:
            if self._rate_limiter:
                self._rate_limiter.record_failure(client_id)
            self._log_decision(
                AuthDecision.DENIED, matched_record.key_id, client_ip, resource,
                "key expired",
            )
            return AuthResult(
                decision=AuthDecision.DENIED,
                method=AuthMethod.API_KEY,
                error="API key has expired",
            )

        # Success
        if self._rate_limiter:
            self._rate_limiter.record_success(client_id)

        rotation_warning = ""
        if matched_record.rotation_due_at > 0 and time.time() > matched_record.rotation_due_at:
            rotation_warning = "key rotation overdue"

        self._log_decision(
            AuthDecision.ALLOWED, matched_record.key_id, client_ip, resource,
            f"owner={matched_record.owner}" + (f" WARNING: {rotation_warning}" if rotation_warning else ""),
        )

        return AuthResult(
            decision=AuthDecision.ALLOWED,
            identity=matched_record.key_id,
            method=AuthMethod.API_KEY,
            roles=matched_record.roles,
            permissions=matched_record.permissions,
            metadata={
                "owner": matched_record.owner,
                "created_at": matched_record.created_at,
                "rotation_due_at": matched_record.rotation_due_at,
                "rotation_overdue": bool(rotation_warning),
            },
        )

    def revoke_key(self, key_id: str) -> bool:
        """Revoke an API key immediately.

        Args:
            key_id: The key ID to revoke.

        Returns:
            True if the key was found and revoked.
        """
        with self._lock:
            if key_id in self._keys:
                self._keys[key_id].active = False
                logger.info("API key revoked: key_id=%s", key_id)
                return True
        return False

    def get_keys_due_rotation(self) -> list[APIKeyRecord]:
        """Get all keys that are due for rotation."""
        now = time.time()
        with self._lock:
            return [
                record for record in self._keys.values()
                if record.active and record.rotation_due_at > 0
                and now > record.rotation_due_at
            ]

    def register_key(self, record: APIKeyRecord) -> None:
        """Register a pre-created key record (for loading from storage).

        Args:
            record: The APIKeyRecord to register.
        """
        with self._lock:
            self._keys[record.key_id] = record

    def _log_decision(
        self,
        decision: AuthDecision,
        identity: str,
        client_ip: str,
        resource: str,
        detail: str,
    ) -> None:
        """Log an auth decision to the audit trail."""
        if self._audit_log:
            self._audit_log.record(
                method=AuthMethod.API_KEY,
                decision=decision,
                identity=identity,
                client_ip=client_ip,
                resource=resource,
                detail=detail,
            )


# ---------------------------------------------------------------------------
# mTLS Certificate Validator
# ---------------------------------------------------------------------------


class MTLSValidator:
    """Mutual TLS client certificate validator for service-to-service auth.

    Validates client certificates against a trusted CA certificate and
    extracts identity from the certificate's Common Name (CN) or Subject
    Alternative Name (SAN).

    Usage:
        validator = MTLSValidator(
            ca_cert_pem=os.environ["MTLS_CA_CERT"],
            allowed_cns=["ml-pipeline.internal", "scoring-service.internal"],
        )
        result = validator.validate_certificate(client_cert_pem)
    """

    def __init__(
        self,
        ca_cert_pem: str,
        allowed_cns: list[str] | None = None,
        allowed_sans: list[str] | None = None,
        rate_limiter: AuthFailureRateLimiter | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        """Initialize the mTLS validator.

        Args:
            ca_cert_pem: CA certificate in PEM format for chain validation.
            allowed_cns: List of allowed Common Names. Empty allows any valid cert.
            allowed_sans: List of allowed Subject Alternative Names.
            rate_limiter: Optional rate limiter for auth failures.
            audit_log: Optional audit log for recording decisions.

        Raises:
            ValueError: If ca_cert_pem is empty or invalid.
        """
        if not ca_cert_pem or not ca_cert_pem.strip():
            raise ValueError("ca_cert_pem must not be empty")

        self._ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode("utf-8"))
        self._allowed_cns = set(allowed_cns) if allowed_cns else None
        self._allowed_sans = set(allowed_sans) if allowed_sans else None
        self._rate_limiter = rate_limiter
        self._audit_log = audit_log

    def validate_certificate(
        self,
        client_cert_pem: str,
        client_ip: str = "",
        resource: str = "",
    ) -> AuthResult:
        """Validate a client certificate for mTLS authentication.

        Checks:
        1. Certificate is parseable and well-formed
        2. Certificate is signed by the trusted CA
        3. Certificate has not expired
        4. Common Name or SAN is in the allowed list (if configured)

        Args:
            client_cert_pem: Client certificate in PEM format.
            client_ip: Client IP for audit logging.
            resource: Resource being accessed.

        Returns:
            AuthResult with authentication decision.
        """
        client_id = client_ip or "unknown"

        # Check rate limiting
        if self._rate_limiter and self._rate_limiter.is_locked_out(client_id):
            remaining = self._rate_limiter.get_lockout_remaining(client_id)
            self._log_decision(
                AuthDecision.RATE_LIMITED, client_id, client_ip, resource,
                f"locked out for {remaining:.0f}s",
            )
            return AuthResult(
                decision=AuthDecision.RATE_LIMITED,
                method=AuthMethod.MTLS,
                error=f"Too many auth failures. Retry after {remaining:.0f}s.",
            )

        try:
            client_cert = x509.load_pem_x509_certificate(
                client_cert_pem.encode("utf-8")
            )
        except Exception as e:
            if self._rate_limiter:
                self._rate_limiter.record_failure(client_id)
            self._log_decision(
                AuthDecision.DENIED, client_id, client_ip, resource,
                f"invalid certificate: {e}",
            )
            return AuthResult(
                decision=AuthDecision.DENIED,
                method=AuthMethod.MTLS,
                error="Invalid client certificate",
            )

        # Verify signature chain (cert signed by CA)
        try:
            ca_public_key = self._ca_cert.public_key()
            ca_public_key.verify(
                client_cert.signature,
                client_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                client_cert.signature_hash_algorithm,
            )
        except Exception:
            if self._rate_limiter:
                self._rate_limiter.record_failure(client_id)
            self._log_decision(
                AuthDecision.DENIED, client_id, client_ip, resource,
                "certificate not signed by trusted CA",
            )
            return AuthResult(
                decision=AuthDecision.DENIED,
                method=AuthMethod.MTLS,
                error="Certificate not signed by trusted CA",
            )

        # Check expiry
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        if client_cert.not_valid_after_utc < now:
            if self._rate_limiter:
                self._rate_limiter.record_failure(client_id)
            self._log_decision(
                AuthDecision.DENIED, client_id, client_ip, resource,
                "certificate expired",
            )
            return AuthResult(
                decision=AuthDecision.DENIED,
                method=AuthMethod.MTLS,
                error="Client certificate has expired",
            )

        if client_cert.not_valid_before_utc > now:
            if self._rate_limiter:
                self._rate_limiter.record_failure(client_id)
            self._log_decision(
                AuthDecision.DENIED, client_id, client_ip, resource,
                "certificate not yet valid",
            )
            return AuthResult(
                decision=AuthDecision.DENIED,
                method=AuthMethod.MTLS,
                error="Client certificate is not yet valid",
            )

        # Extract identity from CN
        cn_attrs = client_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn = cn_attrs[0].value if cn_attrs else ""

        # Extract SANs
        sans: list[str] = []
        try:
            san_ext = client_cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        # Check CN allowlist
        if self._allowed_cns and cn not in self._allowed_cns:
            # Also check if any SAN is allowed
            if not self._allowed_sans or not (set(sans) & self._allowed_sans):
                if self._rate_limiter:
                    self._rate_limiter.record_failure(client_id)
                self._log_decision(
                    AuthDecision.DENIED, cn or client_id, client_ip, resource,
                    f"CN '{cn}' not in allowed list",
                )
                return AuthResult(
                    decision=AuthDecision.DENIED,
                    method=AuthMethod.MTLS,
                    error=f"Certificate CN '{cn}' is not authorized",
                )

        # Check SAN allowlist
        if self._allowed_sans and not self._allowed_cns:
            if not (set(sans) & self._allowed_sans):
                if self._rate_limiter:
                    self._rate_limiter.record_failure(client_id)
                self._log_decision(
                    AuthDecision.DENIED, cn or client_id, client_ip, resource,
                    "no matching SAN",
                )
                return AuthResult(
                    decision=AuthDecision.DENIED,
                    method=AuthMethod.MTLS,
                    error="Certificate SANs not authorized",
                )

        # Success
        if self._rate_limiter:
            self._rate_limiter.record_success(client_id)

        serial_hex = format(client_cert.serial_number, "x")
        identity = cn or (sans[0] if sans else serial_hex)

        self._log_decision(
            AuthDecision.ALLOWED, identity, client_ip, resource,
            f"serial={serial_hex}",
        )

        return AuthResult(
            decision=AuthDecision.ALLOWED,
            identity=identity,
            method=AuthMethod.MTLS,
            roles=["service"],
            permissions=[],
            metadata={
                "serial_number": serial_hex,
                "common_name": cn,
                "sans": sans,
                "not_valid_after": client_cert.not_valid_after_utc.isoformat(),
            },
        )

    def _log_decision(
        self,
        decision: AuthDecision,
        identity: str,
        client_ip: str,
        resource: str,
        detail: str,
    ) -> None:
        """Log an auth decision to the audit trail."""
        if self._audit_log:
            self._audit_log.record(
                method=AuthMethod.MTLS,
                decision=decision,
                identity=identity,
                client_ip=client_ip,
                resource=resource,
                detail=detail,
            )
