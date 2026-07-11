"""Coverage tests for the authentication module.

Covers the mTLS certificate validator (self-signed CA + client certs generated
at runtime with the cryptography library), the auth-failure rate limiter's
lockout/backoff/decay, the in-memory AuditLog, API key expiry / rotation-due /
register paths, and the JWT TokenDenylist revocation flow.
"""

import datetime
import time
from datetime import timedelta

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from poison_detector.auth import (
    APIKeyAuthenticator,
    APIKeyRecord,
    AuditLog,
    AuthDecision,
    AuthFailureRateLimiter,
    AuthMethod,
    JWTAuthenticator,
    MTLSValidator,
    TokenDenylist,
)


# --------------------------------------------------------------------------
# Certificate helpers
# --------------------------------------------------------------------------


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _make_ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Internal CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - timedelta(days=1))
        .not_valid_after(_now() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_client_cert(ca_key, ca_cert, cn, sans=None, not_before=None, not_after=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or (_now() - timedelta(days=1)))
        .not_valid_after(not_after or (_now() + timedelta(days=365)))
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


def _pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


# --------------------------------------------------------------------------
# MTLSValidator
# --------------------------------------------------------------------------


def test_mtls_requires_ca_cert():
    """Constructing MTLSValidator without a CA cert is rejected."""
    with pytest.raises(ValueError):
        MTLSValidator(ca_cert_pem="")


def test_mtls_valid_certificate_allowed():
    """A client cert signed by the trusted CA with an allowed CN authenticates."""
    ca_key, ca_cert = _make_ca()
    _, client_cert = _make_client_cert(ca_key, ca_cert, "ml-pipeline.internal")
    validator = MTLSValidator(
        ca_cert_pem=_pem(ca_cert), allowed_cns=["ml-pipeline.internal"]
    )
    result = validator.validate_certificate(_pem(client_cert))
    assert result.decision == AuthDecision.ALLOWED
    assert result.identity == "ml-pipeline.internal"
    assert result.method == AuthMethod.MTLS
    assert result.metadata["common_name"] == "ml-pipeline.internal"


def test_mtls_rejects_untrusted_ca():
    """A cert signed by a different CA fails chain verification."""
    ca_key, ca_cert = _make_ca()
    other_ca_key, _ = _make_ca()
    # Sign client cert with the OTHER CA key but claim the trusted CA as issuer
    _, client_cert = _make_client_cert(other_ca_key, ca_cert, "rogue.internal")
    validator = MTLSValidator(ca_cert_pem=_pem(ca_cert))
    result = validator.validate_certificate(_pem(client_cert))
    assert result.decision == AuthDecision.DENIED
    assert "trusted CA" in result.error


def test_mtls_rejects_expired_certificate():
    """An expired client certificate is denied."""
    ca_key, ca_cert = _make_ca()
    _, client_cert = _make_client_cert(
        ca_key, ca_cert, "old.internal",
        not_before=_now() - timedelta(days=10),
        not_after=_now() - timedelta(days=1),
    )
    validator = MTLSValidator(ca_cert_pem=_pem(ca_cert))
    result = validator.validate_certificate(_pem(client_cert))
    assert result.decision == AuthDecision.DENIED
    assert "expired" in result.error.lower()


def test_mtls_rejects_not_yet_valid_certificate():
    """A certificate whose validity starts in the future is denied."""
    ca_key, ca_cert = _make_ca()
    _, client_cert = _make_client_cert(
        ca_key, ca_cert, "future.internal",
        not_before=_now() + timedelta(days=1),
        not_after=_now() + timedelta(days=10),
    )
    validator = MTLSValidator(ca_cert_pem=_pem(ca_cert))
    result = validator.validate_certificate(_pem(client_cert))
    assert result.decision == AuthDecision.DENIED
    assert "not yet valid" in result.error.lower()


def test_mtls_rejects_disallowed_cn():
    """A valid cert whose CN is not in the allowlist is denied."""
    ca_key, ca_cert = _make_ca()
    _, client_cert = _make_client_cert(ca_key, ca_cert, "unknown.internal")
    validator = MTLSValidator(
        ca_cert_pem=_pem(ca_cert), allowed_cns=["ml-pipeline.internal"]
    )
    result = validator.validate_certificate(_pem(client_cert))
    assert result.decision == AuthDecision.DENIED
    assert "not authorized" in result.error


def test_mtls_allows_via_san():
    """When only SANs are allowlisted, a matching SAN authenticates the cert."""
    ca_key, ca_cert = _make_ca()
    _, client_cert = _make_client_cert(
        ca_key, ca_cert, "svc.internal", sans=["scoring.internal", "extra.internal"]
    )
    validator = MTLSValidator(
        ca_cert_pem=_pem(ca_cert), allowed_sans=["scoring.internal"]
    )
    result = validator.validate_certificate(_pem(client_cert))
    assert result.decision == AuthDecision.ALLOWED
    assert "scoring.internal" in result.metadata["sans"]


def test_mtls_rejects_disallowed_san():
    """SAN allowlist with no matching SAN denies the cert."""
    ca_key, ca_cert = _make_ca()
    _, client_cert = _make_client_cert(
        ca_key, ca_cert, "svc.internal", sans=["nomatch.internal"]
    )
    validator = MTLSValidator(
        ca_cert_pem=_pem(ca_cert), allowed_sans=["scoring.internal"]
    )
    result = validator.validate_certificate(_pem(client_cert))
    assert result.decision == AuthDecision.DENIED


def test_mtls_rejects_malformed_certificate():
    """Garbage PEM input is rejected as an invalid certificate."""
    ca_key, ca_cert = _make_ca()
    validator = MTLSValidator(ca_cert_pem=_pem(ca_cert))
    result = validator.validate_certificate("-----BEGIN CERTIFICATE-----\nnotreal\n-----END CERTIFICATE-----")
    assert result.decision == AuthDecision.DENIED
    assert "Invalid client certificate" in result.error


def test_mtls_rate_limited_when_locked_out():
    """A locked-out client short-circuits to RATE_LIMITED before validation."""
    ca_key, ca_cert = _make_ca()
    limiter = AuthFailureRateLimiter(max_failures=1, lockout_seconds=100.0)
    validator = MTLSValidator(
        ca_cert_pem=_pem(ca_cert), rate_limiter=limiter
    )
    # First bad attempt trips the lockout for this client IP.
    validator.validate_certificate("bad", client_ip="10.0.0.9")
    result = validator.validate_certificate("bad", client_ip="10.0.0.9")
    assert result.decision == AuthDecision.RATE_LIMITED


# --------------------------------------------------------------------------
# AuthFailureRateLimiter
# --------------------------------------------------------------------------


def test_auth_failure_lockout_and_success_reset():
    """Repeated failures lock a client out; a success clears the failure count."""
    limiter = AuthFailureRateLimiter(max_failures=3, lockout_seconds=50.0)
    assert limiter.is_locked_out("c") is False

    for _ in range(3):
        limiter.record_failure("c")
    assert limiter.is_locked_out("c") is True
    assert limiter.get_lockout_remaining("c") > 0

    # Success clears state even while notionally locked out
    limiter.record_success("c")
    assert limiter.is_locked_out("c") is False
    assert limiter.get_lockout_remaining("c") == 0.0


def test_auth_failure_lockout_expires():
    """After the lockout window passes, is_locked_out returns False and prunes."""
    limiter = AuthFailureRateLimiter(max_failures=1, lockout_seconds=0.01)
    limiter.record_failure("c")
    assert limiter.is_locked_out("c") is True
    time.sleep(0.05)
    assert limiter.is_locked_out("c") is False


# --------------------------------------------------------------------------
# AuditLog
# --------------------------------------------------------------------------


def test_audit_log_records_and_queries():
    """AuditLog records events, returns them newest-first, and filters failures."""
    log = AuditLog(max_entries=5)
    log.record(AuthMethod.JWT, AuthDecision.ALLOWED, "alice", client_ip="1.1.1.1")
    log.record(AuthMethod.API_KEY, AuthDecision.DENIED, "bob", detail="bad key")
    assert log.total_entries == 2

    entries = log.get_entries(limit=10)
    assert entries[0].identity == "bob"  # newest first

    failures = log.get_failures()
    assert len(failures) == 1
    assert failures[0].decision == AuthDecision.DENIED


def test_audit_log_bounded_size():
    """AuditLog keeps only the most recent max_entries records."""
    log = AuditLog(max_entries=3)
    for i in range(6):
        log.record(AuthMethod.JWT, AuthDecision.ALLOWED, f"user-{i}")
    assert log.total_entries == 3
    identities = [e.identity for e in log.get_entries(limit=10)]
    assert "user-5" in identities
    assert "user-0" not in identities


# --------------------------------------------------------------------------
# APIKeyAuthenticator additional paths
# --------------------------------------------------------------------------


def test_api_key_empty_and_invalid():
    """Empty and non-matching keys are denied with descriptive errors."""
    auth = APIKeyAuthenticator()
    empty = auth.authenticate("")
    assert empty.decision == AuthDecision.DENIED
    assert "required" in empty.error

    bad = auth.authenticate("no-such-key")
    assert bad.decision == AuthDecision.DENIED
    assert "Invalid API key" in bad.error


def test_api_key_expiry_denied():
    """A key past its expiry is denied."""
    auth = APIKeyAuthenticator()
    key_id, raw = auth.create_key(owner="svc", expiry_days=1)
    # Force expiry into the past
    auth._keys[key_id].expires_at = time.time() - 10
    result = auth.authenticate(raw)
    assert result.decision == AuthDecision.DENIED
    assert "expired" in result.error.lower()


def test_api_key_rotation_due_reporting_and_register():
    """Overdue rotation is flagged and get_keys_due_rotation lists such keys.
    register_key installs a pre-built record that then authenticates."""
    auth = APIKeyAuthenticator(audit_log=AuditLog())
    key_id, raw = auth.create_key(owner="svc", roles=["service"], permissions=["score"])
    # Force rotation overdue
    auth._keys[key_id].rotation_due_at = time.time() - 10

    result = auth.authenticate(raw)
    assert result.decision == AuthDecision.ALLOWED
    assert result.metadata["rotation_overdue"] is True

    due = auth.get_keys_due_rotation()
    assert any(r.key_id == key_id for r in due)

    # Register a record built elsewhere; it should not be authenticatable by a
    # random string but should appear in the store.
    import bcrypt
    raw2 = "externally-provisioned-key"
    rec = APIKeyRecord(
        key_id="pk_ext",
        key_hash=bcrypt.hashpw(raw2.encode(), bcrypt.gensalt(rounds=4)).decode(),
        owner="ext",
        roles=["service"],
        permissions=["score"],
    )
    auth.register_key(rec)
    assert auth.authenticate(raw2).decision == AuthDecision.ALLOWED


def test_api_key_rate_limited():
    """A locked-out client is rate limited before key comparison."""
    limiter = AuthFailureRateLimiter(max_failures=1, lockout_seconds=100.0)
    auth = APIKeyAuthenticator(rate_limiter=limiter)
    auth.authenticate("wrong", client_ip="9.9.9.9")  # failure -> lockout
    result = auth.authenticate("wrong", client_ip="9.9.9.9")
    assert result.decision == AuthDecision.RATE_LIMITED


# --------------------------------------------------------------------------
# JWT revocation via TokenDenylist
# --------------------------------------------------------------------------


def _rsa_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pub


def test_token_denylist_revoke_prune_size():
    """TokenDenylist revokes by jti, prunes expired entries, and reports size."""
    dl = TokenDenylist()
    with pytest.raises(ValueError):
        dl.revoke("")
    assert dl.is_revoked("missing") is False

    dl.revoke("jti-1", expires_at=time.time() + 100)
    dl.revoke("jti-old", expires_at=time.time() - 5)
    assert dl.is_revoked("jti-1") is True
    # Expired entry pruned lazily on access
    assert dl.is_revoked("jti-old") is False
    assert dl.is_revoked("") is False

    dl.revoke("jti-old2", expires_at=time.time() - 5)
    removed = dl.prune()
    assert removed >= 1
    assert dl.size >= 1


def test_jwt_revoked_token_denied():
    """A signature-valid JWT whose jti is revoked is denied."""
    priv, pub = _rsa_keypair()
    auth = JWTAuthenticator(public_key_pem=pub, issuer="iss", audience="aud")
    payload = {
        "sub": "user@example.com",
        "iss": "iss",
        "aud": "aud",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        "jti": "token-123",
    }
    token = jwt.encode(payload, priv, algorithm="RS256")
    assert auth.authenticate(token).decision == AuthDecision.ALLOWED

    auth.revoke("token-123", expires_at=payload["exp"])
    result = auth.authenticate(token)
    assert result.decision == AuthDecision.DENIED
    assert "revoked" in result.error.lower()


def test_jwt_rejects_symmetric_algorithm_config():
    """Configuring the validator with HS256 is refused (key-confusion guard)."""
    _, pub = _rsa_keypair()
    with pytest.raises(ValueError):
        JWTAuthenticator(public_key_pem=pub, allowed_algorithms=["HS256"])


def test_jwt_missing_sub_denied():
    """A token without a 'sub' claim is denied."""
    priv, pub = _rsa_keypair()
    auth = JWTAuthenticator(public_key_pem=pub)
    token = jwt.encode({"exp": int(time.time()) + 100}, priv, algorithm="RS256")
    result = auth.authenticate(token)
    assert result.decision == AuthDecision.DENIED
