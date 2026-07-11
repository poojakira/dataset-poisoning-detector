"""Tests for authentication, API key rotation, and RBAC enforcement.

Verifies JWT RS256 validation, API key lifecycle with rotation,
and role-based permission enforcement using real cryptographic operations.
"""

import time

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from poison_detector.auth import (
    APIKeyAuthenticator,
    AuthDecision,
    JWTAuthenticator,
)
from poison_detector.rbac import (
    Permission,
    RBACEnforcer,
    Role,
)


def _generate_rsa_keypair() -> tuple[str, str]:
    """Generate an RSA key pair and return (private_pem, public_pem) as strings."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def test_jwt_validation_accepts_valid_token():
    """JWTAuthenticator accepts a correctly signed RS256 token with valid claims."""
    private_pem, public_pem = _generate_rsa_keypair()

    authenticator = JWTAuthenticator(
        public_key_pem=public_pem,
        issuer="https://auth.example.com",
        audience="poison-detector-api",
    )

    payload = {
        "sub": "user@example.com",
        "iss": "https://auth.example.com",
        "aud": "poison-detector-api",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        "roles": ["analyst"],
        "permissions": ["score", "view_quarantine"],
    }
    token = jwt.encode(payload, private_pem, algorithm="RS256")

    result = authenticator.authenticate(token)

    assert result.decision == AuthDecision.ALLOWED
    assert result.identity == "user@example.com"
    assert "analyst" in result.roles
    assert result.metadata["issuer"] == "https://auth.example.com"


def test_jwt_validation_rejects_invalid_token():
    """JWTAuthenticator rejects expired, wrong-issuer, and tampered tokens."""
    private_pem, public_pem = _generate_rsa_keypair()
    other_private_pem, _ = _generate_rsa_keypair()

    authenticator = JWTAuthenticator(
        public_key_pem=public_pem,
        issuer="https://auth.example.com",
        audience="poison-detector-api",
    )

    # Expired token
    expired_payload = {
        "sub": "user@example.com",
        "iss": "https://auth.example.com",
        "aud": "poison-detector-api",
        "exp": int(time.time()) - 3600,
        "iat": int(time.time()) - 7200,
    }
    expired_token = jwt.encode(expired_payload, private_pem, algorithm="RS256")
    result = authenticator.authenticate(expired_token)
    assert result.decision == AuthDecision.DENIED
    assert "expired" in result.error.lower()

    # Wrong issuer
    wrong_issuer_payload = {
        "sub": "user@example.com",
        "iss": "https://evil.example.com",
        "aud": "poison-detector-api",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
    }
    wrong_issuer_token = jwt.encode(wrong_issuer_payload, private_pem, algorithm="RS256")
    result = authenticator.authenticate(wrong_issuer_token)
    assert result.decision == AuthDecision.DENIED
    assert "issuer" in result.error.lower()

    # Tampered token (signed with different key)
    tampered_payload = {
        "sub": "attacker@evil.com",
        "iss": "https://auth.example.com",
        "aud": "poison-detector-api",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
    }
    tampered_token = jwt.encode(tampered_payload, other_private_pem, algorithm="RS256")
    result = authenticator.authenticate(tampered_token)
    assert result.decision == AuthDecision.DENIED
    assert "signature" in result.error.lower()


def test_api_key_rotation():
    """API key rotation invalidates old keys after revocation."""
    auth = APIKeyAuthenticator()

    # Create an initial key
    key_id_1, raw_key_1 = auth.create_key(
        owner="ml-pipeline",
        roles=["service"],
        permissions=["score", "batch_score"],
    )

    # Verify old key works
    result = auth.authenticate(raw_key_1)
    assert result.decision == AuthDecision.ALLOWED
    assert result.identity == key_id_1

    # Create a new key (simulating rotation)
    key_id_2, raw_key_2 = auth.create_key(
        owner="ml-pipeline",
        roles=["service"],
        permissions=["score", "batch_score"],
    )

    # Revoke the old key (complete the rotation)
    revoked = auth.revoke_key(key_id_1)
    assert revoked is True

    # Old key must be rejected
    result = auth.authenticate(raw_key_1)
    assert result.decision == AuthDecision.DENIED

    # New key must still work
    result = auth.authenticate(raw_key_2)
    assert result.decision == AuthDecision.ALLOWED
    assert result.identity == key_id_2


def test_rbac_permission_enforcement():
    """RBACEnforcer correctly allows and denies based on role-permission matrix."""
    enforcer = RBACEnforcer()

    # Assign roles to identities
    enforcer.assign_role("admin-user", Role.ADMIN)
    enforcer.assign_role("analyst-user", Role.ANALYST)
    enforcer.assign_role("service-account", Role.SERVICE)
    enforcer.assign_role("readonly-user", Role.READONLY)

    # Admin can do everything
    decision = enforcer.check_permission("admin-user", Permission.MODIFY_CONFIG)
    assert decision.allowed is True

    decision = enforcer.check_permission("admin-user", Permission.VIEW_AUDIT)
    assert decision.allowed is True

    # Analyst can score and view quarantine but cannot modify config
    decision = enforcer.check_permission("analyst-user", Permission.SCORE)
    assert decision.allowed is True

    decision = enforcer.check_permission("analyst-user", Permission.VIEW_QUARANTINE)
    assert decision.allowed is True

    decision = enforcer.check_permission("analyst-user", Permission.MODIFY_CONFIG)
    assert decision.allowed is False
    assert "does not have permission" in decision.reason

    # Service can score but cannot view quarantine
    decision = enforcer.check_permission("service-account", Permission.SCORE)
    assert decision.allowed is True

    decision = enforcer.check_permission("service-account", Permission.VIEW_QUARANTINE)
    assert decision.allowed is False

    # Readonly can view quarantine but cannot score
    decision = enforcer.check_permission("readonly-user", Permission.VIEW_QUARANTINE)
    assert decision.allowed is True

    decision = enforcer.check_permission("readonly-user", Permission.SCORE)
    assert decision.allowed is False

    # Unknown identity is denied
    decision = enforcer.check_permission("unknown-user", Permission.SCORE)
    assert decision.allowed is False
