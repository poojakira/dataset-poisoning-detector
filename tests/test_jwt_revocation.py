"""Tests for JWT jti-based revocation (TokenDenylist)."""

import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from poison_detector.auth import AuthDecision, JWTAuthenticator, TokenDenylist


def _keypair() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pub


def _token(priv: str, jti: str = "abc123", exp_delta: int = 3600) -> tuple[str, int]:
    exp = int(time.time()) + exp_delta
    payload = {
        "sub": "svc@example.com",
        "exp": exp,
        "iat": int(time.time()),
        "jti": jti,
        "roles": ["service"],
    }
    return jwt.encode(payload, priv, algorithm="RS256"), exp


def test_denylist_basic_revoke_and_prune():
    dl = TokenDenylist()
    assert dl.is_revoked("x") is False
    dl.revoke("x", expires_at=time.time() + 100)
    assert dl.is_revoked("x") is True
    assert dl.size == 1
    # An already-expired revocation is pruned on read.
    dl.revoke("y", expires_at=time.time() - 1)
    assert dl.is_revoked("y") is False


def test_denylist_prune_counts_expired():
    dl = TokenDenylist()
    dl.revoke("a", expires_at=time.time() - 1)
    dl.revoke("b", expires_at=time.time() + 100)
    removed = dl.prune()
    assert removed == 1
    assert dl.size == 1


def test_denylist_rejects_empty_jti():
    dl = TokenDenylist()
    with pytest.raises(ValueError):
        dl.revoke("")


def test_valid_token_allowed_then_denied_after_revoke():
    priv, pub = _keypair()
    auth = JWTAuthenticator(public_key_pem=pub)
    token, exp = _token(priv, jti="tok-1")

    # Initially valid.
    result = auth.authenticate(token)
    assert result.decision == AuthDecision.ALLOWED
    assert result.metadata["jti"] == "tok-1"

    # After revocation, the same signature-valid token is denied.
    auth.revoke("tok-1", expires_at=exp)
    result2 = auth.authenticate(token)
    assert result2.decision == AuthDecision.DENIED
    assert "revoked" in result2.error.lower()


def test_revoking_one_jti_does_not_affect_others():
    priv, pub = _keypair()
    auth = JWTAuthenticator(public_key_pem=pub)
    token_a, exp_a = _token(priv, jti="A")
    token_b, exp_b = _token(priv, jti="B")

    auth.revoke("A", expires_at=exp_a)
    assert auth.authenticate(token_a).decision == AuthDecision.DENIED
    assert auth.authenticate(token_b).decision == AuthDecision.ALLOWED


def test_token_without_jti_cannot_be_revoked_but_still_validates():
    priv, pub = _keypair()
    auth = JWTAuthenticator(public_key_pem=pub)
    payload = {"sub": "u", "exp": int(time.time()) + 3600, "iat": int(time.time())}
    token = jwt.encode(payload, priv, algorithm="RS256")
    # No jti -> validates fine; there is nothing to put on the denylist.
    assert auth.authenticate(token).decision == AuthDecision.ALLOWED
