"""Coverage tests for crypto: envelope encryption edge cases, scrypt KDF,
associated-data authentication, master-key rotation, dict integrity tags, and
key-material validation.
"""

import base64
import os

import pytest

from poison_detector.crypto import (
    DataEncryptor,
    IntegrityVerifier,
    KeyDeriver,
    generate_hmac_key,
    generate_master_key,
)


def test_key_deriver_rejects_empty_and_short_keys():
    """KeyDeriver requires a non-empty master key of at least 16 bytes."""
    with pytest.raises(ValueError):
        KeyDeriver(master_key="")
    with pytest.raises(ValueError):
        KeyDeriver(master_key="   ")
    # 'short' decodes to fewer than 16 bytes -> rejected
    with pytest.raises(ValueError):
        KeyDeriver(master_key="short")


def test_key_deriver_scrypt_method():
    """The scrypt KDF derives a deterministic key for a fixed salt."""
    deriver = KeyDeriver(master_key=generate_master_key(), method="scrypt")
    assert deriver.method == "scrypt"
    salt = os.urandom(16)
    k1, s1 = deriver.derive_key(salt=salt)
    k2, _ = deriver.derive_key(salt=salt)
    assert k1 == k2
    assert len(k1) == 32


def test_encrypt_decrypt_with_associated_data():
    """AAD is authenticated: correct AAD decrypts, tampered AAD fails."""
    enc = DataEncryptor(master_key=generate_master_key())
    payload = enc.encrypt(b"secret", associated_data=b"context-v1")
    assert enc.decrypt(payload, associated_data=b"context-v1") == b"secret"
    with pytest.raises(ValueError):
        enc.decrypt(payload, associated_data=b"wrong-context")


def test_decrypt_wrong_master_key_fails():
    """Decrypting with a different master key fails at the data-key step."""
    payload = DataEncryptor(master_key=generate_master_key()).encrypt(b"data")
    other = DataEncryptor(master_key=generate_master_key())
    with pytest.raises(ValueError, match="data key"):
        other.decrypt(payload)


def test_decrypt_tampered_ciphertext_fails():
    """Flipping ciphertext bytes causes AEAD decryption to fail."""
    enc = DataEncryptor(master_key=generate_master_key())
    payload = enc.encrypt(b"important data")
    raw = bytearray(base64.b64decode(payload.ciphertext))
    raw[0] ^= 0xFF
    payload.ciphertext = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(ValueError):
        enc.decrypt(payload)


def test_decrypt_invalid_encoding_fails():
    """A payload with non-base64 fields raises a clear error."""
    enc = DataEncryptor(master_key=generate_master_key())
    payload = enc.encrypt(b"x")
    payload.nonce = "!!!not base64!!!"
    with pytest.raises(ValueError, match="Invalid payload encoding"):
        enc.decrypt(payload)


def test_master_key_rotation_preserves_plaintext():
    """Rotating the master key re-wraps the DEK; data still decrypts under new key."""
    old_key = generate_master_key()
    new_key = generate_master_key()
    enc_old = DataEncryptor(master_key=old_key)
    payload = enc_old.encrypt(b"rotate me")

    rotated = enc_old.rotate_master_key(payload, old_key, new_key)
    # Ciphertext body unchanged, only the wrapped key/salt changed
    assert rotated.ciphertext == payload.ciphertext

    enc_new = DataEncryptor(master_key=new_key)
    assert enc_new.decrypt(rotated) == b"rotate me"


def test_integrity_verifier_rejects_empty_key():
    """IntegrityVerifier requires a non-empty HMAC key."""
    with pytest.raises(ValueError):
        IntegrityVerifier(hmac_key="")


def test_integrity_verifier_short_key_is_stretched():
    """A short HMAC key is stretched via SHA-256 so tags still verify."""
    verifier = IntegrityVerifier(hmac_key="tiny", key_id="k1")
    assert verifier.key_id == "k1"
    tag = verifier.generate_tag(b"payload")
    assert verifier.verify_tag(b"payload", tag) is True
    assert verifier.verify_tag(b"payload-2", tag) is False


def test_integrity_verifier_dict_roundtrip():
    """Dict integrity tags verify on identical data and fail on changes."""
    verifier = IntegrityVerifier(hmac_key=generate_hmac_key())
    data = {"sample_id": "abc", "score": 0.9, "nested": {"a": 1}}
    tag = verifier.generate_tag_for_dict(data)
    assert verifier.verify_tag_for_dict(data, tag) is True

    changed = dict(data)
    changed["score"] = 0.1
    assert verifier.verify_tag_for_dict(changed, tag) is False


def test_generate_keys_are_distinct_and_sized():
    """Key generators produce distinct 32-byte base64 keys."""
    a = generate_master_key()
    b = generate_master_key()
    assert a != b
    assert len(base64.b64decode(a)) == 32
    assert len(base64.b64decode(generate_hmac_key())) == 32
