"""Tests for cryptographic integrity and encryption.

Verifies AES-256-GCM encryption roundtrip, HMAC-SHA256 tamper detection,
and deterministic key derivation using real cryptographic operations.
"""

import base64
import os

from poison_detector.crypto import (
    DataEncryptor,
    IntegrityVerifier,
    KeyDeriver,
    generate_master_key,
)


def test_encryption_roundtrip():
    """DataEncryptor encrypt-then-decrypt recovers the original plaintext."""
    master_key = generate_master_key()
    encryptor = DataEncryptor(master_key=master_key)

    plaintext = b"sensitive sample data with unicode: \xc3\xa9\xc3\xa0"

    # Encrypt
    payload = encryptor.encrypt(plaintext)
    assert payload.ciphertext != ""
    assert payload.nonce != ""
    assert payload.algorithm == "AES-256-GCM"

    # The ciphertext should not contain the plaintext
    ciphertext_bytes = base64.b64decode(payload.ciphertext)
    assert plaintext not in ciphertext_bytes

    # Decrypt
    recovered = encryptor.decrypt(payload)
    assert recovered == plaintext


def test_hmac_integrity_detects_tampering():
    """IntegrityVerifier detects any modification to the tagged data."""
    hmac_key = base64.b64encode(os.urandom(32)).decode("ascii")
    verifier = IntegrityVerifier(hmac_key=hmac_key)

    original_data = b"quarantined sample data for integrity check"

    # Generate tag for original data
    tag = verifier.generate_tag(original_data)
    assert tag.tag != ""
    assert tag.algorithm == "HMAC-SHA256"

    # Verification succeeds on untampered data
    assert verifier.verify_tag(original_data, tag) is True

    # Tampering: modify a single byte
    tampered_data = b"Quarantined sample data for integrity check"  # 'q' -> 'Q'
    assert verifier.verify_tag(tampered_data, tag) is False

    # Tampering: append data
    extended_data = original_data + b" extra"
    assert verifier.verify_tag(extended_data, tag) is False

    # Tampering: truncate data
    truncated_data = original_data[:10]
    assert verifier.verify_tag(truncated_data, tag) is False


def test_key_derivation_deterministic():
    """KeyDeriver produces the same key from the same password and salt."""
    master_key = generate_master_key()
    deriver = KeyDeriver(master_key=master_key, method="pbkdf2")

    # First derivation with a fixed salt
    salt = os.urandom(16)
    key_1, salt_1 = deriver.derive_key(salt=salt)
    key_2, salt_2 = deriver.derive_key(salt=salt)

    # Same salt must yield the same key
    assert key_1 == key_2
    assert salt_1 == salt_2 == salt
    assert len(key_1) == 32  # 256-bit key

    # Different salt must yield a different key
    different_salt = os.urandom(16)
    key_3, _ = deriver.derive_key(salt=different_salt)
    assert key_3 != key_1
