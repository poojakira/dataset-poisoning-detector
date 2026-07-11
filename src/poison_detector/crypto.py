"""
Cryptographic integrity and encryption module for the poisoning detection system.

Provides AES-256-GCM encryption for sample data at rest, HMAC-SHA256 for
tamper detection in quarantine storage, and envelope encryption with key
derivation from a master key.

Threat Model Assumptions:
    - The master key is stored in a KMS, Vault, or environment variable
      protected by the deployment infrastructure. It is never committed
      to version control or logged.
    - AES-256-GCM provides both confidentiality and integrity (AEAD). An
      attacker who modifies ciphertext will cause decryption to fail with
      an InvalidTag error rather than producing corrupted plaintext.
    - HMAC-SHA256 integrity tags detect tampering in quarantine storage.
      An attacker who modifies a quarantined sample without the HMAC key
      will be detected. If the HMAC key is compromised, the attacker can
      forge valid tags.
    - Key derivation via PBKDF2 or scrypt produces unique data encryption
      keys from the master key + a random salt. Compromise of one data
      key does not reveal the master key or other data keys.

Honest Limitations:
    - Key rotation for envelope encryption requires re-encrypting all data
      keys with the new master key. The data itself does not need re-encryption.
      However, this module does not implement automatic rotation; it must be
      triggered externally.
    - AES-256-GCM has a nonce reuse catastrophe: if the same nonce is used
      twice with the same key, confidentiality is completely broken. This
      implementation uses os.urandom(12) for nonces, which is safe for up
      to 2^32 encryptions per key (birthday bound). For higher volumes,
      use AES-256-GCM-SIV or rotate keys more frequently.
    - PBKDF2 with 600,000 iterations is OWASP-recommended for 2024 but
      may need adjustment as hardware improves. Scrypt is preferred for
      new deployments due to memory-hardness.
    - No support for HSM-backed keys. All cryptographic operations happen
      in process memory. Use a KMS for the master key if HSM protection
      is required.

Security Notes:
    - NEVER hardcode keys. All keys come from environment variables, KMS,
      or Vault. This module refuses to operate with empty/default keys.
    - Nonces are generated via os.urandom (CSPRNG). Never reuse nonces.
    - Key material is not logged, printed, or included in error messages.
    - Failed integrity checks raise exceptions rather than returning
      corrupted data. Callers must handle these exceptions appropriately.
    - The envelope encryption pattern means data keys are short-lived and
      unique per record. Even if one data key leaks, only one record is
      compromised.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_AES_KEY_SIZE = 32  # 256 bits
_NONCE_SIZE = 12  # 96 bits for AES-GCM
_SALT_SIZE = 16  # 128 bits
_HMAC_KEY_SIZE = 32  # 256 bits
_PBKDF2_ITERATIONS = 600_000  # OWASP 2024 recommendation


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class EncryptedPayload:
    """Encrypted data with all metadata needed for decryption.

    Attributes:
        ciphertext: The encrypted data (base64-encoded).
        nonce: The nonce/IV used for encryption (base64-encoded).
        encrypted_data_key: The data key encrypted by the master key (base64).
        key_salt: Salt used in key derivation (base64-encoded).
        algorithm: Encryption algorithm identifier.
        version: Schema version for forward compatibility.
    """

    ciphertext: str
    nonce: str
    encrypted_data_key: str
    key_salt: str
    algorithm: str = "AES-256-GCM"
    version: int = 1


@dataclass
class IntegrityTag:
    """HMAC integrity tag for tamper detection.

    Attributes:
        tag: The HMAC-SHA256 tag (hex-encoded).
        key_id: Identifier for the HMAC key used (for key rotation).
        algorithm: HMAC algorithm identifier.
        version: Schema version.
    """

    tag: str
    key_id: str = "default"
    algorithm: str = "HMAC-SHA256"
    version: int = 1


# ---------------------------------------------------------------------------
# Key Derivation
# ---------------------------------------------------------------------------


class KeyDeriver:
    """Derives encryption keys from a master key using PBKDF2 or scrypt.

    Produces unique, deterministic data encryption keys by combining the
    master key with a random salt. The same master key + salt always produces
    the same derived key, enabling decryption.

    Usage:
        deriver = KeyDeriver(master_key=os.environ["MASTER_KEY"])
        data_key, salt = deriver.derive_key()
        # Use data_key for encryption, store salt alongside ciphertext
    """

    def __init__(
        self,
        master_key: str,
        method: str = "pbkdf2",
        iterations: int = _PBKDF2_ITERATIONS,
    ) -> None:
        """Initialize the key deriver.

        Args:
            master_key: Base64-encoded master key from KMS/Vault/env.
            method: Key derivation method ("pbkdf2" or "scrypt").
            iterations: PBKDF2 iteration count (ignored for scrypt).

        Raises:
            ValueError: If master_key is empty or too short.
        """
        if not master_key or not master_key.strip():
            raise ValueError(
                "master_key must not be empty. "
                "Set via environment variable or KMS."
            )

        # Decode or use raw bytes
        try:
            self._master_key_bytes = base64.b64decode(master_key)
        except Exception:
            # If not valid base64, use raw UTF-8 bytes
            self._master_key_bytes = master_key.encode("utf-8")

        if len(self._master_key_bytes) < 16:
            raise ValueError(
                "master_key must be at least 16 bytes (128 bits). "
                "Use 32 bytes (256 bits) for AES-256."
            )

        self._method = method
        self._iterations = iterations

    def derive_key(
        self,
        salt: bytes | None = None,
        key_length: int = _AES_KEY_SIZE,
    ) -> tuple[bytes, bytes]:
        """Derive an encryption key from the master key.

        Args:
            salt: Optional salt (random salt generated if None).
            key_length: Desired key length in bytes.

        Returns:
            Tuple of (derived_key, salt). Store salt for later derivation.
        """
        if salt is None:
            salt = os.urandom(_SALT_SIZE)

        if self._method == "scrypt":
            kdf = Scrypt(
                salt=salt,
                length=key_length,
                n=2**14,
                r=8,
                p=1,
            )
            derived = kdf.derive(self._master_key_bytes)
        else:
            # PBKDF2 (default)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=key_length,
                salt=salt,
                iterations=self._iterations,
            )
            derived = kdf.derive(self._master_key_bytes)

        return derived, salt

    @property
    def method(self) -> str:
        """The key derivation method in use."""
        return self._method


# ---------------------------------------------------------------------------
# Data Encryptor (AES-256-GCM with Envelope Encryption)
# ---------------------------------------------------------------------------


class DataEncryptor:
    """AES-256-GCM encryption with envelope encryption pattern.

    Encrypts data using a randomly generated data encryption key (DEK),
    then encrypts the DEK with a key derived from the master key. This
    pattern limits the exposure of the master key and allows efficient
    key rotation (only DEKs need re-encryption, not the data itself).

    Usage:
        encryptor = DataEncryptor(master_key=os.environ["MASTER_KEY"])

        # Encrypt
        payload = encryptor.encrypt(b"sensitive sample data")

        # Decrypt
        plaintext = encryptor.decrypt(payload)
        assert plaintext == b"sensitive sample data"
    """

    def __init__(
        self,
        master_key: str,
        kdf_method: str = "pbkdf2",
        kdf_iterations: int = _PBKDF2_ITERATIONS,
    ) -> None:
        """Initialize the data encryptor.

        Args:
            master_key: Base64-encoded master key from KMS/Vault/env.
            kdf_method: Key derivation method ("pbkdf2" or "scrypt").
            kdf_iterations: PBKDF2 iteration count.

        Raises:
            ValueError: If master_key is empty.
        """
        self._key_deriver = KeyDeriver(
            master_key=master_key,
            method=kdf_method,
            iterations=kdf_iterations,
        )

    def encrypt(self, plaintext: bytes, associated_data: bytes | None = None) -> EncryptedPayload:
        """Encrypt data using AES-256-GCM with envelope encryption.

        Steps:
        1. Generate a random data encryption key (DEK).
        2. Encrypt the plaintext with the DEK using AES-256-GCM.
        3. Derive a key encryption key (KEK) from the master key.
        4. Encrypt the DEK with the KEK.
        5. Return all components needed for decryption.

        Args:
            plaintext: Data to encrypt.
            associated_data: Optional additional authenticated data (AAD).
                AAD is authenticated but not encrypted.

        Returns:
            EncryptedPayload with ciphertext and metadata.
        """
        # Step 1: Generate random DEK
        dek = os.urandom(_AES_KEY_SIZE)

        # Step 2: Encrypt plaintext with DEK
        data_nonce = os.urandom(_NONCE_SIZE)
        data_cipher = AESGCM(dek)
        ciphertext = data_cipher.encrypt(data_nonce, plaintext, associated_data)

        # Step 3: Derive KEK from master key
        kek, kek_salt = self._key_deriver.derive_key(key_length=_AES_KEY_SIZE)

        # Step 4: Encrypt DEK with KEK
        dek_nonce = os.urandom(_NONCE_SIZE)
        kek_cipher = AESGCM(kek)
        encrypted_dek = kek_cipher.encrypt(dek_nonce, dek, None)

        # Combine DEK nonce + encrypted DEK for storage
        encrypted_data_key = dek_nonce + encrypted_dek

        return EncryptedPayload(
            ciphertext=base64.b64encode(ciphertext).decode("ascii"),
            nonce=base64.b64encode(data_nonce).decode("ascii"),
            encrypted_data_key=base64.b64encode(encrypted_data_key).decode("ascii"),
            key_salt=base64.b64encode(kek_salt).decode("ascii"),
        )

    def decrypt(self, payload: EncryptedPayload, associated_data: bytes | None = None) -> bytes:
        """Decrypt data from an EncryptedPayload.

        Steps:
        1. Derive the KEK from the master key + stored salt.
        2. Decrypt the DEK using the KEK.
        3. Decrypt the ciphertext using the DEK.

        Args:
            payload: The encrypted payload to decrypt.
            associated_data: AAD that was provided during encryption.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            ValueError: If decryption fails (wrong key, tampered data).
        """
        try:
            ciphertext = base64.b64decode(payload.ciphertext)
            data_nonce = base64.b64decode(payload.nonce)
            encrypted_data_key = base64.b64decode(payload.encrypted_data_key)
            kek_salt = base64.b64decode(payload.key_salt)
        except Exception as e:
            raise ValueError(f"Invalid payload encoding: {e}") from e

        # Step 1: Derive KEK
        kek, _ = self._key_deriver.derive_key(salt=kek_salt, key_length=_AES_KEY_SIZE)

        # Step 2: Decrypt DEK
        try:
            dek_nonce = encrypted_data_key[:_NONCE_SIZE]
            encrypted_dek = encrypted_data_key[_NONCE_SIZE:]
            kek_cipher = AESGCM(kek)
            dek = kek_cipher.decrypt(dek_nonce, encrypted_dek, None)
        except Exception as e:
            raise ValueError(
                "Failed to decrypt data key. Master key may have changed."
            ) from e

        # Step 3: Decrypt data
        try:
            data_cipher = AESGCM(dek)
            plaintext = data_cipher.decrypt(data_nonce, ciphertext, associated_data)
        except Exception as e:
            raise ValueError(
                "Failed to decrypt data. Data may have been tampered with."
            ) from e

        return plaintext

    def rotate_master_key(
        self,
        payload: EncryptedPayload,
        old_master_key: str,
        new_master_key: str,
    ) -> EncryptedPayload:
        """Re-encrypt a payload's data key with a new master key.

        This rotates the master key without re-encrypting the actual data.
        Only the data encryption key wrapper changes.

        Args:
            payload: Existing encrypted payload.
            old_master_key: The old master key (to decrypt DEK).
            new_master_key: The new master key (to re-encrypt DEK).

        Returns:
            New EncryptedPayload with DEK encrypted under new master key.
        """
        # Decrypt DEK with old master key
        old_deriver = KeyDeriver(master_key=old_master_key)
        old_kek_salt = base64.b64decode(payload.key_salt)
        old_kek, _ = old_deriver.derive_key(salt=old_kek_salt, key_length=_AES_KEY_SIZE)

        encrypted_data_key = base64.b64decode(payload.encrypted_data_key)
        dek_nonce = encrypted_data_key[:_NONCE_SIZE]
        encrypted_dek = encrypted_data_key[_NONCE_SIZE:]

        old_kek_cipher = AESGCM(old_kek)
        dek = old_kek_cipher.decrypt(dek_nonce, encrypted_dek, None)

        # Re-encrypt DEK with new master key
        new_deriver = KeyDeriver(master_key=new_master_key)
        new_kek, new_kek_salt = new_deriver.derive_key(key_length=_AES_KEY_SIZE)

        new_dek_nonce = os.urandom(_NONCE_SIZE)
        new_kek_cipher = AESGCM(new_kek)
        new_encrypted_dek = new_kek_cipher.encrypt(new_dek_nonce, dek, None)

        new_encrypted_data_key = new_dek_nonce + new_encrypted_dek

        return EncryptedPayload(
            ciphertext=payload.ciphertext,
            nonce=payload.nonce,
            encrypted_data_key=base64.b64encode(new_encrypted_data_key).decode("ascii"),
            key_salt=base64.b64encode(new_kek_salt).decode("ascii"),
        )


# ---------------------------------------------------------------------------
# Integrity Verifier (HMAC-SHA256)
# ---------------------------------------------------------------------------


class IntegrityVerifier:
    """HMAC-SHA256 integrity verification for quarantine tamper detection.

    Generates and verifies HMAC tags over serialized data to detect
    unauthorized modifications to quarantined samples. Any modification
    to the data (even a single bit flip) will cause verification to fail.

    Usage:
        verifier = IntegrityVerifier(hmac_key=os.environ["HMAC_KEY"])

        # Generate tag for data
        tag = verifier.generate_tag(serialized_sample)

        # Later, verify integrity
        if not verifier.verify_tag(serialized_sample, tag):
            raise SecurityError("Quarantine data has been tampered with!")
    """

    def __init__(self, hmac_key: str, key_id: str = "default") -> None:
        """Initialize the integrity verifier.

        Args:
            hmac_key: Base64-encoded HMAC key from KMS/Vault/env.
            key_id: Identifier for this key (for rotation tracking).

        Raises:
            ValueError: If hmac_key is empty or too short.
        """
        if not hmac_key or not hmac_key.strip():
            raise ValueError(
                "hmac_key must not be empty. "
                "Set via environment variable or KMS."
            )

        try:
            self._key_bytes = base64.b64decode(hmac_key)
        except Exception:
            self._key_bytes = hmac_key.encode("utf-8")

        if len(self._key_bytes) < _HMAC_KEY_SIZE:
            # Derive a proper key from short input using SHA-256
            self._key_bytes = hashlib.sha256(self._key_bytes).digest()

        self._key_id = key_id

    def generate_tag(self, data: bytes) -> IntegrityTag:
        """Generate an HMAC-SHA256 tag for the given data.

        Args:
            data: The data to generate a tag for.

        Returns:
            IntegrityTag with the computed HMAC.
        """
        tag_value = hmac.new(
            self._key_bytes,
            data,
            hashlib.sha256,
        ).hexdigest()

        return IntegrityTag(
            tag=tag_value,
            key_id=self._key_id,
        )

    def verify_tag(self, data: bytes, tag: IntegrityTag) -> bool:
        """Verify an HMAC tag against data.

        Uses constant-time comparison to prevent timing attacks.

        Args:
            data: The data to verify.
            tag: The IntegrityTag to check against.

        Returns:
            True if the tag is valid, False if data has been tampered with.
        """
        expected = hmac.new(
            self._key_bytes,
            data,
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(expected, tag.tag)

    def generate_tag_for_dict(self, data: dict[str, Any]) -> IntegrityTag:
        """Generate an HMAC tag for a dictionary (deterministic serialization).

        Serializes the dictionary with sorted keys for deterministic output,
        then generates the HMAC.

        Args:
            data: Dictionary to generate tag for.

        Returns:
            IntegrityTag for the serialized dictionary.
        """
        import json
        serialized = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return self.generate_tag(serialized)

    def verify_tag_for_dict(self, data: dict[str, Any], tag: IntegrityTag) -> bool:
        """Verify an HMAC tag for a dictionary.

        Args:
            data: Dictionary to verify.
            tag: The IntegrityTag to check against.

        Returns:
            True if valid, False if tampered.
        """
        import json
        serialized = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return self.verify_tag(serialized, tag)

    @property
    def key_id(self) -> str:
        """The key identifier for this verifier."""
        return self._key_id


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------


def generate_master_key() -> str:
    """Generate a cryptographically secure master key.

    Returns a base64-encoded 256-bit key suitable for use as a master
    encryption key or HMAC key.

    Returns:
        Base64-encoded 32-byte key string.
    """
    return base64.b64encode(os.urandom(_AES_KEY_SIZE)).decode("ascii")


def generate_hmac_key() -> str:
    """Generate a cryptographically secure HMAC key.

    Returns:
        Base64-encoded 32-byte key string.
    """
    return base64.b64encode(os.urandom(_HMAC_KEY_SIZE)).decode("ascii")
