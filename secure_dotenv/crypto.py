"""Cryptographic primitives for secure-dotenv.

Encryption scheme
-----------------
* Cipher:        AES-256-GCM (AEAD) via ``cryptography.hazmat``.
* Master key:    32 random bytes, stored/transported as standard base64 text.
* Per value:     a fresh random 12-byte nonce is generated for every value.
* Wire format:   ``ENC[AES_GCM,data:<base64(nonce || ciphertext || tag)>]``
* AAD:           the variable *name* is bound as Additional Authenticated Data.
                 This means a ciphertext for ``ADMIN_TOKEN`` will not decrypt if
                 it is moved onto ``GUEST_TOKEN`` in the file -- it prevents
                 value-swapping tampering, not just bit-flipping.

Nothing here shells out to external binaries (age/gpg/openssl/sops). It is pure
Python on top of the ``cryptography`` package.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import (
    DecryptionError,
    EncryptionError,
    InvalidMasterKeyError,
)

# --- Format constants -------------------------------------------------------

ALGORITHM = "AES_GCM"
KEY_SIZE = 32  # AES-256
NONCE_SIZE = 12  # 96-bit nonce recommended for GCM

ENC_PREFIX = f"ENC[{ALGORITHM},data:"
ENC_SUFFIX = "]"

# Domain separation string so the public fingerprint can never be confused with
# any other hash of the key material.
_FINGERPRINT_DOMAIN = b"secure-dotenv/key-fingerprint/v1"


# --- Helpers ----------------------------------------------------------------

def _zero(buf: bytearray) -> None:
    """Best-effort overwrite of a mutable byte buffer.

    Python cannot guarantee secrets are erased from memory (immutable ``bytes``/
    ``str`` and GC copies make this impossible in the general case), but for the
    mutable buffers we control we overwrite them promptly to shrink the window.
    """
    for i in range(len(buf)):
        buf[i] = 0


# --- Key management ---------------------------------------------------------

def generate_master_key() -> str:
    """Generate a new cryptographically secure master key (base64 text)."""
    return base64.b64encode(os.urandom(KEY_SIZE)).decode("ascii")


def load_key_bytes(master_key: str) -> bytes:
    """Decode and validate a base64-encoded master key string into raw bytes.

    Raises:
        InvalidMasterKeyError: if the key is not valid base64 or has the wrong
            length for AES-256.
    """
    if not isinstance(master_key, str):
        raise InvalidMasterKeyError("Master key must be a string.")
    cleaned = master_key.strip()
    if not cleaned:
        raise InvalidMasterKeyError("Master key is empty.")
    try:
        raw = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidMasterKeyError(
            "Master key is not valid base64. It must be a base64-encoded "
            "32-byte key as produced by `secure-dotenv init`."
        ) from exc
    if len(raw) != KEY_SIZE:
        raise InvalidMasterKeyError(
            f"Master key must decode to {KEY_SIZE} bytes (got {len(raw)}). "
            "Did you copy the whole key?"
        )
    return raw


def key_fingerprint(key_bytes: bytes) -> str:
    """Return a short, non-reversible fingerprint of a key (16 hex chars).

    This is safe to store in the encrypted file: it lets us detect a wrong key
    up front without revealing key material.
    """
    digest = hashlib.sha256(_FINGERPRINT_DOMAIN + key_bytes).digest()
    return digest[:8].hex()


# --- Value encryption / decryption ------------------------------------------

def is_encrypted_value(value: str) -> bool:
    """Return True if ``value`` is a well-formed ENC[...] token."""
    return value.startswith(ENC_PREFIX) and value.endswith(ENC_SUFFIX)


def encrypt_value(key_bytes: bytes, plaintext: str, *, aad: str) -> str:
    """Encrypt a single value, returning the ``ENC[...]`` wire token.

    Args:
        key_bytes: raw 32-byte AES key.
        plaintext: the cleartext value to protect.
        aad: additional authenticated data (the variable name) bound to the
            ciphertext. Must be supplied identically at decryption time.
    """
    aesgcm = AESGCM(key_bytes)
    nonce = os.urandom(NONCE_SIZE)
    pt = bytearray(plaintext.encode("utf-8"))
    try:
        ciphertext = aesgcm.encrypt(nonce, bytes(pt), aad.encode("utf-8"))
    except Exception as exc:  # pragma: no cover - defensive
        raise EncryptionError(f"Failed to encrypt value: {exc}") from exc
    finally:
        _zero(pt)
    payload = base64.b64encode(nonce + ciphertext).decode("ascii")
    return f"{ENC_PREFIX}{payload}{ENC_SUFFIX}"


def decrypt_value(key_bytes: bytes, token: str, *, aad: str) -> str:
    """Decrypt an ``ENC[...]`` token back into the cleartext value.

    Raises:
        DecryptionError: if the token is malformed, the key is wrong, the AAD
            (variable name) does not match, or the ciphertext was tampered with.
    """
    if not is_encrypted_value(token):
        raise DecryptionError(
            "Value is not a recognized ENC[AES_GCM,...] token."
        )
    payload_b64 = token[len(ENC_PREFIX):-len(ENC_SUFFIX)]
    try:
        blob = base64.b64decode(payload_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DecryptionError("Corrupted data: payload is not valid base64.") from exc
    if len(blob) <= NONCE_SIZE:
        raise DecryptionError("Corrupted data: ciphertext is too short.")
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    aesgcm = AESGCM(key_bytes)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad.encode("utf-8"))
    except InvalidTag as exc:
        raise DecryptionError(
            "Invalid Master Key or Corrupted Data."
        ) from exc
    return plaintext.decode("utf-8")
