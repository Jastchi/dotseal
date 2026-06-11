"""Cryptographic primitives for dotseal.

Symmetric scheme (default)
--------------------------
* Cipher:        AES-256-GCM (AEAD) via ``cryptography.hazmat``.
* Master key:    32 random bytes, stored/transported as standard base64 text.
* Per value:     a fresh random 12-byte nonce is generated for every value.
* Wire format:   ``ENC[AES_GCM,data:<base64(nonce || ciphertext || tag)>]``
* AAD:           the variable *name* is bound as Additional Authenticated Data.
                 This means a ciphertext for ``ADMIN_TOKEN`` will not decrypt if
                 it is moved onto ``GUEST_TOKEN`` in the file -- it prevents
                 value-swapping tampering, not just bit-flipping.

Asymmetric scheme (multi-recipient, opt-in)
-------------------------------------------
* Envelope:      a random 32-byte *data key* (DEK) encrypts the values exactly
                 like the symmetric path. The DEK itself is then *wrapped*
                 once per recipient.
* Wrapping:      X25519 ECDH (the same primitive ``age`` uses) -> HKDF-SHA256
                 -> AES-256-GCM. A fresh ephemeral key pair is generated per
                 wrap, so the wrapped DEK is non-deterministic and forward-ish.
* Keys:          recipients hold an X25519 key pair. The public key
                 (``dsk-pub-...``) is safe to commit/share; the private key
                 (``dsk-prv-...``) stays secret. No secret is ever transported
                 between developers.

Nothing here shells out to external binaries (age/gpg/openssl/sops). It is pure
Python on top of the ``cryptography`` package.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
from typing import Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .exceptions import (
    DecryptionError,
    EncryptionError,
    InvalidMasterKeyError,
    InvalidRecipientKeyError,
)

# --- Format constants -------------------------------------------------------

ALGORITHM = "AES_GCM"
ALGORITHM_ASYM = "AES_GCM+X25519"
KEY_SIZE = 32  # AES-256 (and the X25519 key/DEK size)
NONCE_SIZE = 12  # 96-bit nonce recommended for GCM

ENC_PREFIX = f"ENC[{ALGORITHM},data:"
ENC_SUFFIX = "]"

# Human-recognizable prefixes so a key's role is obvious at a glance and the two
# halves of a pair can never be confused for one another.
PUBKEY_PREFIX = "dsk-pub-"
PRIVKEY_PREFIX = "dsk-prv-"

# Domain separation strings so a public fingerprint can never be confused with
# any other hash of the key material.
_FINGERPRINT_DOMAIN = b"dotseal/key-fingerprint/v1"
_RECIPIENT_FP_DOMAIN = b"dotseal/recipient-fingerprint/v1"
_DEK_WRAP_INFO = b"dotseal/dek-wrap/v1"


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
            "32-byte key as produced by `dotseal init`."
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


# --- Asymmetric recipient keys (X25519) -------------------------------------

def generate_recipient_keypair() -> Tuple[str, str]:
    """Generate a fresh X25519 recipient key pair.

    Returns:
        ``(private_key, public_key)`` as ``dsk-prv-...`` / ``dsk-pub-...``
        base64 strings. The public key is safe to share/commit; the private key
        must be kept secret.
    """
    private = X25519PrivateKey.generate()
    priv_raw = private.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    pub_raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    priv_str = PRIVKEY_PREFIX + base64.b64encode(priv_raw).decode("ascii")
    pub_str = PUBKEY_PREFIX + base64.b64encode(pub_raw).decode("ascii")
    return priv_str, pub_str


def _decode_key_body(value: str, prefix: str, role: str) -> bytes:
    if not isinstance(value, str):
        raise InvalidRecipientKeyError(f"{role} key must be a string.")
    cleaned = value.strip()
    if not cleaned.startswith(prefix):
        raise InvalidRecipientKeyError(
            f"{role} key must start with {prefix!r}. "
            "Did you mix up the public and private halves?"
        )
    try:
        raw = base64.b64decode(cleaned[len(prefix):], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidRecipientKeyError(
            f"{role} key is not valid base64."
        ) from exc
    if len(raw) != KEY_SIZE:
        raise InvalidRecipientKeyError(
            f"{role} key must decode to {KEY_SIZE} bytes (got {len(raw)})."
        )
    return raw


def load_recipient_public_key(value: str) -> X25519PublicKey:
    """Parse a ``dsk-pub-...`` string into an X25519 public key object."""
    raw = _decode_key_body(value, PUBKEY_PREFIX, "Public")
    return X25519PublicKey.from_public_bytes(raw)


def load_recipient_private_key(value: str) -> X25519PrivateKey:
    """Parse a ``dsk-prv-...`` string into an X25519 private key object."""
    raw = _decode_key_body(value, PRIVKEY_PREFIX, "Private")
    return X25519PrivateKey.from_private_bytes(raw)


def public_key_str_from_private(value: str) -> str:
    """Derive the ``dsk-pub-...`` string that matches a ``dsk-prv-...`` string."""
    private = load_recipient_private_key(value)
    pub_raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return PUBKEY_PREFIX + base64.b64encode(pub_raw).decode("ascii")


def recipient_fingerprint(public_key: str) -> str:
    """Return a short, non-reversible fingerprint of a recipient public key.

    Used to label recipient slots in the file so the right wrapped DEK can be
    located quickly without trial-decrypting every slot.
    """
    raw = _decode_key_body(public_key, PUBKEY_PREFIX, "Public")
    digest = hashlib.sha256(_RECIPIENT_FP_DOMAIN + raw).digest()
    return digest[:8].hex()


# --- DEK (data key) envelope ------------------------------------------------

def generate_data_key() -> bytes:
    """Generate a fresh random 32-byte data key (DEK) for one file."""
    return os.urandom(KEY_SIZE)


def _wrap_key(ephem_pub_raw: bytes, recipient_pub_raw: bytes, shared: bytes) -> bytes:
    """Derive the AES key that wraps the DEK for one recipient.

    The HKDF salt binds both the ephemeral and recipient public keys (as ``age``
    does), so a wrapped DEK cannot be transplanted onto a different recipient.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=ephem_pub_raw + recipient_pub_raw,
        info=_DEK_WRAP_INFO,
    ).derive(shared)


def wrap_dek(recipient_public: X25519PublicKey, dek: bytes) -> Tuple[str, str]:
    """Wrap ``dek`` for a single recipient via ephemeral-static ECDH.

    Returns:
        ``(ephemeral_public_b64, wrapped_dek_b64)`` -- both base64 ASCII. The
        ephemeral public key lets the recipient reconstruct the shared secret.
    """
    ephemeral = X25519PrivateKey.generate()
    ephem_pub_raw = ephemeral.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    recipient_pub_raw = recipient_public.public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    shared = ephemeral.exchange(recipient_public)
    wrap_key = _wrap_key(ephem_pub_raw, recipient_pub_raw, shared)
    nonce = os.urandom(NONCE_SIZE)
    try:
        wrapped = AESGCM(wrap_key).encrypt(nonce, dek, None)
    except Exception as exc:  # pragma: no cover - defensive
        raise EncryptionError(f"Failed to wrap data key: {exc}") from exc
    ephem_b64 = base64.b64encode(ephem_pub_raw).decode("ascii")
    wrapped_b64 = base64.b64encode(nonce + wrapped).decode("ascii")
    return ephem_b64, wrapped_b64


def unwrap_dek(
    recipient_private: X25519PrivateKey,
    ephemeral_public_b64: str,
    wrapped_dek_b64: str,
) -> bytes:
    """Recover a DEK from one recipient slot. Raises ``DecryptionError`` on miss.

    A ``DecryptionError`` here simply means this slot was not wrapped for the
    supplied private key (or the data is corrupt); callers may try other slots.
    """
    try:
        ephem_pub_raw = base64.b64decode(ephemeral_public_b64, validate=True)
        blob = base64.b64decode(wrapped_dek_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DecryptionError("Corrupted recipient slot: invalid base64.") from exc
    if len(ephem_pub_raw) != KEY_SIZE or len(blob) <= NONCE_SIZE:
        raise DecryptionError("Corrupted recipient slot: wrong field length.")
    ephemeral_public = X25519PublicKey.from_public_bytes(ephem_pub_raw)
    recipient_pub_raw = recipient_private.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    shared = recipient_private.exchange(ephemeral_public)
    wrap_key = _wrap_key(ephem_pub_raw, recipient_pub_raw, shared)
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    try:
        return AESGCM(wrap_key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise DecryptionError(
            "This private key cannot unwrap this recipient slot."
        ) from exc
