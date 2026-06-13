"""Custom exception hierarchy for dotseal.

These exceptions exist so that failures surface as clear, actionable messages
instead of leaking raw cryptographic tracebacks (which are both confusing and a
minor information-leak risk) to end users.
"""

from __future__ import annotations


class DotsealError(Exception):
    """Base class for all dotseal errors."""


class KeyManagementError(DotsealError):
    """Base for key-related problems."""


# Backwards-compatible alias for the old (builtin-shadowing) name.
KeyError_ = KeyManagementError


class MasterKeyNotFoundError(KeyManagementError):
    """Raised when no master key can be located via any supported method."""


class PrivateKeyNotFoundError(KeyManagementError):
    """Raised when no recipient private key can be located via any supported method."""


class InvalidMasterKeyError(KeyManagementError):
    """Raised when a provided master key is malformed (wrong length/encoding)."""


class InvalidRecipientKeyError(KeyManagementError):
    """Raised when an X25519 recipient public/private key is malformed.

    Covers a missing ``dsk-pub-``/``dsk-prv-`` prefix, invalid base64, or the
    wrong decoded length for an X25519 key.
    """


class RecipientNotFoundError(KeyManagementError):
    """Raised when no recipient slot in a file matches the supplied private key."""


class KeyFingerprintMismatchError(DotsealError):
    """Raised when the key fingerprint in the file does not match the supplied key.

    This lets us fail fast with a helpful message *before* attempting to decrypt
    every value with an obviously-wrong key.
    """


class DecryptionError(DotsealError):
    """Raised when a value cannot be decrypted (bad key or tampered ciphertext)."""


class EncryptionError(DotsealError):
    """Raised when a value cannot be encrypted."""


class ParseError(DotsealError):
    """Raised when a .env / .env.enc file cannot be parsed."""


class KeyNotFoundError(DotsealError):
    """Raised when a requested variable name does not exist in the file."""
