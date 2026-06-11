"""Custom exception hierarchy for dotseal.

These exceptions exist so that failures surface as clear, actionable messages
instead of leaking raw cryptographic tracebacks (which are both confusing and a
minor information-leak risk) to end users.
"""

from __future__ import annotations


class DotsealError(Exception):
    """Base class for all dotseal errors."""


class KeyError_(DotsealError):
    """Base for key-related problems."""


class MasterKeyNotFoundError(KeyError_):
    """Raised when no master key can be located via any supported method."""


class PrivateKeyNotFoundError(KeyError_):
    """Raised when no recipient private key can be located via any supported method."""


class InvalidMasterKeyError(KeyError_):
    """Raised when a provided master key is malformed (wrong length/encoding)."""


class InvalidRecipientKeyError(KeyError_):
    """Raised when an X25519 recipient public/private key is malformed.

    Covers a missing ``dsk-pub-``/``dsk-prv-`` prefix, invalid base64, or the
    wrong decoded length for an X25519 key.
    """


class RecipientNotFoundError(KeyError_):
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
