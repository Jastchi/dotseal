"""dotseal: Git-friendly encrypted env var manager with cleartext keys and sealed values.

Public API
----------
* :func:`load_env` -- runtime loader (decrypt into ``os.environ``); drop-in for
  ``python-dotenv``'s ``load_dotenv``.
* :func:`encrypt_text` / :func:`decrypt_text` -- whole-file transforms.
* :func:`decrypt_to_dict` -- decrypt into a mapping, in memory.
* :func:`generate_master_key` / :func:`resolve_master_key` -- key helpers.
* The exception hierarchy rooted at :class:`DotsealError`.
"""

from __future__ import annotations

from .core import (
    ENV_VAR_NAME,
    KEY_FILE_NAME,
    PRIVATE_ENV_VAR_NAME,
    PRIVATE_KEY_FILE_NAME,
    add_recipient_to_text,
    decrypt_text,
    decrypt_text_asymmetric,
    decrypt_to_dict,
    decrypt_to_dict_asymmetric,
    encrypt_text,
    encrypt_text_asymmetric,
    file_mode,
    remove_recipient_from_text,
    resolve_master_key,
    resolve_private_key,
)
from .crypto import (
    generate_master_key,
    generate_recipient_keypair,
    key_fingerprint,
    load_key_bytes,
    public_key_str_from_private,
    recipient_fingerprint,
)
from .exceptions import (
    DecryptionError,
    DotsealError,
    EncryptionError,
    InvalidMasterKeyError,
    InvalidRecipientKeyError,
    KeyFingerprintMismatchError,
    MasterKeyNotFoundError,
    ParseError,
    PrivateKeyNotFoundError,
    RecipientNotFoundError,
)
from .loader import load_env

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "load_env",
    "encrypt_text",
    "decrypt_text",
    "decrypt_to_dict",
    "encrypt_text_asymmetric",
    "decrypt_text_asymmetric",
    "decrypt_to_dict_asymmetric",
    "add_recipient_to_text",
    "remove_recipient_from_text",
    "file_mode",
    "generate_master_key",
    "generate_recipient_keypair",
    "resolve_master_key",
    "resolve_private_key",
    "load_key_bytes",
    "key_fingerprint",
    "recipient_fingerprint",
    "public_key_str_from_private",
    "ENV_VAR_NAME",
    "KEY_FILE_NAME",
    "PRIVATE_ENV_VAR_NAME",
    "PRIVATE_KEY_FILE_NAME",
    "DotsealError",
    "MasterKeyNotFoundError",
    "PrivateKeyNotFoundError",
    "InvalidMasterKeyError",
    "InvalidRecipientKeyError",
    "KeyFingerprintMismatchError",
    "RecipientNotFoundError",
    "DecryptionError",
    "EncryptionError",
    "ParseError",
]
