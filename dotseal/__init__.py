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

from importlib.metadata import version as _pkg_version

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
    get_value,
    reencrypt_text,
    reencrypt_text_asymmetric,
    remove_recipient_from_text,
    resolve_master_key,
    resolve_private_key,
    set_value,
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
    KeyManagementError,
    KeyNotFoundError,
    MasterKeyNotFoundError,
    ParseError,
    PrivateKeyNotFoundError,
    RecipientNotFoundError,
)
from .loader import load_env

__version__ = _pkg_version("dotseal")

__all__ = [
    "ENV_VAR_NAME",
    "KEY_FILE_NAME",
    "PRIVATE_ENV_VAR_NAME",
    "PRIVATE_KEY_FILE_NAME",
    "DecryptionError",
    "DotsealError",
    "EncryptionError",
    "InvalidMasterKeyError",
    "InvalidRecipientKeyError",
    "KeyFingerprintMismatchError",
    "KeyManagementError",
    "KeyNotFoundError",
    "MasterKeyNotFoundError",
    "ParseError",
    "PrivateKeyNotFoundError",
    "RecipientNotFoundError",
    "__version__",
    "add_recipient_to_text",
    "decrypt_text",
    "decrypt_text_asymmetric",
    "decrypt_to_dict",
    "decrypt_to_dict_asymmetric",
    "encrypt_text",
    "encrypt_text_asymmetric",
    "file_mode",
    "generate_master_key",
    "generate_recipient_keypair",
    "get_value",
    "key_fingerprint",
    "load_env",
    "load_key_bytes",
    "public_key_str_from_private",
    "recipient_fingerprint",
    "reencrypt_text",
    "reencrypt_text_asymmetric",
    "remove_recipient_from_text",
    "resolve_master_key",
    "resolve_private_key",
    "set_value",
]
