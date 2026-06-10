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
    decrypt_text,
    decrypt_to_dict,
    encrypt_text,
    resolve_master_key,
)
from .crypto import generate_master_key, key_fingerprint, load_key_bytes
from .exceptions import (
    DecryptionError,
    EncryptionError,
    InvalidMasterKeyError,
    KeyFingerprintMismatchError,
    MasterKeyNotFoundError,
    ParseError,
    DotsealError,
)
from .loader import load_env

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "load_env",
    "encrypt_text",
    "decrypt_text",
    "decrypt_to_dict",
    "generate_master_key",
    "resolve_master_key",
    "load_key_bytes",
    "key_fingerprint",
    "ENV_VAR_NAME",
    "KEY_FILE_NAME",
    "DotsealError",
    "MasterKeyNotFoundError",
    "InvalidMasterKeyError",
    "KeyFingerprintMismatchError",
    "DecryptionError",
    "EncryptionError",
    "ParseError",
]
