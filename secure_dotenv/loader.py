"""Runtime loader: decrypt an ``.env.enc`` into ``os.environ`` with no disk write.

This is the import-time companion to the CLI. Applications call
:func:`load_secure_dotenv` early in startup to make their secrets available via
``os.environ`` / ``os.getenv`` without ever materializing a cleartext file.
"""

from __future__ import annotations

import os
from typing import Dict, Optional

from . import core, crypto
from .exceptions import MasterKeyNotFoundError, SecureDotenvError


def load_secure_dotenv(
    enc_file_path: str = ".env.enc",
    master_key: Optional[str] = None,
    *,
    override: bool = False,
) -> Dict[str, str]:
    """Decrypt ``enc_file_path`` in memory and inject the values into ``os.environ``.

    Args:
        enc_file_path: path to the encrypted env file.
        master_key: base64 master key. If ``None``, it is resolved from the
            ``SECURE_DOTENV_MASTER_KEY`` env var or a local key file.
        override: if ``False`` (default), variables already present in
            ``os.environ`` are left untouched (the process environment wins,
            which matches typical 12-factor behavior). If ``True``, decrypted
            values overwrite existing ones.

    Returns:
        A mapping of the variables that were loaded from the file (the full
        decrypted set, regardless of whether each one was injected).

    Raises:
        FileNotFoundError: if ``enc_file_path`` does not exist.
        MasterKeyNotFoundError / DecryptionError / KeyFingerprintMismatchError:
            on key resolution or decryption problems.
    """
    if not os.path.isfile(enc_file_path):
        raise FileNotFoundError(f"Encrypted env file not found: {enc_file_path}")

    key_str = core.resolve_master_key(
        master_key, search_dir=os.path.dirname(os.path.abspath(enc_file_path))
    )
    key_bytes = bytearray(crypto.load_key_bytes(key_str))

    with open(enc_file_path, "r", encoding="utf-8") as fh:
        text = fh.read()

    try:
        values = core.decrypt_to_dict(text, bytes(key_bytes))
    finally:
        crypto._zero(key_bytes)

    for name, value in values.items():
        if override or name not in os.environ:
            os.environ[name] = value

    return values


__all__ = [
    "load_secure_dotenv",
    "MasterKeyNotFoundError",
    "SecureDotenvError",
]
