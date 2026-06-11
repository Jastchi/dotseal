"""Runtime loader: decrypt an ``.env.enc`` into ``os.environ`` with no disk write.

This is the import-time companion to the CLI and a drop-in replacement for
``python-dotenv``'s ``load_dotenv``: call :func:`load_env` early in startup to
make your (encrypted) secrets available via ``os.environ`` / ``os.getenv``
without ever materializing a cleartext file.
"""

from __future__ import annotations

import os
from typing import Optional

from . import core, crypto
from .exceptions import MasterKeyNotFoundError, DotsealError


def load_env(
    dotenv_path: str = ".env.enc",
    *,
    master_key: Optional[str] = None,
    private_key: Optional[str] = None,
    override: bool = False,
    encoding: str = "utf-8",
) -> bool:
    """Decrypt ``dotenv_path`` in memory and inject the values into ``os.environ``.

    Mirrors ``python-dotenv``'s ``load_dotenv`` so it can be used as a drop-in
    replacement, but reads a structurally-encrypted ``.env.enc`` file. The
    encryption mode (symmetric master key vs. asymmetric X25519 recipients) is
    auto-detected from the file's metadata.

    Args:
        dotenv_path: path to the encrypted env file (default ``".env.enc"``).
        master_key: base64 master key for symmetric files. If ``None``, it is
            resolved from the ``DOTSEAL_MASTER_KEY`` env var or a local key file.
        private_key: ``dsk-prv-...`` recipient private key for asymmetric files.
            If ``None``, it is resolved from the ``DOTSEAL_PRIVATE_KEY`` env var
            or a local ``.dotseal.prv`` file.
        override: if ``False`` (default), variables already present in
            ``os.environ`` are left untouched (the process environment wins,
            which matches typical 12-factor behavior). If ``True``, decrypted
            values overwrite existing ones.
        encoding: text encoding used to read the file.

    Returns:
        ``True`` if at least one variable was set in ``os.environ``, else
        ``False`` (matching ``load_dotenv``). To get the decrypted values back
        as a mapping instead, use :func:`dotseal.decrypt_to_dict`.

    Raises:
        FileNotFoundError: if ``dotenv_path`` does not exist.
        MasterKeyNotFoundError / PrivateKeyNotFoundError / DecryptionError /
        KeyFingerprintMismatchError / RecipientNotFoundError:
            on key resolution or decryption problems.
    """
    if not os.path.isfile(dotenv_path):
        raise FileNotFoundError(f"Encrypted env file not found: {dotenv_path}")

    search_dir = os.path.dirname(os.path.abspath(dotenv_path))
    with open(dotenv_path, "r", encoding=encoding) as fh:
        text = fh.read()

    if core.file_mode(text) == "asymmetric":
        priv = core.resolve_private_key(private_key, search_dir=search_dir)
        values = core.decrypt_to_dict_asymmetric(text, priv)
    else:
        key_str = core.resolve_master_key(master_key, search_dir=search_dir)
        key_bytes = bytearray(crypto.load_key_bytes(key_str))
        try:
            values = core.decrypt_to_dict(text, bytes(key_bytes))
        finally:
            crypto._zero(key_bytes)

    set_any = False
    for name, value in values.items():
        if override or name not in os.environ:
            os.environ[name] = value
            set_any = True

    return set_any


__all__ = [
    "load_env",
    "MasterKeyNotFoundError",
    "DotsealError",
]
