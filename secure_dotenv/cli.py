"""Command-line interface for secure-dotenv (built on argparse, no extra deps).

Commands:
    init                     create a master key + gitignore it
    encrypt [in] [out]       .env      -> .env.enc
    decrypt [in] [out]       .env.enc  -> .env
    edit [file]              decrypt -> $EDITOR -> re-encrypt (sops-style)
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import tempfile
from typing import List, Optional

from . import __version__, core, crypto
from .exceptions import SecureDotenvError

_GITIGNORE_NOTE = "# Added by `secure-dotenv init` -- never commit your master key"


# --- small IO helpers -------------------------------------------------------

def _read(path: str) -> str:
    if not os.path.isfile(path):
        raise SecureDotenvError(f"Input file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _err(msg: str) -> None:
    print(f"secure-dotenv: error: {msg}", file=sys.stderr)


def _resolve_key_bytes(args: argparse.Namespace, *, search_dir: str) -> bytes:
    key_str = core.resolve_master_key(
        getattr(args, "key", None),
        key_file=getattr(args, "key_file", None),
        search_dir=search_dir,
    )
    return crypto.load_key_bytes(key_str)


def _secure_delete(path: str) -> None:
    """Best-effort secure delete: overwrite then unlink."""
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as fh:
            fh.write(b"\x00" * size)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


# --- gitignore handling -----------------------------------------------------

def _ensure_gitignored(name: str, directory: str) -> str:
    """Make sure ``name`` is ignored by git. Returns a human-readable status."""
    gitignore = os.path.join(directory, ".gitignore")
    if os.path.isfile(gitignore):
        with open(gitignore, "r", encoding="utf-8") as fh:
            content = fh.read()
        if any(line.strip() == name for line in content.splitlines()):
            return f"{name} already present in .gitignore"
        sep = "" if content.endswith("\n") or content == "" else "\n"
        with open(gitignore, "a", encoding="utf-8") as fh:
            fh.write(f"{sep}{_GITIGNORE_NOTE}\n{name}\n")
        return f"appended {name} to existing .gitignore"
    with open(gitignore, "w", encoding="utf-8") as fh:
        fh.write(f"{_GITIGNORE_NOTE}\n{name}\n")
    return f"created .gitignore and added {name}"


# --- commands ---------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> int:
    directory = os.getcwd()
    key_path = os.path.join(directory, core.KEY_FILE_NAME)

    if os.path.exists(key_path) and not args.force:
        _err(
            f"{core.KEY_FILE_NAME} already exists. Refusing to overwrite "
            "(use --force to replace it -- this will make existing .env.enc "
            "files undecryptable)."
        )
        return 1

    key_str = crypto.generate_master_key()
    core.write_secret_file(key_path, key_str + "\n", mode=0o600)
    fingerprint = crypto.key_fingerprint(crypto.load_key_bytes(key_str))
    gitignore_status = _ensure_gitignored(core.KEY_FILE_NAME, directory)

    print(f"Created master key: {key_path} (mode 0600)")
    print(f"Key fingerprint:    {fingerprint}")
    print(f"gitignore:          {gitignore_status}")
    print()
    print("To use this key in CI/containers instead of the file, export:")
    print(f"  export {core.ENV_VAR_NAME}=$(cat {core.KEY_FILE_NAME})")
    return 0


def cmd_encrypt(args: argparse.Namespace) -> int:
    text = _read(args.input)
    key_bytes = bytearray(_resolve_key_bytes(args, search_dir=os.path.dirname(os.path.abspath(args.input))))
    try:
        out = core.encrypt_text(text, bytes(key_bytes))
    finally:
        crypto._zero(key_bytes)
    # .env.enc is safe to commit -> default permissions are fine.
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(out)
    print(f"Encrypted {args.input} -> {args.output}")
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    text = _read(args.input)
    key_bytes = bytearray(_resolve_key_bytes(args, search_dir=os.path.dirname(os.path.abspath(args.input))))
    try:
        out = core.decrypt_text(text, bytes(key_bytes))
    finally:
        crypto._zero(key_bytes)
    # Cleartext output contains secrets -> owner-only perms.
    core.write_secret_file(args.output, out, mode=0o600)
    print(f"Decrypted {args.input} -> {args.output} (mode 0600)")
    return 0


def cmd_edit(args: argparse.Namespace) -> int:
    search_dir = os.path.dirname(os.path.abspath(args.input))
    if os.path.isfile(args.input):
        text = _read(args.input)
        key_bytes = bytearray(_resolve_key_bytes(args, search_dir=search_dir))
        try:
            cleartext = core.decrypt_text(text, bytes(key_bytes))
        finally:
            crypto._zero(key_bytes)
    else:
        # Allow creating a new encrypted file by editing from scratch.
        key_bytes = bytearray(_resolve_key_bytes(args, search_dir=search_dir))
        crypto._zero(key_bytes)
        cleartext = "# New encrypted env file. Add KEY=value lines.\n"

    fd, tmp_path = tempfile.mkstemp(suffix=".env", prefix=".secure-dotenv-edit-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(cleartext)

        editor = os.environ.get("EDITOR", "nano")
        cmd = shlex.split(editor) + [tmp_path]
        try:
            result = subprocess.run(cmd)
        except FileNotFoundError:
            _err(f"Editor not found: {editor!r}. Set $EDITOR to a valid editor.")
            return 1
        if result.returncode != 0:
            _err(f"Editor exited with status {result.returncode}; aborting (no changes saved).")
            return 1

        with open(tmp_path, "r", encoding="utf-8") as fh:
            edited = fh.read()

        key_bytes = bytearray(_resolve_key_bytes(args, search_dir=search_dir))
        try:
            out = core.encrypt_text(edited, bytes(key_bytes))
        finally:
            crypto._zero(key_bytes)
        with open(args.input, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"Saved encrypted changes to {args.input}")
        return 0
    finally:
        _secure_delete(tmp_path)


# --- argument parsing -------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secure-dotenv",
        description="Offline-first, Git-friendly encrypted .env manager (SOPS-style structural encryption).",
    )
    parser.add_argument("--version", action="version", version=f"secure-dotenv {__version__}")

    def add_key_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("-k", "--key", help="Master key (base64). Overrides env var and key file.")
        p.add_argument("--key-file", help=f"Path to a key file (default: discover {core.KEY_FILE_NAME}).")

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Generate a master key and gitignore it.")
    p_init.add_argument("--force", action="store_true", help="Overwrite an existing key file.")
    p_init.set_defaults(func=cmd_init)

    p_enc = sub.add_parser("encrypt", help="Encrypt a cleartext .env into .env.enc.")
    p_enc.add_argument("input", nargs="?", default=".env")
    p_enc.add_argument("output", nargs="?", default=".env.enc")
    add_key_args(p_enc)
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="Decrypt .env.enc into a cleartext .env.")
    p_dec.add_argument("input", nargs="?", default=".env.enc")
    p_dec.add_argument("output", nargs="?", default=".env")
    add_key_args(p_dec)
    p_dec.set_defaults(func=cmd_decrypt)

    p_edit = sub.add_parser("edit", help="Decrypt, open $EDITOR, then re-encrypt (sops-style).")
    p_edit.add_argument("input", nargs="?", default=".env.enc")
    add_key_args(p_edit)
    p_edit.set_defaults(func=cmd_edit)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except SecureDotenvError as exc:
        _err(str(exc))
        return 1
    except KeyboardInterrupt:  # pragma: no cover
        _err("interrupted")
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
