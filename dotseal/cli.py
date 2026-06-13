"""Command-line interface for dotseal (built on argparse, no extra deps).

Commands:
    init                     create a master key + gitignore it (symmetric)
    keygen                   create an X25519 recipient key pair (asymmetric)
    encrypt [in] [out]       .env      -> .env.enc
    decrypt [in] [out]       .env.enc  -> .env  (auto-detects sym/asym)
    edit [file]              decrypt -> $EDITOR -> re-encrypt (sops-style)
    add-recipient <pub>      grant a new recipient access to a file
    rm-recipient <pub|fp>    revoke a recipient's slot from a file
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import shlex
import subprocess
import sys
import tempfile
from typing import List, Optional

from . import __version__, core, crypto, parser
from .exceptions import DotsealError, KeyNotFoundError

_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*$")

_GITIGNORE_NOTE = "# Added by `dotseal init` -- never commit your master key"


# --- small IO helpers -------------------------------------------------------

def _read(path: str) -> str:
    if not os.path.isfile(path):
        raise DotsealError(f"Input file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _err(msg: str) -> None:
    print(f"dotseal: error: {msg}", file=sys.stderr)


def _warn(msg: str) -> None:
    print(f"dotseal: warning: {msg}", file=sys.stderr)


def _warn_plain_keys_already_encrypted(
    text: str,
    plain_keys: Optional[List[str]],
) -> None:
    """Warn when --plain-key names a value that is already ENC[...].

    encrypt_text is idempotent on ciphertext, so the value won't be unsealed
    by this run — only the footer policy changes.  Without this warning the
    user might not realise that the next `dotseal edit` will write that value
    as cleartext once the footer policy is inherited.
    """
    if not plain_keys:
        return
    parsed = parser.parse(text)
    already_enc = sorted(
        k for k in plain_keys
        if any(
            r.kind == "entry" and r.key == k and crypto.is_encrypted_value(r.value)
            for r in parsed.records
        )
    )
    if already_enc:
        _warn(
            "--plain-key has no effect on already-encrypted values: "
            + ", ".join(already_enc)
            + "; use 'dotseal edit --plain-key' to unseal"
        )


def _warn_policy_override(
    original_text: str,
    cleartext: str,
    *,
    plain_keys: Optional[List[str]],
    plain_key_regex: Optional[List[str]],
) -> None:
    if plain_keys is None and plain_key_regex is None:
        return
    keys = core.keys_newly_sealed_by_policy_override(
        parser.parse(original_text),
        parser.parse(cleartext),
        plain_keys=plain_keys,
        plain_key_regex=plain_key_regex,
    )
    if keys:
        _warn(
            "policy override will seal previously plaintext keys: "
            + ", ".join(keys)
        )


def _resolve_key_bytes(args: argparse.Namespace, *, search_dir: str) -> bytes:
    key_str = core.resolve_master_key(
        getattr(args, "key", None),
        key_file=getattr(args, "key_file", None),
        search_dir=search_dir,
    )
    return crypto.load_key_bytes(key_str)


def _resolve_private_key(args: argparse.Namespace, *, search_dir: str) -> str:
    return core.resolve_private_key(
        getattr(args, "private_key", None),
        key_file=getattr(args, "private_key_file", None),
        search_dir=search_dir,
    )


def _collect_recipients(args: argparse.Namespace) -> List[str]:
    """Gather recipient public keys from --recipient and --recipients-file."""
    recipients: List[str] = list(getattr(args, "recipient", None) or [])
    recipients_file = getattr(args, "recipients_file", None)
    if recipients_file:
        if not os.path.isfile(recipients_file):
            raise DotsealError(f"Recipients file not found: {recipients_file}")
        with open(recipients_file, "r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    recipients.append(stripped)
    return recipients


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

def _gitignore_covers(content: str, name: str) -> bool:
    """True if the .gitignore ``content`` leaves ``name`` ignored.

    Lines are evaluated in order so a later ``!name`` negation re-includes the
    file, mirroring git's last-match-wins rule. Only exact entries and simple
    glob patterns (e.g. ``*.key``) are recognized.
    """
    covered = False
    for line in content.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        negated = entry.startswith("!")
        if negated:
            entry = entry[1:].strip()
        entry = entry.rstrip("/").lstrip("/")
        if entry and (entry == name or fnmatch.fnmatch(name, entry)):
            covered = not negated
    return covered


def _ensure_gitignored(name: str, directory: str) -> str:
    """Make sure ``name`` is ignored by git. Returns a human-readable status."""
    gitignore = os.path.join(directory, ".gitignore")
    if os.path.isfile(gitignore):
        with open(gitignore, "r", encoding="utf-8") as fh:
            content = fh.read()
        if _gitignore_covers(content, name):
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


def cmd_keygen(args: argparse.Namespace) -> int:
    private_str, public_str = crypto.generate_recipient_keypair()
    fingerprint = crypto.recipient_fingerprint(public_str)

    if args.print:
        # Print both halves to stdout; nothing written to disk.
        print(private_str)
        print(public_str)
        return 0

    directory = os.getcwd()
    out_path = args.out or os.path.join(directory, core.PRIVATE_KEY_FILE_NAME)

    if os.path.exists(out_path) and not args.force:
        _err(
            f"{out_path} already exists. Refusing to overwrite "
            "(use --force to replace it)."
        )
        return 1

    core.write_secret_file(out_path, private_str + "\n", mode=0o600)
    # Only auto-gitignore when the key lands in the current directory.
    gitignore_status = None
    if os.path.dirname(os.path.abspath(out_path)) == os.path.abspath(directory):
        gitignore_status = _ensure_gitignored(os.path.basename(out_path), directory)

    print(f"Created private key: {out_path} (mode 0600)")
    if gitignore_status:
        print(f"gitignore:           {gitignore_status}")
    print(f"Fingerprint:         {fingerprint}")
    print()
    print("Share your PUBLIC key (safe to commit) so others can encrypt for you:")
    print(f"  {public_str}")
    print()
    print("Encrypt for recipients with:")
    print(f"  dotseal encrypt --recipient {public_str} [--recipient ...]")
    return 0


def cmd_encrypt(args: argparse.Namespace) -> int:
    text = _read(args.input)
    search_dir = os.path.dirname(os.path.abspath(args.input))
    recipients = _collect_recipients(args)
    plain_keys = getattr(args, "plain_key", None)
    plain_key_regex = getattr(args, "plain_key_regex", None)
    _warn_policy_override(
        text,
        text,
        plain_keys=plain_keys,
        plain_key_regex=plain_key_regex,
    )
    _warn_plain_keys_already_encrypted(text, plain_keys)

    if recipients:
        out = core.encrypt_text_asymmetric(
            text,
            recipients,
            plain_keys=plain_keys,
            plain_key_regex=plain_key_regex,
        )
        mode_note = f"{len(recipients)} recipient(s)"
    else:
        out = core.encrypt_text(
            text,
            _resolve_key_bytes(args, search_dir=search_dir),
            plain_keys=plain_keys,
            plain_key_regex=plain_key_regex,
        )
        mode_note = "symmetric"

    # .env.enc is safe to commit -> default permissions are fine.
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(out)
    print(f"Encrypted {args.input} -> {args.output} ({mode_note})")
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    text = _read(args.input)
    search_dir = os.path.dirname(os.path.abspath(args.input))

    if core.file_mode(text) == "asymmetric":
        private_key = _resolve_private_key(args, search_dir=search_dir)
        out = core.decrypt_text_asymmetric(text, private_key)
    else:
        out = core.decrypt_text(text, _resolve_key_bytes(args, search_dir=search_dir))
    # Cleartext output contains secrets -> owner-only perms.
    core.write_secret_file(args.output, out, mode=0o600)
    print(f"Decrypted {args.input} -> {args.output} (mode 0600)")
    return 0


def _ask_reopen_editor() -> bool:
    """Ask (interactively) whether to re-open the editor after a failure."""
    try:
        answer = input("Re-open the editor to fix it? [Y/n] ")
    except EOFError:
        return False
    return not answer.strip().lower().startswith("n")


def cmd_edit(args: argparse.Namespace) -> int:
    search_dir = os.path.dirname(os.path.abspath(args.input))
    original_text = None
    is_asym = False
    recipients: List[str] = []

    if os.path.isfile(args.input):
        original_text = _read(args.input)
        is_asym = core.file_mode(original_text) == "asymmetric"
        if is_asym:
            private_key = _resolve_private_key(args, search_dir=search_dir)
            cleartext = core.decrypt_text_asymmetric(original_text, private_key)
        else:
            cleartext = core.decrypt_text(
                original_text, _resolve_key_bytes(args, search_dir=search_dir)
            )
    else:
        # Allow creating a new encrypted file by editing from scratch.
        recipients = _collect_recipients(args)
        is_asym = bool(recipients)
        if not is_asym:
            # Fail fast (missing/invalid key) before the user invests editing time.
            _resolve_key_bytes(args, search_dir=search_dir)
        cleartext = "# New encrypted env file. Add KEY=value lines.\n"

    fd, tmp_path = tempfile.mkstemp(suffix=".env", prefix=".dotseal-edit-")
    keep_tmp = False
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(cleartext)

        editor = os.environ.get("EDITOR", "nano")
        editor_cmd = shlex.split(editor)
        while True:
            try:
                result = subprocess.run(editor_cmd + [tmp_path])
            except FileNotFoundError:
                _err(f"Editor not found: {editor!r}. Set $EDITOR to a valid editor.")
                return 1
            if result.returncode != 0:
                _err(f"Editor exited with status {result.returncode}; aborting (no changes saved).")
                return 1

            with open(tmp_path, "r", encoding="utf-8") as fh:
                edited = fh.read()

            if edited == cleartext:
                if original_text is not None:
                    print(f"No changes; {args.input} left untouched.")
                else:
                    print(f"No changes; {args.input} was not created.")
                return 0

            plain_keys = getattr(args, "plain_key", None)
            plain_key_regex = getattr(args, "plain_key_regex", None)
            if original_text is not None:
                _warn_policy_override(
                    original_text,
                    edited,
                    plain_keys=plain_keys,
                    plain_key_regex=plain_key_regex,
                )

            try:
                if is_asym and original_text is not None:
                    # Re-encrypt reusing the original DEK + recipients (only our key needed).
                    private_key = _resolve_private_key(args, search_dir=search_dir)
                    out = core.reencrypt_text_asymmetric(
                        edited,
                        private_key,
                        original_text,
                        plain_keys=plain_keys,
                        plain_key_regex=plain_key_regex,
                    )
                elif is_asym:
                    out = core.encrypt_text_asymmetric(
                        edited,
                        recipients,
                        plain_keys=plain_keys,
                        plain_key_regex=plain_key_regex,
                    )
                else:
                    key_bytes = _resolve_key_bytes(args, search_dir=search_dir)
                    if original_text is not None:
                        # Unchanged values keep their ciphertext (diff-friendly).
                        out = core.reencrypt_text(
                            edited,
                            key_bytes,
                            original_text,
                            plain_keys=plain_keys,
                            plain_key_regex=plain_key_regex,
                        )
                    else:
                        out = core.encrypt_text(
                            edited,
                            key_bytes,
                            plain_keys=plain_keys,
                            plain_key_regex=plain_key_regex,
                        )
                break
            except DotsealError as exc:
                # Never throw the user's edits away over a typo: offer to
                # re-open the editor; otherwise preserve the temp file.
                _err(f"could not re-encrypt your edits: {exc}")
                if sys.stdin.isatty() and _ask_reopen_editor():
                    continue
                keep_tmp = True
                _err(
                    f"your edits were kept at {tmp_path} (mode 0600). Fix the "
                    f"problem, re-run `dotseal edit`, and delete that file."
                )
                return 1

        with open(args.input, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"Saved encrypted changes to {args.input}")
        return 0
    finally:
        if not keep_tmp:
            _secure_delete(tmp_path)


def cmd_add_recipient(args: argparse.Namespace) -> int:
    text = _read(args.file)
    search_dir = os.path.dirname(os.path.abspath(args.file))
    if core.file_mode(text) != "asymmetric":
        _err(
            f"{args.file} is not an asymmetric (multi-recipient) file. "
            "Recipients only apply to files encrypted with --recipient."
        )
        return 1
    private_key = _resolve_private_key(args, search_dir=search_dir)
    out = core.add_recipient_to_text(text, private_key, args.public_key)
    with open(args.file, "w", encoding="utf-8") as fh:
        fh.write(out)
    fp = crypto.recipient_fingerprint(args.public_key)
    print(f"Added recipient {fp} to {args.file}")
    return 0


def cmd_rm_recipient(args: argparse.Namespace) -> int:
    text = _read(args.file)
    if core.file_mode(text) != "asymmetric":
        _err(
            f"{args.file} is not an asymmetric (multi-recipient) file."
        )
        return 1
    out = core.remove_recipient_from_text(text, args.identifier)
    with open(args.file, "w", encoding="utf-8") as fh:
        fh.write(out)
    print(f"Removed recipient {args.identifier} from {args.file}")
    print(
        "Note: the data key was not rotated; the removed recipient can still "
        "decrypt older committed versions. Re-encrypt from cleartext to fully revoke."
    )
    return 0


def cmd_get(args: argparse.Namespace) -> int:
    text = _read(args.file)
    search_dir = os.path.dirname(os.path.abspath(args.file))
    try:
        if core.file_mode(text) == "asymmetric":
            private_key = _resolve_private_key(args, search_dir=search_dir)
            value = core.get_value(text, args.variable, private_key=private_key)
        else:
            key_bytes = _resolve_key_bytes(args, search_dir=search_dir)
            value = core.get_value(text, args.variable, key_bytes=key_bytes)
    except KeyNotFoundError:
        if args.default is not None:
            sys.stdout.write(args.default)
            return 0
        raise
    sys.stdout.write(value)
    return 0


def cmd_set(args: argparse.Namespace) -> int:
    if "=" not in args.assignment:
        _err("set: argument must be in KEY=VALUE form")
        return 1
    key, _, value = args.assignment.partition("=")
    if not _KEY_RE.match(key):
        _err(f"set: {key!r} is not a valid variable name (must match [A-Za-z_][A-Za-z0-9_.]*)")
        return 1
    text = _read(args.file)
    search_dir = os.path.dirname(os.path.abspath(args.file))
    if core.file_mode(text) == "asymmetric":
        private_key = _resolve_private_key(args, search_dir=search_dir)
        out = core.set_value(text, key, value, private_key=private_key)
    else:
        key_bytes = _resolve_key_bytes(args, search_dir=search_dir)
        out = core.set_value(text, key, value, key_bytes=key_bytes)
    with open(args.file, "w", encoding="utf-8") as fh:
        fh.write(out)
    return 0


# --- argument parsing -------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dotseal",
        description="Git-friendly encrypted .env manager with cleartext keys and sealed values.",
    )
    parser.add_argument("--version", action="version", version=f"dotseal {__version__}")

    def add_key_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("-k", "--key", help="Master key (base64). Overrides env var and key file.")
        p.add_argument("--key-file", help=f"Path to a key file (default: discover {core.KEY_FILE_NAME}).")

    def add_private_key_args(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--private-key",
            help="Recipient private key (dsk-prv-...). Overrides env var and key file.",
        )
        p.add_argument(
            "--private-key-file",
            help=f"Path to a private key file (default: discover {core.PRIVATE_KEY_FILE_NAME}).",
        )

    def add_recipient_args(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "-r",
            "--recipient",
            action="append",
            metavar="PUBKEY",
            help="Recipient public key (dsk-pub-...). Repeatable. Enables asymmetric mode.",
        )
        p.add_argument(
            "--recipients-file",
            help="File listing one recipient public key per line (# comments allowed).",
        )

    def add_selective_encryption_args(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--plain-key",
            action="append",
            metavar="KEY",
            help="Keep this key unencrypted (repeatable).",
        )
        p.add_argument(
            "--plain-key-regex",
            action="append",
            metavar="REGEX",
            help="Keep keys matching this regex unencrypted (repeatable, fullmatch).",
        )

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Generate a master key and gitignore it (symmetric).")
    p_init.add_argument("--force", action="store_true", help="Overwrite an existing key file.")
    p_init.set_defaults(func=cmd_init)

    p_keygen = sub.add_parser(
        "keygen", help="Generate an X25519 recipient key pair (asymmetric)."
    )
    p_keygen.add_argument(
        "--out", help=f"Path to write the private key (default: {core.PRIVATE_KEY_FILE_NAME})."
    )
    p_keygen.add_argument("--force", action="store_true", help="Overwrite an existing private key file.")
    p_keygen.add_argument(
        "--print",
        action="store_true",
        help="Print private + public keys to stdout instead of writing to disk.",
    )
    p_keygen.set_defaults(func=cmd_keygen)

    p_enc = sub.add_parser("encrypt", help="Encrypt a cleartext .env into .env.enc.")
    p_enc.add_argument("input", nargs="?", default=".env")
    p_enc.add_argument("output", nargs="?", default=".env.enc")
    add_key_args(p_enc)
    add_recipient_args(p_enc)
    add_selective_encryption_args(p_enc)
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="Decrypt .env.enc into a cleartext .env (auto-detects mode).")
    p_dec.add_argument("input", nargs="?", default=".env.enc")
    p_dec.add_argument("output", nargs="?", default=".env")
    add_key_args(p_dec)
    add_private_key_args(p_dec)
    p_dec.set_defaults(func=cmd_decrypt)

    p_get = sub.add_parser("get", help="Read one variable's value from an encrypted file.")
    p_get.add_argument("variable", metavar="KEY", help="Variable name to retrieve.")
    p_get.add_argument("file", nargs="?", default=".env.enc", metavar="FILE")
    p_get.add_argument(
        "--default",
        metavar="VAL",
        default=None,
        help="Value to emit (and exit 0) when the key is absent.",
    )
    add_key_args(p_get)
    add_private_key_args(p_get)
    p_get.set_defaults(func=cmd_get)

    p_set = sub.add_parser("set", help="Add or replace one variable in an encrypted file.")
    p_set.add_argument(
        "assignment",
        metavar="KEY=VALUE",
        help="Assignment in KEY=VALUE form (shell quoting applies).",
    )
    p_set.add_argument("file", nargs="?", default=".env.enc", metavar="FILE")
    add_key_args(p_set)
    add_private_key_args(p_set)
    p_set.set_defaults(func=cmd_set)

    p_edit = sub.add_parser("edit", help="Decrypt, open $EDITOR, then re-encrypt (sops-style).")
    p_edit.add_argument("input", nargs="?", default=".env.enc")
    add_key_args(p_edit)
    add_private_key_args(p_edit)
    add_recipient_args(p_edit)
    add_selective_encryption_args(p_edit)
    p_edit.set_defaults(func=cmd_edit)

    p_add = sub.add_parser(
        "add-recipient", help="Grant a new recipient access to an asymmetric file."
    )
    p_add.add_argument("public_key", metavar="PUBKEY", help="Recipient public key (dsk-pub-...).")
    p_add.add_argument("file", nargs="?", default=".env.enc")
    add_private_key_args(p_add)
    p_add.set_defaults(func=cmd_add_recipient)

    p_rm = sub.add_parser(
        "rm-recipient", help="Revoke a recipient slot from an asymmetric file."
    )
    p_rm.add_argument(
        "identifier", metavar="PUBKEY_OR_FP", help="Recipient public key or fingerprint."
    )
    p_rm.add_argument("file", nargs="?", default=".env.enc")
    p_rm.set_defaults(func=cmd_rm_recipient)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except DotsealError as exc:
        _err(str(exc))
        return 1
    except KeyboardInterrupt:  # pragma: no cover
        _err("interrupted")
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
