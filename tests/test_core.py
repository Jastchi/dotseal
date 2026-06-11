import os
import stat

import pytest

from dotseal import core, crypto, parser
from dotseal.exceptions import (
    KeyFingerprintMismatchError,
    MasterKeyNotFoundError,
    PrivateKeyNotFoundError,
)


# --- find_key_file -----------------------------------------------------------

def test_find_key_file_returns_none_when_absent(tmp_path):
    assert core.find_key_file(str(tmp_path)) is None


def test_find_key_file_finds_in_start_dir(tmp_path):
    (tmp_path / core.KEY_FILE_NAME).write_text("key")
    assert core.find_key_file(str(tmp_path)) == str(tmp_path / core.KEY_FILE_NAME)


def test_find_key_file_walks_up_to_parent(tmp_path):
    (tmp_path / core.KEY_FILE_NAME).write_text("key")
    subdir = tmp_path / "sub" / "deep"
    subdir.mkdir(parents=True)
    assert core.find_key_file(str(subdir)) == str(tmp_path / core.KEY_FILE_NAME)


# --- resolve_master_key ------------------------------------------------------

def test_resolve_master_key_explicit_arg(monkeypatch):
    monkeypatch.delenv(core.ENV_VAR_NAME, raising=False)
    key = crypto.generate_master_key()
    assert core.resolve_master_key(key) == key


def test_resolve_master_key_strips_whitespace(monkeypatch):
    monkeypatch.delenv(core.ENV_VAR_NAME, raising=False)
    key = crypto.generate_master_key()
    assert core.resolve_master_key(f"  {key}  ") == key


def test_resolve_master_key_from_env_var(monkeypatch):
    key = crypto.generate_master_key()
    monkeypatch.setenv(core.ENV_VAR_NAME, key)
    assert core.resolve_master_key() == key


def test_resolve_master_key_env_var_whitespace_only_is_skipped(tmp_path, monkeypatch):
    key = crypto.generate_master_key()
    monkeypatch.setenv(core.ENV_VAR_NAME, "   ")
    key_path = tmp_path / core.KEY_FILE_NAME
    key_path.write_text(key + "\n")
    assert core.resolve_master_key(search_dir=str(tmp_path)) == key


def test_resolve_master_key_from_explicit_key_file(tmp_path, monkeypatch):
    monkeypatch.delenv(core.ENV_VAR_NAME, raising=False)
    key = crypto.generate_master_key()
    key_path = tmp_path / "mykey"
    key_path.write_text(key + "\n")
    assert core.resolve_master_key(key_file=str(key_path)) == key


def test_resolve_master_key_raises_when_nothing_found(tmp_path, monkeypatch):
    monkeypatch.delenv(core.ENV_VAR_NAME, raising=False)
    with pytest.raises(MasterKeyNotFoundError):
        core.resolve_master_key(search_dir=str(tmp_path))


# --- find_private_key_file ---------------------------------------------------

def test_find_private_key_file_returns_none_when_absent(tmp_path):
    assert core.find_private_key_file(str(tmp_path)) is None


def test_find_private_key_file_finds_in_start_dir(tmp_path):
    (tmp_path / core.PRIVATE_KEY_FILE_NAME).write_text("key")
    assert core.find_private_key_file(str(tmp_path)) == str(
        tmp_path / core.PRIVATE_KEY_FILE_NAME
    )


def test_find_private_key_file_walks_up_to_parent(tmp_path):
    (tmp_path / core.PRIVATE_KEY_FILE_NAME).write_text("key")
    subdir = tmp_path / "sub"
    subdir.mkdir()
    assert core.find_private_key_file(str(subdir)) == str(
        tmp_path / core.PRIVATE_KEY_FILE_NAME
    )


# --- resolve_private_key -----------------------------------------------------

def test_resolve_private_key_explicit_arg(monkeypatch):
    monkeypatch.delenv(core.PRIVATE_ENV_VAR_NAME, raising=False)
    priv, _ = crypto.generate_recipient_keypair()
    assert core.resolve_private_key(priv) == priv


def test_resolve_private_key_from_env_var(monkeypatch):
    priv, _ = crypto.generate_recipient_keypair()
    monkeypatch.setenv(core.PRIVATE_ENV_VAR_NAME, priv)
    assert core.resolve_private_key() == priv


def test_resolve_private_key_env_var_whitespace_only_is_skipped(tmp_path, monkeypatch):
    priv, _ = crypto.generate_recipient_keypair()
    monkeypatch.setenv(core.PRIVATE_ENV_VAR_NAME, "   ")
    key_path = tmp_path / core.PRIVATE_KEY_FILE_NAME
    key_path.write_text(priv + "\n")
    assert core.resolve_private_key(search_dir=str(tmp_path)) == priv


def test_resolve_private_key_from_explicit_key_file(tmp_path, monkeypatch):
    monkeypatch.delenv(core.PRIVATE_ENV_VAR_NAME, raising=False)
    priv, _ = crypto.generate_recipient_keypair()
    key_path = tmp_path / "mypriv"
    key_path.write_text(priv + "\n")
    assert core.resolve_private_key(key_file=str(key_path)) == priv


def test_resolve_private_key_raises_when_nothing_found(tmp_path, monkeypatch):
    monkeypatch.delenv(core.PRIVATE_ENV_VAR_NAME, raising=False)
    with pytest.raises(PrivateKeyNotFoundError):
        core.resolve_private_key(search_dir=str(tmp_path))


# --- parse_metadata / parse_recipients ---------------------------------------

def test_parse_metadata_returns_empty_for_plain_file():
    parsed = parser.parse("FOO=bar\n")
    assert core.parse_metadata(parsed) == {}


def test_parse_metadata_skips_recipient_lines():
    text = "# dotseal:recipient fp=abc ephem=def enc=ghi\nFOO=bar\n"
    parsed = parser.parse(text)
    assert core.parse_metadata(parsed) == {}


def test_parse_recipients_returns_empty_for_plain_file():
    parsed = parser.parse("FOO=bar\n")
    assert core.parse_recipients(parsed) == []


def test_parse_recipients_skips_slots_missing_required_fields():
    text = "# dotseal:recipient fp=abc ephem=def\nFOO=bar\n"
    parsed = parser.parse(text)
    assert core.parse_recipients(parsed) == []


# --- verify_key --------------------------------------------------------------

def test_verify_key_raises_on_fingerprint_mismatch():
    key1 = crypto.load_key_bytes(crypto.generate_master_key())
    key2 = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text("FOO=bar\n", key1)
    parsed = parser.parse(enc)
    with pytest.raises(KeyFingerprintMismatchError):
        core.verify_key(parsed, key2)


def test_verify_key_passes_when_no_fingerprint_present():
    parsed = parser.parse("FOO=bar\n")
    key = crypto.load_key_bytes(crypto.generate_master_key())
    core.verify_key(parsed, key)  # must not raise


# --- decrypt_to_dict ---------------------------------------------------------

def test_decrypt_to_dict_returns_mapping():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text("FOO=bar\nBAZ=qux\n", key)
    assert core.decrypt_to_dict(enc, key) == {"FOO": "bar", "BAZ": "qux"}


def test_decrypt_to_dict_handles_plain_values():
    # A file without encrypted values: the else branch in decrypt_to_dict
    key = crypto.load_key_bytes(crypto.generate_master_key())
    plain = "FOO=bar\n"
    assert core.decrypt_to_dict(plain, key) == {"FOO": "bar"}


# --- write_secret_file -------------------------------------------------------

def test_write_secret_file_creates_with_correct_permissions(tmp_path):
    path = str(tmp_path / "secret.txt")
    core.write_secret_file(path, "content")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    with open(path) as fh:
        assert fh.read() == "content"


def test_write_secret_file_tightens_perms_on_preexisting_file(tmp_path):
    path = str(tmp_path / "secret.txt")
    with open(path, "w") as fh:
        fh.write("old")
    os.chmod(path, 0o644)
    core.write_secret_file(path, "new", mode=0o600)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    with open(path) as fh:
        assert fh.read() == "new"
