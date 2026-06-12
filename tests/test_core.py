import os
import stat

import pytest

from dotseal import core, crypto, parser
from dotseal.exceptions import (
    DecryptionError,
    EncryptionError,
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


def test_write_secret_file_survives_chmod_oserror(tmp_path, monkeypatch):
    path = str(tmp_path / "secret.txt")
    monkeypatch.setattr(os, "chmod", lambda *a: (_ for _ in ()).throw(OSError("no chmod")))
    core.write_secret_file(path, "content")  # must not raise
    with open(path) as fh:
        assert fh.read() == "content"


# --- parse_metadata / parse_recipients token edge cases ----------------------

def test_parse_metadata_skips_tokens_without_equals():
    text = "FOO=bar\n# dotseal: v=1 badtoken alg=AES_GCM\n"
    parsed = parser.parse(text)
    meta = core.parse_metadata(parsed)
    assert meta == {"v": "1", "alg": "AES_GCM"}


def test_parse_metadata_ignores_fake_dotseal_comment():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text("FOO=bar\n", key)
    tampered = "# dotseal: managed file, do not touch\n" + enc
    meta = core.parse_metadata(parser.parse(tampered))
    assert meta.get("v") == "1"
    assert meta.get("key_fp") == crypto.key_fingerprint(key)


def test_file_mode_asymmetric_from_recipients_without_footer():
    _, pub = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric("FOO=bar\n", [pub])
    lines = [
        line for line in enc.splitlines() if not line.strip().startswith("# dotseal: v=")
    ]
    damaged = "\n".join(lines) + "\n"
    assert core.file_mode(damaged) == "asymmetric"


def test_parse_recipients_skips_tokens_without_equals():
    _, pub = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric("FOO=bar\n", [pub])
    # Inject a malformed recipient line that still has the required fields but
    # also a bare token without "="; the slot should still be returned.
    from dotseal import parser as p
    parsed = p.parse(enc)
    for r in parsed.records:
        if r.kind == "comment" and r.raw.strip().startswith(core.RECIPIENT_PREFIX):
            r.raw = r.raw.rstrip() + " baretoken\n"
    recipients = core.parse_recipients(parsed)
    assert len(recipients) == 1


# --- encrypt_text idempotency and empty-body branch --------------------------

def test_encrypt_text_idempotent():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text("FOO=bar\n", key)
    enc2 = core.encrypt_text(enc, key)
    # Values must decrypt to the same result.
    assert core.decrypt_to_dict(enc2, key) == {"FOO": "bar"}


def test_encrypt_text_empty_body():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    result = core.encrypt_text("", key)
    assert result.startswith(core.BANNER)
    assert "# dotseal:" in result


# --- decrypt_text plain-value branch -----------------------------------------

def test_decrypt_text_preserves_plain_values():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text("FOO=bar\nBAZ=qux\n", key)
    # Manually replace one ENC[...] value with a plain string.
    parsed = parser.parse(enc)
    for r in parsed.records:
        if r.kind == "entry" and r.key == "BAZ":
            r.value = "plain"
    modified = parser.serialize(parsed)
    result = core.decrypt_text(modified, key)
    entries = {e.key: e.value for e in parser.parse(result).entries()}
    assert entries["FOO"] == "bar"
    assert entries["BAZ"] == "plain"


# --- asymmetric empty-body branch --------------------------------------------

def test_encrypt_text_asymmetric_empty_body():
    _, pub = crypto.generate_recipient_keypair()
    result = core.encrypt_text_asymmetric("", [pub])
    assert result.startswith(core.BANNER)
    assert crypto.ALGORITHM_ASYM in result


# --- encrypt_text_asymmetric deduplication and idempotency -------------------

def test_encrypt_text_asymmetric_deduplicates_recipients():
    _, pub = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric("FOO=bar\n", [pub, pub])
    assert len(core.parse_recipients(parser.parse(enc))) == 1


def test_encrypt_text_asymmetric_rejects_already_encrypted_value():
    from dotseal.exceptions import EncryptionError

    _, pub = crypto.generate_recipient_keypair()
    # A file that already contains a real ENC[...] token (under some other
    # key) must be refused: a fresh DEK could never decrypt it again.
    other_key = crypto.load_key_bytes(crypto.generate_master_key())
    preexisting = crypto.encrypt_value(other_key, "original", aad="FOO")
    with pytest.raises(EncryptionError):
        core.encrypt_text_asymmetric(f"FOO={preexisting}\n", [pub])


# --- recover_data_key with no recipients -------------------------------------

def test_recover_data_key_raises_for_no_recipients():
    from dotseal.exceptions import DecryptionError
    priv, _ = crypto.generate_recipient_keypair()
    parsed = parser.parse("FOO=bar\n")  # plain file, no recipients
    with pytest.raises(DecryptionError):
        core.recover_data_key(parsed, priv)


# --- asymmetric decrypt plain-value branches ---------------------------------

def _asym_file_with_plain_value() -> tuple:
    """Return (enc_with_plain_val, priv) where BAZ has a plain (non-ENC) value."""
    priv, pub = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric("FOO=bar\nBAZ=qux\n", [pub])
    parsed = parser.parse(enc)
    for r in parsed.records:
        if r.kind == "entry" and r.key == "BAZ":
            r.value = "plainval"
    return parser.serialize(parsed), priv


def test_decrypt_text_asymmetric_handles_plain_values():
    modified, priv = _asym_file_with_plain_value()
    result = core.decrypt_text_asymmetric(modified, priv)
    entries = {e.key: e.value for e in parser.parse(result).entries()}
    assert entries["FOO"] == "bar"
    assert entries["BAZ"] == "plainval"


def test_decrypt_to_dict_asymmetric_handles_plain_values():
    modified, priv = _asym_file_with_plain_value()
    result = core.decrypt_to_dict_asymmetric(modified, priv)
    assert result["FOO"] == "bar"
    assert result["BAZ"] == "plainval"


# --- reencrypt_text_asymmetric non-entry and already-encrypted branches ------

def test_reencrypt_text_asymmetric_with_comments_and_blanks():
    priv, pub = crypto.generate_recipient_keypair()
    original = core.encrypt_text_asymmetric("FOO=bar\n", [pub])
    cleartext = "# comment\n\nFOO=newval\n"
    result = core.reencrypt_text_asymmetric(cleartext, priv, original)
    assert core.decrypt_to_dict_asymmetric(result, priv) == {"FOO": "newval"}


def test_reencrypt_text_asymmetric_idempotent_values():
    priv, pub = crypto.generate_recipient_keypair()
    original = core.encrypt_text_asymmetric("FOO=bar\n", [pub])
    # Pass the encrypted file as "cleartext" — values are already ENC[...].
    result = core.reencrypt_text_asymmetric(original, priv, original)
    assert core.decrypt_to_dict_asymmetric(result, priv) == {"FOO": "bar"}


# --- add_recipient idempotency -----------------------------------------------

def test_add_recipient_already_present_is_idempotent():
    priv, pub = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric("FOO=bar\n", [pub])
    enc2 = core.add_recipient_to_text(enc, priv, pub)
    assert len(core.parse_recipients(parser.parse(enc2))) == 1


# --- remove_recipient not-found raises ---------------------------------------

def test_remove_recipient_not_found_raises():
    from dotseal.exceptions import RecipientNotFoundError
    _, pub_a = crypto.generate_recipient_keypair()
    _, pub_b = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric("FOO=bar\n", [pub_a])
    with pytest.raises(RecipientNotFoundError):
        core.remove_recipient_from_text(enc, pub_b)


# --- re-encryption guards (issue: bricked files) ------------------------------

def test_encrypt_text_with_wrong_key_raises_instead_of_bricking():
    from dotseal.exceptions import KeyFingerprintMismatchError as FpMismatch

    k1 = crypto.load_key_bytes(crypto.generate_master_key())
    k2 = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text("FOO=bar\n", k1)
    with pytest.raises(FpMismatch):
        core.encrypt_text(enc, k2)


def test_encrypt_text_rejects_enc_lookalike_without_metadata():
    from dotseal.exceptions import EncryptionError

    key = crypto.load_key_bytes(crypto.generate_master_key())
    with pytest.raises(EncryptionError):
        core.encrypt_text("SNEAKY=ENC[AES_GCM,data:aGVsbG8=]\n", key)


def test_encrypt_text_rejects_asymmetric_file():
    from dotseal.exceptions import EncryptionError

    _, pub = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric("FOO=bar\n", [pub])
    key = crypto.load_key_bytes(crypto.generate_master_key())
    with pytest.raises(EncryptionError):
        core.encrypt_text(enc, key)


def test_encrypt_text_partial_encryption_with_matching_key_is_supported():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text("FOO=bar\n", key)
    # Simulate a user appending a new cleartext variable to the .env.enc.
    with_new = enc.replace("# dotseal:", "NEW=cleartext\n# dotseal:")
    enc2 = core.encrypt_text(with_new, key)
    assert core.decrypt_to_dict(enc2, key) == {"FOO": "bar", "NEW": "cleartext"}


# --- key resolution precedence -------------------------------------------------

def test_explicit_key_file_beats_env_var(tmp_path, monkeypatch):
    file_key = crypto.generate_master_key()
    env_key = crypto.generate_master_key()
    key_path = tmp_path / "explicit.key"
    key_path.write_text(file_key + "\n")
    monkeypatch.setenv(core.ENV_VAR_NAME, env_key)
    assert core.resolve_master_key(key_file=str(key_path)) == file_key


def test_explicit_missing_key_file_raises(tmp_path, monkeypatch):
    monkeypatch.setenv(core.ENV_VAR_NAME, crypto.generate_master_key())
    with pytest.raises(MasterKeyNotFoundError):
        core.resolve_master_key(key_file=str(tmp_path / "nope.key"))


def test_explicit_private_key_file_beats_env_var(tmp_path, monkeypatch):
    file_priv, _ = crypto.generate_recipient_keypair()
    env_priv, _ = crypto.generate_recipient_keypair()
    key_path = tmp_path / "explicit.prv"
    key_path.write_text(file_priv + "\n")
    monkeypatch.setenv(core.PRIVATE_ENV_VAR_NAME, env_priv)
    assert core.resolve_private_key(key_file=str(key_path)) == file_priv


def test_explicit_missing_private_key_file_raises(tmp_path, monkeypatch):
    monkeypatch.delenv(core.PRIVATE_ENV_VAR_NAME, raising=False)
    with pytest.raises(PrivateKeyNotFoundError):
        core.resolve_private_key(key_file=str(tmp_path / "nope.prv"))


# --- reencrypt_text: unchanged ciphertexts are reused --------------------------

def test_reencrypt_text_reuses_unchanged_ciphertexts():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    original = core.encrypt_text("KEEP=same\nCHANGE=old\n", key)
    tokens = {e.key: e.value for e in parser.parse(original).entries()}

    result = core.reencrypt_text("KEEP=same\nCHANGE=new\n", key, original)
    new_tokens = {e.key: e.value for e in parser.parse(result).entries()}

    assert new_tokens["KEEP"] == tokens["KEEP"]  # token preserved verbatim
    assert new_tokens["CHANGE"] != tokens["CHANGE"]
    assert core.decrypt_to_dict(result, key) == {"KEEP": "same", "CHANGE": "new"}


def test_reencrypt_text_wrong_key_raises():
    k1 = crypto.load_key_bytes(crypto.generate_master_key())
    k2 = crypto.load_key_bytes(crypto.generate_master_key())
    original = core.encrypt_text("FOO=bar\n", k1)
    with pytest.raises(KeyFingerprintMismatchError):
        core.reencrypt_text("FOO=baz\n", k2, original)


def test_reencrypt_text_rejects_asymmetric_file():
    _, pub = crypto.generate_recipient_keypair()
    original = core.encrypt_text_asymmetric("FOO=bar\n", [pub])
    key = crypto.load_key_bytes(crypto.generate_master_key())
    with pytest.raises(EncryptionError, match="asymmetric"):
        core.reencrypt_text("FOO=baz\n", key, original)


def test_decrypt_to_dict_rejects_asymmetric_with_master_key():
    _, pub = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric("FOO=bar\n", [pub])
    key = crypto.load_key_bytes(crypto.generate_master_key())
    with pytest.raises(DecryptionError, match="asymmetric"):
        core.decrypt_to_dict(enc, key)


def test_reencrypt_text_asymmetric_reuses_unchanged_ciphertexts():
    priv, pub = crypto.generate_recipient_keypair()
    original = core.encrypt_text_asymmetric("KEEP=same\nCHANGE=old\n", [pub])
    tokens = {e.key: e.value for e in parser.parse(original).entries()}

    result = core.reencrypt_text_asymmetric("KEEP=same\nCHANGE=new\n", priv, original)
    new_tokens = {e.key: e.value for e in parser.parse(result).entries()}

    assert new_tokens["KEEP"] == tokens["KEEP"]
    assert new_tokens["CHANGE"] != tokens["CHANGE"]
    assert core.decrypt_to_dict_asymmetric(result, priv) == {
        "KEEP": "same",
        "CHANGE": "new",
    }


# --- write_secret_file hardening -----------------------------------------------

def test_write_secret_file_replaces_loose_permissions(tmp_path):
    target = tmp_path / "out.env"
    target.write_text("old")
    os.chmod(target, 0o644)
    core.write_secret_file(str(target), "secret")
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
    assert target.read_text() == "secret"


def test_write_secret_file_replaces_symlink_instead_of_following(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("untouched")
    target = tmp_path / "out.env"
    os.symlink(victim, target)
    core.write_secret_file(str(target), "secret")
    assert victim.read_text() == "untouched"  # symlink target not written through
    assert not os.path.islink(target)
    assert target.read_text() == "secret"


def test_write_secret_file_leaves_no_temp_files(tmp_path):
    core.write_secret_file(str(tmp_path / "out.env"), "secret")
    leftovers = [p for p in os.listdir(tmp_path) if p.startswith(".dotseal-tmp-")]
    assert leftovers == []
