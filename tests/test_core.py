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


def test_encrypt_text_respects_plain_key_policy():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text(
        "PUBLIC=ok\nSECRET=shh\n",
        key,
        plain_keys=["PUBLIC"],
    )
    entries = {e.key: e.value for e in parser.parse(enc).entries()}
    meta = core.parse_metadata(parser.parse(enc))
    assert entries["PUBLIC"] == "ok"
    assert entries["SECRET"].startswith("ENC[")
    assert meta.get(core.PLAINTEXT_KEYS_TOKEN) == "PUBLIC"


def test_encrypt_text_respects_plain_key_regex_policy():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text(
        "PUBLIC_A=one\nPUBLIC_B=two\nSECRET=three\n",
        key,
        plain_key_regex=[r"PUBLIC_.+"],
    )
    entries = {e.key: e.value for e in parser.parse(enc).entries()}
    assert entries["PUBLIC_A"] == "one"
    assert entries["PUBLIC_B"] == "two"
    assert entries["SECRET"].startswith("ENC[")


def test_reencrypt_text_preserves_metadata_policy_by_default():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    original = core.encrypt_text("PUBLIC=old\nSECRET=old\n", key, plain_keys=["PUBLIC"])
    updated = core.reencrypt_text("PUBLIC=new\nSECRET=new\n", key, original)
    entries = {e.key: e.value for e in parser.parse(updated).entries()}
    meta = core.parse_metadata(parser.parse(updated))
    assert entries["PUBLIC"] == "new"
    assert entries["SECRET"].startswith("ENC[")
    assert meta.get(core.PLAINTEXT_KEYS_TOKEN) == "PUBLIC"


def test_reencrypt_partial_plain_key_override_merges_regex():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    original = core.encrypt_text(
        "FOO=old\nPUBLIC_EXTRA=old\nSECRET=old\n",
        key,
        plain_keys=["FOO"],
        plain_key_regex=[r"PUBLIC_.+"],
    )
    updated = core.reencrypt_text(
        "FOO=still\nPUBLIC_EXTRA=still\nSECRET=still\n",
        key,
        original,
        plain_keys=["BAR"],
    )
    entries = {e.key: e.value for e in parser.parse(updated).entries()}
    meta = core.parse_metadata(parser.parse(updated))
    assert meta.get(core.PLAINTEXT_REGEX_TOKEN)
    assert meta.get(core.PLAINTEXT_KEYS_TOKEN) == "BAR"
    assert entries["FOO"].startswith("ENC[")
    assert entries["PUBLIC_EXTRA"] == "still"
    assert entries["SECRET"].startswith("ENC[")


def test_keys_newly_sealed_by_policy_override():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    original = core.encrypt_text(
        "FOO=old\nPUBLIC_EXTRA=old\n",
        key,
        plain_keys=["FOO"],
        plain_key_regex=[r"PUBLIC_.+"],
    )
    cleartext = parser.parse("FOO=still\nPUBLIC_EXTRA=still\n")
    assert core.keys_newly_sealed_by_policy_override(
        parser.parse(original), cleartext, plain_keys=["BAR"]
    ) == ["FOO"]
    assert core.keys_newly_sealed_by_policy_override(
        parser.parse(original), cleartext
    ) == []


def test_add_rm_recipient_preserves_metadata_policy():
    priv_a, pub_a = crypto.generate_recipient_keypair()
    _, pub_b = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric("PUBLIC=ok\nSECRET=shh\n", [pub_a], plain_keys=["PUBLIC"])
    with_b = core.add_recipient_to_text(enc, priv_a, pub_b)
    after_rm = core.remove_recipient_from_text(with_b, pub_b)
    meta = core.parse_metadata(parser.parse(after_rm))
    entries = {e.key: e.value for e in parser.parse(after_rm).entries()}
    assert meta.get(core.PLAINTEXT_KEYS_TOKEN) == "PUBLIC"
    assert entries["PUBLIC"] == "ok"
    assert entries["SECRET"].startswith("ENC[")


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


# --- asymmetric plain-key policy ---------------------------------------------

def test_encrypt_text_asymmetric_respects_plain_key_policy():
    _, pub = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric(
        "PUBLIC=ok\nSECRET=shh\n",
        [pub],
        plain_keys=["PUBLIC"],
    )
    entries = {e.key: e.value for e in parser.parse(enc).entries()}
    meta = core.parse_metadata(parser.parse(enc))
    assert entries["PUBLIC"] == "ok"
    assert entries["SECRET"].startswith("ENC[")
    assert meta.get(core.PLAINTEXT_KEYS_TOKEN) == "PUBLIC"


def test_encrypt_text_asymmetric_respects_plain_key_regex_policy():
    _, pub = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric(
        "PUBLIC_A=one\nPUBLIC_B=two\nSECRET=three\n",
        [pub],
        plain_key_regex=[r"PUBLIC_.+"],
    )
    entries = {e.key: e.value for e in parser.parse(enc).entries()}
    assert entries["PUBLIC_A"] == "one"
    assert entries["PUBLIC_B"] == "two"
    assert entries["SECRET"].startswith("ENC[")


def test_reencrypt_text_asymmetric_preserves_metadata_policy_by_default():
    priv, pub = crypto.generate_recipient_keypair()
    original = core.encrypt_text_asymmetric(
        "PUBLIC=old\nSECRET=old\n",
        [pub],
        plain_keys=["PUBLIC"],
    )
    updated = core.reencrypt_text_asymmetric(
        "PUBLIC=new\nSECRET=new\n",
        priv,
        original,
    )
    entries = {e.key: e.value for e in parser.parse(updated).entries()}
    meta = core.parse_metadata(parser.parse(updated))
    assert entries["PUBLIC"] == "new"
    assert entries["SECRET"].startswith("ENC[")
    assert meta.get(core.PLAINTEXT_KEYS_TOKEN) == "PUBLIC"


def test_reencrypt_text_asymmetric_partial_plain_key_override_merges_regex():
    priv, pub = crypto.generate_recipient_keypair()
    original = core.encrypt_text_asymmetric(
        "FOO=old\nPUBLIC_EXTRA=old\nSECRET=old\n",
        [pub],
        plain_keys=["FOO"],
        plain_key_regex=[r"PUBLIC_.+"],
    )
    updated = core.reencrypt_text_asymmetric(
        "FOO=still\nPUBLIC_EXTRA=still\nSECRET=still\n",
        priv,
        original,
        plain_keys=["BAR"],
    )
    entries = {e.key: e.value for e in parser.parse(updated).entries()}
    meta = core.parse_metadata(parser.parse(updated))
    assert meta.get(core.PLAINTEXT_REGEX_TOKEN)
    assert meta.get(core.PLAINTEXT_KEYS_TOKEN) == "BAR"
    assert entries["FOO"].startswith("ENC[")
    assert entries["PUBLIC_EXTRA"] == "still"
    assert entries["SECRET"].startswith("ENC[")


def test_reencrypt_text_asymmetric_seals_removed_plain_key():
    priv, pub = crypto.generate_recipient_keypair()
    original = core.encrypt_text_asymmetric(
        "FOO=old\nSECRET=old\n",
        [pub],
        plain_keys=["FOO"],
    )
    updated = core.reencrypt_text_asymmetric(
        "FOO=new\nSECRET=new\n",
        priv,
        original,
        plain_keys=[],
    )
    entries = {e.key: e.value for e in parser.parse(updated).entries()}
    meta = core.parse_metadata(parser.parse(updated))
    assert core.PLAINTEXT_KEYS_TOKEN not in meta
    assert entries["FOO"].startswith("ENC[")
    assert entries["SECRET"].startswith("ENC[")


def test_reencrypt_text_asymmetric_unseals_added_plain_key():
    priv, pub = crypto.generate_recipient_keypair()
    original = core.encrypt_text_asymmetric("SECRET=old\n", [pub])
    updated = core.reencrypt_text_asymmetric(
        "SECRET=newplain\n",
        priv,
        original,
        plain_keys=["SECRET"],
    )
    entries = {e.key: e.value for e in parser.parse(updated).entries()}
    meta = core.parse_metadata(parser.parse(updated))
    assert meta.get(core.PLAINTEXT_KEYS_TOKEN) == "SECRET"
    assert entries["SECRET"] == "newplain"


# --- encrypt idempotency / partial-override footguns -------------------------

def test_encrypt_text_idempotent_expanding_plain_key_set_keeps_sealed_values():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text("SECRET=shh\n", key)
    enc2 = core.encrypt_text(enc, key, plain_keys=["SECRET"])
    entries = {e.key: e.value for e in parser.parse(enc2).entries()}
    meta = core.parse_metadata(parser.parse(enc2))
    # SECRET was already ENC[…]; the idempotency guard keeps the value
    # encrypted, so it must NOT appear in plain_keys (that would cause the
    # next `edit` to silently unseal it).
    assert core.PLAINTEXT_KEYS_TOKEN not in meta
    assert entries["SECRET"].startswith("ENC[")
    assert core.decrypt_to_dict(enc2, key) == {"SECRET": "shh"}


def test_encrypt_text_partial_override_rewrites_footer_without_unsealing():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text("SECRET=shh\nPUBLIC=ok\n", key)
    enc2 = core.encrypt_text(enc, key, plain_keys=["SECRET", "PUBLIC"])
    entries = {e.key: e.value for e in parser.parse(enc2).entries()}
    meta = core.parse_metadata(parser.parse(enc2))
    # Both keys are already ENC[…]; neither should appear in plain_keys.
    assert core.PLAINTEXT_KEYS_TOKEN not in meta
    assert entries["SECRET"].startswith("ENC[")
    assert entries["PUBLIC"].startswith("ENC[")
    assert core.decrypt_to_dict(enc2, key) == {"SECRET": "shh", "PUBLIC": "ok"}


def test_encrypt_text_partial_plain_key_override_merges_regex_on_rerun():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text(
        "FOO=old\nPUBLIC_EXTRA=old\nSECRET=old\n",
        key,
        plain_keys=["FOO"],
        plain_key_regex=[r"PUBLIC_.+"],
    )
    enc2 = core.encrypt_text(enc, key, plain_keys=["BAR"])
    entries = {e.key: e.value for e in parser.parse(enc2).entries()}
    meta = core.parse_metadata(parser.parse(enc2))
    assert meta.get(core.PLAINTEXT_REGEX_TOKEN)
    # BAR does not exist in the input file, so it is not encrypted in the
    # output; it is a forward-looking policy entry and must stay in the footer.
    assert meta.get(core.PLAINTEXT_KEYS_TOKEN) == "BAR"
    assert entries["FOO"].startswith("ENC[")
    assert entries["PUBLIC_EXTRA"] == "old"
    assert entries["SECRET"].startswith("ENC[")


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


def test_write_secret_file_cleans_up_temp_on_failure(tmp_path, monkeypatch):
    target = tmp_path / "out.env"

    def fail_replace(_src, _dst):
        raise OSError("replace failed")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        core.write_secret_file(str(target), "secret")
    leftovers = [p for p in tmp_path.iterdir() if p.name.startswith(".dotseal-tmp-")]
    assert leftovers == []


def test_write_secret_file_survives_unlink_error_during_cleanup(tmp_path, monkeypatch):
    target = tmp_path / "out.env"
    real_unlink = os.unlink

    def fail_unlink_on_temp(path):
        if ".dotseal-tmp-" in path:
            raise OSError("unlink failed")
        return real_unlink(path)

    monkeypatch.setattr(os, "replace", lambda *_: (_ for _ in ()).throw(OSError("replace failed")))
    monkeypatch.setattr(os, "unlink", fail_unlink_on_temp)
    with pytest.raises(OSError, match="replace failed"):
        core.write_secret_file(str(target), "secret")


def test_reencrypt_text_skips_undecryptable_original_tokens():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    good = crypto.encrypt_value(key, "val", aad="GOOD")
    bad = good[:-4] + "XXXX"
    original = parser.serialize(parser.parse(f"GOOD={good}\nBAD={bad}\n"))

    result = core.reencrypt_text("GOOD=val\nBAD=val\n", key, original)
    assert core.decrypt_to_dict(result, key) == {"GOOD": "val", "BAD": "val"}


def test_original_tokens_skips_decrypt_failures():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    good = crypto.encrypt_value(key, "val", aad="GOOD")
    bad = good[:-4] + "XXXX"
    parsed = parser.parse(f"GOOD={good}\nBAD={bad}\n")
    tokens = core._original_tokens(
        parsed,
        lambda token, name: crypto.decrypt_value(key, token, aad=name),
    )
    assert set(tokens) == {"GOOD"}


def test_reencrypt_text_preserves_enc_token_left_in_cleartext():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    original = core.encrypt_text("FOO=bar\n", key)
    token = next(e.value for e in parser.parse(original).entries())

    result = core.reencrypt_text(f"FOO={token}\n", key, original)
    assert next(e.value for e in parser.parse(result).entries()) == token


def test_reencrypt_text_with_comments_and_empty_body():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    original = core.encrypt_text("FOO=bar\n", key)

    result = core.reencrypt_text("\n\n", key, original)
    assert result.startswith(core.BANNER)
    assert core.build_metadata_line(key) in result
    assert not parser.parse(result).entries()


def test_parse_plaintext_policy_ignores_empty_regex_chunks():
    keys, regexes = core.parse_plaintext_policy({core.PLAINTEXT_REGEX_TOKEN: ","})
    assert regexes == []


def test_encrypt_text_rejects_python_only_regex_syntax():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    with pytest.raises(EncryptionError, match="Python-only syntax"):
        core.encrypt_text("FOO=bar\n", key, plain_key_regex=["(?i)FOO"])


def test_encrypt_text_rejects_invalid_regex():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    with pytest.raises(EncryptionError, match="Invalid plain-key regex"):
        core.encrypt_text("FOO=bar\n", key, plain_key_regex=["[invalid"])


# --- get_value ---------------------------------------------------------------

def test_get_value_symmetric_encrypted():
    key_bytes = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text("FOO=bar\nBAZ=qux\n", key_bytes)
    assert core.get_value(enc, "FOO", key_bytes=key_bytes) == "bar"
    assert core.get_value(enc, "BAZ", key_bytes=key_bytes) == "qux"


def test_get_value_plain_key():
    key_bytes = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text("PUBLIC=open\nSECRET=shh\n", key_bytes, plain_keys=["PUBLIC"])
    assert core.get_value(enc, "PUBLIC", key_bytes=key_bytes) == "open"


def test_get_value_missing_key_raises():
    from dotseal.exceptions import KeyNotFoundError
    key_bytes = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text("FOO=bar\n", key_bytes)
    with pytest.raises(KeyNotFoundError):
        core.get_value(enc, "MISSING", key_bytes=key_bytes)


def test_get_value_last_wins_for_duplicates():
    key_bytes = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text("FOO=first\nFOO=second\n", key_bytes)
    assert core.get_value(enc, "FOO", key_bytes=key_bytes) == "second"


def test_get_value_asymmetric():
    prv, pub = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric("SECRET=hidden\n", [pub])
    assert core.get_value(enc, "SECRET", private_key=prv) == "hidden"


def test_get_value_missing_key_symmetric_requires_key_bytes():
    from dotseal.exceptions import MasterKeyNotFoundError
    key_bytes = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text("FOO=bar\n", key_bytes)
    with pytest.raises(MasterKeyNotFoundError):
        core.get_value(enc, "FOO")


def test_get_value_asymmetric_requires_private_key():
    from dotseal.exceptions import PrivateKeyNotFoundError
    _, pub = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric("SECRET=hidden\n", [pub])
    with pytest.raises(PrivateKeyNotFoundError):
        core.get_value(enc, "SECRET")


# --- set_value ---------------------------------------------------------------

def test_set_value_only_target_ciphertext_changes():
    key_bytes = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text("KEEP=same\nCHANGE=old\n", key_bytes)
    before = {e.key: e.value for e in parser.parse(enc).entries()}

    enc2 = core.set_value(enc, "CHANGE", "new", key_bytes=key_bytes)
    after = {e.key: e.value for e in parser.parse(enc2).entries()}

    assert after["KEEP"] == before["KEEP"]
    assert after["CHANGE"] != before["CHANGE"]
    assert core.get_value(enc2, "CHANGE", key_bytes=key_bytes) == "new"


def test_set_value_new_key_appended_and_encrypted():
    key_bytes = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text("EXISTING=val\n", key_bytes)

    enc2 = core.set_value(enc, "NEW_KEY", "secret", key_bytes=key_bytes)
    entries = {e.key: e.value for e in parser.parse(enc2).entries()}
    assert "NEW_KEY" in entries
    assert crypto.is_encrypted_value(entries["NEW_KEY"])
    assert core.get_value(enc2, "NEW_KEY", key_bytes=key_bytes) == "secret"


def test_set_value_get_roundtrip():
    key_bytes = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text("FOO=original\n", key_bytes)
    enc2 = core.set_value(enc, "FOO", "updated", key_bytes=key_bytes)
    assert core.get_value(enc2, "FOO", key_bytes=key_bytes) == "updated"


def test_set_value_plain_policy_key_stays_cleartext():
    key_bytes = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text("PUBLIC=old\nSECRET=shh\n", key_bytes, plain_keys=["PUBLIC"])

    enc2 = core.set_value(enc, "PUBLIC", "new", key_bytes=key_bytes)
    entries = {e.key: e.value for e in parser.parse(enc2).entries()}
    assert not crypto.is_encrypted_value(entries["PUBLIC"])
    assert core.get_value(enc2, "PUBLIC", key_bytes=key_bytes) == "new"


def test_set_value_asymmetric_one_recipient():
    prv, pub = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric("TOKEN=old\n", [pub])
    enc2 = core.set_value(enc, "TOKEN", "new", private_key=prv)
    assert core.get_value(enc2, "TOKEN", private_key=prv) == "new"
    assert core.file_mode(enc2) == "asymmetric"
    assert len(core.parse_recipients(parser.parse(enc2))) == 1


def test_set_value_preserves_comments_and_order():
    key_bytes = crypto.load_key_bytes(crypto.generate_master_key())
    env_text = "# header\nFOO=foo\n# mid\nBAR=bar\n"
    enc = core.encrypt_text(env_text, key_bytes)
    enc2 = core.set_value(enc, "FOO", "updated", key_bytes=key_bytes)
    assert "# header" in enc2
    assert "# mid" in enc2
    assert core.get_value(enc2, "FOO", key_bytes=key_bytes) == "updated"
    assert core.get_value(enc2, "BAR", key_bytes=key_bytes) == "bar"


def test_set_value_value_with_special_chars():
    key_bytes = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text("PWD=old\n", key_bytes)
    complex_val = "!!@#$%=keep=this"
    enc2 = core.set_value(enc, "PWD", complex_val, key_bytes=key_bytes)
    assert core.get_value(enc2, "PWD", key_bytes=key_bytes) == complex_val


def test_set_value_asymmetric_requires_private_key():
    from dotseal.exceptions import PrivateKeyNotFoundError
    _, pub = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric("TOKEN=old\n", [pub])
    with pytest.raises(PrivateKeyNotFoundError):
        core.set_value(enc, "TOKEN", "new")


def test_set_value_symmetric_requires_key_bytes():
    from dotseal.exceptions import MasterKeyNotFoundError
    key_bytes = crypto.load_key_bytes(crypto.generate_master_key())
    enc = core.encrypt_text("FOO=bar\n", key_bytes)
    with pytest.raises(MasterKeyNotFoundError):
        core.set_value(enc, "FOO", "new")
