import os
import stat
import sys

import pytest

from dotseal import core, crypto
from dotseal.cli import main

SAMPLE_ENV = (
    "# project config\n"
    "DATABASE_URL=postgres://user:pass@localhost:5432/db\n"
    "DEBUG=True\n"
    "PASSWORD=!!@#$%=\n"
    'QUOTED="  spaced value  "\n'
)


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(core.ENV_VAR_NAME, raising=False)
    return tmp_path


def test_init_creates_key_and_gitignore(project, capsys):
    assert main(["init"]) == 0
    key_path = project / core.KEY_FILE_NAME
    assert key_path.is_file()
    mode = stat.S_IMODE(key_path.stat().st_mode)
    assert mode == 0o600
    gitignore = (project / ".gitignore").read_text()
    assert core.KEY_FILE_NAME in gitignore
    out = capsys.readouterr().out
    assert "fingerprint" in out.lower()


def test_init_appends_to_existing_gitignore(project):
    (project / ".gitignore").write_text("__pycache__/\n")
    assert main(["init"]) == 0
    gitignore = (project / ".gitignore").read_text()
    assert "__pycache__/" in gitignore
    assert core.KEY_FILE_NAME in gitignore


def test_init_refuses_overwrite_without_force(project):
    assert main(["init"]) == 0
    assert main(["init"]) == 1
    assert main(["init", "--force"]) == 0


def test_encrypt_keeps_keys_cleartext(project):
    (project / ".env").write_text(SAMPLE_ENV)
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    enc = (project / ".env.enc").read_text()
    # keys are visible; values are wrapped
    assert "DATABASE_URL=ENC[AES_GCM,data:" in enc
    assert "DEBUG=ENC[AES_GCM,data:" in enc
    assert "# project config" in enc  # comments preserved
    assert "# dotseal:" in enc  # metadata footer
    assert "postgres://user" not in enc  # value is gone


def test_encrypt_decrypt_roundtrip_via_cli(project):
    (project / ".env").write_text(SAMPLE_ENV)
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    (project / ".env").unlink()
    assert main(["decrypt"]) == 0
    parsed = (project / ".env").read_text()
    from dotseal import parser

    entries = {e.key: e.value for e in parser.parse(parsed).entries()}
    assert entries["DATABASE_URL"] == "postgres://user:pass@localhost:5432/db"
    assert entries["DEBUG"] == "True"
    assert entries["PASSWORD"] == "!!@#$%="
    assert entries["QUOTED"] == "  spaced value  "


def test_encrypt_with_plain_key_option(project):
    (project / ".env").write_text("PUBLIC=ok\nSECRET=shh\n")
    assert main(["init"]) == 0
    assert main(["encrypt", "--plain-key", "PUBLIC"]) == 0
    enc = (project / ".env.enc").read_text()
    assert "PUBLIC=ok" in enc
    assert "SECRET=ENC[AES_GCM,data:" in enc
    assert "plain_keys=PUBLIC" in enc


def test_encrypt_with_plain_key_regex_option(project):
    (project / ".env").write_text("PUBLIC_A=1\nPUBLIC_B=2\nSECRET=3\n")
    assert main(["init"]) == 0
    assert main(["encrypt", "--plain-key-regex", "PUBLIC_.+"]) == 0
    enc = (project / ".env.enc").read_text()
    assert "PUBLIC_A=1" in enc
    assert "PUBLIC_B=2" in enc
    assert "SECRET=ENC[AES_GCM,data:" in enc
    assert "plain_re=" in enc


def test_decrypt_output_is_owner_only(project):
    (project / ".env").write_text("FOO=bar\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    assert main(["decrypt", ".env.enc", "out.env"]) == 0
    mode = stat.S_IMODE((project / "out.env").stat().st_mode)
    assert mode == 0o600


def test_decrypt_with_wrong_key_fails(project, capsys):
    (project / ".env").write_text("FOO=bar\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    wrong = crypto.generate_master_key()
    assert main(["decrypt", ".env.enc", "out.env", "--key", wrong]) == 1
    err = capsys.readouterr().err
    assert "error" in err.lower()


def test_encrypt_with_key_from_env_var(project, monkeypatch):
    key = crypto.generate_master_key()
    monkeypatch.setenv(core.ENV_VAR_NAME, key)
    (project / ".env").write_text("FOO=bar\n")
    assert main(["encrypt"]) == 0
    assert main(["decrypt", ".env.enc", "out.env"]) == 0
    assert "FOO=bar" in (project / "out.env").read_text()


def test_read_missing_file_raises(project, capsys):
    assert main(["encrypt", "nonexistent.env"]) == 1
    assert "error" in capsys.readouterr().err.lower()


def test_init_already_in_gitignore(project):
    # Second forced init should report key already present in .gitignore.
    assert main(["init"]) == 0
    assert main(["init", "--force"]) == 0
    out = main(["init", "--force"])
    assert out == 0


def test_collect_recipients_from_file(project, capsys):
    _, pub1 = crypto.generate_recipient_keypair()
    _, pub2 = crypto.generate_recipient_keypair()
    recipients_file = project / "recipients.txt"
    recipients_file.write_text(f"# comment\n{pub1}\n{pub2}\n")
    (project / ".env").write_text("FOO=bar\n")
    assert main(["encrypt", "--recipients-file", str(recipients_file)]) == 0
    enc = (project / ".env.enc").read_text()
    assert core.file_mode(enc) == "asymmetric"
    recipients = core.parse_recipients(__import__("dotseal.parser", fromlist=["parse"]).parse(enc))
    assert len(recipients) == 2


def test_collect_recipients_file_not_found(project, capsys):
    (project / ".env").write_text("FOO=bar\n")
    assert main(["encrypt", "--recipients-file", "no-such-file.txt"]) == 1
    assert "error" in capsys.readouterr().err.lower()


def test_keygen_print_flag(project, capsys):
    assert main(["keygen", "--print"]) == 0
    out = capsys.readouterr().out
    assert crypto.PRIVKEY_PREFIX in out
    assert crypto.PUBKEY_PREFIX in out
    assert not (project / core.PRIVATE_KEY_FILE_NAME).exists()


def test_keygen_out_outside_cwd_skips_gitignore(project, tmp_path):
    out_path = str(tmp_path / "subdir" / "my.prv")
    os.makedirs(os.path.dirname(out_path))
    assert main(["keygen", "--out", out_path]) == 0
    assert os.path.isfile(out_path)
    assert not (project / ".gitignore").exists()


def test_secure_delete_survives_overwrite_oserror(tmp_path, monkeypatch):
    from dotseal.cli import _secure_delete
    path = str(tmp_path / "file.txt")
    with open(path, "w") as fh:
        fh.write("secret")
    monkeypatch.setattr(os.path, "getsize", lambda p: (_ for _ in ()).throw(OSError("disk")))
    _secure_delete(path)  # must not raise; file should be unlinked
    assert not os.path.exists(path)


def test_secure_delete_survives_unlink_oserror(tmp_path, monkeypatch):
    from dotseal.cli import _secure_delete
    path = str(tmp_path / "file.txt")
    with open(path, "w") as fh:
        fh.write("secret")
    monkeypatch.setattr(os, "unlink", lambda p: (_ for _ in ()).throw(OSError("locked")))
    _secure_delete(path)  # must not raise


def test_edit_new_file_symmetric(project, monkeypatch):
    editor_script = project / "fake_editor.py"
    editor_script.write_text(
        "import sys\nopen(sys.argv[1], 'w').write('NEW=value\\n')\n"
    )
    monkeypatch.setenv("EDITOR", f"{sys.executable} {editor_script}")
    assert main(["init"]) == 0
    assert main(["edit", "brand-new.env.enc"]) == 0
    assert (project / "brand-new.env.enc").is_file()


def test_edit_new_file_unchanged_does_not_create(project, monkeypatch, capsys):
    editor_script = project / "noop_editor.py"
    editor_script.write_text("import sys\n")
    monkeypatch.setenv("EDITOR", f"{sys.executable} {editor_script}")
    assert main(["init"]) == 0
    target = project / "brand-new.env.enc"
    assert not target.exists()
    assert main(["edit", "brand-new.env.enc"]) == 0
    assert not target.exists()
    assert "was not created" in capsys.readouterr().out


def test_edit_new_file_asymmetric(project, monkeypatch):
    editor_script = project / "fake_editor.py"
    editor_script.write_text(
        "import sys\nopen(sys.argv[1], 'w').write('NEW=value\\n')\n"
    )
    monkeypatch.setenv("EDITOR", f"{sys.executable} {editor_script}")
    _, pub = crypto.generate_recipient_keypair()
    assert main(["edit", "brand-new-asym.env.enc", "-r", pub]) == 0
    enc = (project / "brand-new-asym.env.enc").read_text()
    assert core.file_mode(enc) == "asymmetric"


def test_edit_editor_not_found(project, monkeypatch):
    (project / ".env").write_text("FOO=bar\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    monkeypatch.setenv("EDITOR", "/no/such/editor/binary")
    assert main(["edit"]) == 1


def test_edit_editor_nonzero_exit(project, monkeypatch):
    editor_script = project / "failing_editor.py"
    editor_script.write_text("import sys\nsys.exit(1)\n")
    monkeypatch.setenv("EDITOR", f"{sys.executable} {editor_script}")
    (project / ".env").write_text("FOO=bar\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    assert main(["edit"]) == 1


def test_add_recipient_on_symmetric_file_fails(project, capsys):
    (project / ".env").write_text("FOO=bar\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    _, pub = crypto.generate_recipient_keypair()
    assert main(["add-recipient", pub, ".env.enc"]) == 1
    assert "error" in capsys.readouterr().err.lower()


def test_rm_recipient_on_symmetric_file_fails(project, capsys):
    (project / ".env").write_text("FOO=bar\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    assert main(["rm-recipient", "somefp", ".env.enc"]) == 1
    assert "error" in capsys.readouterr().err.lower()


def test_edit_reencrypts_changes(project, monkeypatch):
    # A fake $EDITOR that mutates the decrypted temp file in place.
    editor_script = project / "fake_editor.py"
    editor_script.write_text(
        "import sys\n"
        "p = sys.argv[1]\n"
        "text = open(p).read().replace('DEBUG=True', 'DEBUG=False')\n"
        "open(p, 'w').write(text + 'NEW_KEY=new_value\\n')\n"
    )
    monkeypatch.setenv("EDITOR", f"{sys.executable} {editor_script}")

    (project / ".env").write_text("DEBUG=True\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    assert main(["edit"]) == 0

    # no temp .env files left behind
    leftovers = [p for p in os.listdir(project) if "dotseal-edit-" in p]
    assert leftovers == []

    assert main(["decrypt", ".env.enc", "out.env"]) == 0
    from dotseal import parser

    entries = {e.key: e.value for e in parser.parse((project / "out.env").read_text()).entries()}
    assert entries["DEBUG"] == "False"
    assert entries["NEW_KEY"] == "new_value"


# --- edit: edits survive a re-encrypt failure ---------------------------------

def test_edit_parse_error_preserves_edits(project, monkeypatch, capsys):
    import tempfile

    # Keep the edit temp file inside the test sandbox so we can find it.
    monkeypatch.setattr(tempfile, "tempdir", str(project))

    editor_script = project / "fake_editor.py"
    editor_script.write_text(
        "import sys\nopen(sys.argv[1], 'w').write('this is not = a valid !! line\\n')\n"
    )
    monkeypatch.setenv("EDITOR", f"{sys.executable} {editor_script}")

    (project / ".env").write_text("FOO=bar\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    assert main(["edit"]) == 1

    err = capsys.readouterr().err
    assert "your edits were kept" in err
    leftovers = [p for p in os.listdir(project) if p.startswith(".dotseal-edit-")]
    assert len(leftovers) == 1
    assert "not = a valid" in (project / leftovers[0]).read_text()
    # The encrypted file itself must be untouched.
    assert "FOO=ENC[" in (project / ".env.enc").read_text()


def test_edit_no_changes_leaves_file_untouched(project, monkeypatch, capsys):
    editor_script = project / "noop_editor.py"
    editor_script.write_text("import sys\n")  # editor saves nothing
    monkeypatch.setenv("EDITOR", f"{sys.executable} {editor_script}")

    (project / ".env").write_text("FOO=bar\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    before = (project / ".env.enc").read_text()
    assert main(["edit"]) == 0
    assert (project / ".env.enc").read_text() == before
    assert "No changes" in capsys.readouterr().out


def test_edit_unchanged_values_keep_their_ciphertext(project, monkeypatch):
    from dotseal import parser

    editor_script = project / "fake_editor.py"
    editor_script.write_text(
        "import sys\n"
        "p = sys.argv[1]\n"
        "text = open(p).read().replace('CHANGE=old', 'CHANGE=new')\n"
        "open(p, 'w').write(text)\n"
    )
    monkeypatch.setenv("EDITOR", f"{sys.executable} {editor_script}")

    (project / ".env").write_text("KEEP=same\nCHANGE=old\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    before = {e.key: e.value for e in parser.parse((project / ".env.enc").read_text()).entries()}
    assert main(["edit"]) == 0
    after = {e.key: e.value for e in parser.parse((project / ".env.enc").read_text()).entries()}

    assert after["KEEP"] == before["KEEP"]  # unchanged value: token reused
    assert after["CHANGE"] != before["CHANGE"]


def test_edit_preserves_existing_plain_policy(project, monkeypatch):
    editor_script = project / "fake_editor.py"
    editor_script.write_text(
        "import sys\n"
        "p = sys.argv[1]\n"
        "text = open(p).read().replace('PUBLIC=old', 'PUBLIC=new').replace('SECRET=old', 'SECRET=new')\n"
        "open(p, 'w').write(text)\n"
    )
    monkeypatch.setenv("EDITOR", f"{sys.executable} {editor_script}")

    (project / ".env").write_text("PUBLIC=old\nSECRET=old\n")
    assert main(["init"]) == 0
    assert main(["encrypt", "--plain-key", "PUBLIC"]) == 0
    assert main(["edit"]) == 0
    enc = (project / ".env.enc").read_text()
    assert "PUBLIC=new" in enc
    assert "SECRET=ENC[AES_GCM,data:" in enc
    assert "plain_keys=PUBLIC" in enc


def test_encrypt_warns_when_policy_override_seals_keys(project, capsys):
    (project / ".env").write_text("FOO=old\nSECRET=old\n")
    assert main(["init"]) == 0
    assert main(["encrypt", "--plain-key", "FOO"]) == 0
    assert main(["encrypt", ".env.enc", ".env.enc", "--plain-key", "BAR"]) == 0
    err = capsys.readouterr().err
    assert "warning: policy override will seal previously plaintext keys: FOO" in err
    enc = (project / ".env.enc").read_text()
    assert "FOO=ENC[AES_GCM,data:" in enc


def test_encrypt_idempotent_expanding_plain_key_set_keeps_sealed_values(project, capsys):
    (project / ".env").write_text("SECRET=shh\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    assert main(["encrypt", ".env.enc", ".env.enc", "--plain-key", "SECRET"]) == 0
    enc = (project / ".env.enc").read_text()
    # SECRET was already ENC[…] — the idempotency guard keeps it encrypted
    # and must NOT write it to plain_keys (that would silently unseal it on
    # the next edit).  A warning is emitted instead.
    assert "plain_keys=" not in enc
    assert "SECRET=ENC[AES_GCM,data:" in enc
    assert "SECRET" in capsys.readouterr().err


def test_encrypt_partial_override_footer_mismatches_enc_values(project, capsys):
    (project / ".env").write_text("SECRET=shh\nPUBLIC=ok\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    assert main(
        ["encrypt", ".env.enc", ".env.enc", "--plain-key", "SECRET", "--plain-key", "PUBLIC"]
    ) == 0
    enc = (project / ".env.enc").read_text()
    # Both values are already ENC[…] — neither should appear in plain_keys.
    assert "plain_keys=" not in enc
    assert "SECRET=ENC[AES_GCM,data:" in enc
    assert "PUBLIC=ENC[AES_GCM,data:" in enc
    err = capsys.readouterr().err
    assert "PUBLIC" in err and "SECRET" in err


def test_edit_warns_when_policy_override_seals_keys(project, monkeypatch, capsys):
    editor_script = project / "fake_editor.py"
    editor_script.write_text(
        "import sys\n"
        "p = sys.argv[1]\n"
        "text = open(p).read().replace('FOO=old', 'FOO=new')\n"
        "open(p, 'w').write(text)\n"
    )
    monkeypatch.setenv("EDITOR", f"{sys.executable} {editor_script}")

    (project / ".env").write_text("FOO=old\nSECRET=old\n")
    assert main(["init"]) == 0
    assert main(["encrypt", "--plain-key", "FOO"]) == 0
    assert main(["edit", "--plain-key", "BAR"]) == 0
    err = capsys.readouterr().err
    assert "warning: policy override will seal previously plaintext keys: FOO" in err
    enc = (project / ".env.enc").read_text()
    assert "FOO=ENC[AES_GCM,data:" in enc


# --- encrypt: refuses to brick a re-encrypted file ----------------------------

def test_encrypt_after_key_rotation_fails_loudly(project, capsys):
    (project / ".env").write_text("FOO=bar\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    assert main(["init", "--force"]) == 0
    # Re-encrypting .env.enc (already encrypted under the old key) must fail.
    assert main(["encrypt", ".env.enc", ".env.enc"]) == 1
    assert "different master key" in capsys.readouterr().err


# --- gitignore pattern awareness -----------------------------------------------

def test_init_recognizes_covering_gitignore_pattern(project, capsys):
    (project / ".gitignore").write_text("*.key\n")
    assert main(["init"]) == 0
    assert "already present" in capsys.readouterr().out
    # No duplicate entry appended.
    assert ".dotseal.key" not in (project / ".gitignore").read_text()


def test_init_appends_when_gitignore_negation_reincludes_key(project, capsys):
    gitignore = project / ".gitignore"
    gitignore.write_text(".dotseal.key\n!.dotseal.key\n")
    assert main(["init"]) == 0
    out = capsys.readouterr().out
    assert "already present" not in out
    assert gitignore.read_text().count(".dotseal.key\n") >= 2


def test_gitignore_covers_respects_negation_and_globs():
    from dotseal.cli import _gitignore_covers

    assert _gitignore_covers("*.key\n", ".dotseal.key")
    assert not _gitignore_covers(".dotseal.key\n!.dotseal.key\n", ".dotseal.key")
    assert _gitignore_covers("# comment\n*.key\n", ".dotseal.key")


def test_ask_reopen_editor(project, monkeypatch):
    from dotseal.cli import _ask_reopen_editor

    monkeypatch.setattr("builtins.input", lambda _: "")
    assert _ask_reopen_editor() is True

    monkeypatch.setattr("builtins.input", lambda _: "n")
    assert _ask_reopen_editor() is False

    def raise_eof(_prompt):
        raise EOFError

    monkeypatch.setattr("builtins.input", raise_eof)
    assert _ask_reopen_editor() is False


def test_edit_reopens_editor_after_reencrypt_failure(project, monkeypatch, capsys):
    import tempfile

    monkeypatch.setattr(tempfile, "tempdir", str(project))

    editor_script = project / "two_pass_editor.py"
    editor_script.write_text(
        "import sys, os\n"
        "p = sys.argv[1]\n"
        "marker = p + '.pass'\n"
        "if not os.path.exists(marker):\n"
        "    open(marker, 'w').close()\n"
        "    open(p, 'w').write('this is not = a valid !! line\\n')\n"
        "else:\n"
        "    open(p, 'w').write('DEBUG=False\\n')\n"
        "    os.remove(marker)\n"
    )
    monkeypatch.setenv("EDITOR", f"{sys.executable} {editor_script}")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "")

    (project / ".env").write_text("DEBUG=True\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    assert main(["edit"]) == 0

    assert main(["decrypt", ".env.enc", "out.env"]) == 0
    from dotseal import parser

    entries = {e.key: e.value for e in parser.parse((project / "out.env").read_text()).entries()}
    assert entries["DEBUG"] == "False"
    leftovers = [p for p in os.listdir(project) if p.startswith(".dotseal-edit-")]
    assert leftovers == []


# --- get command -------------------------------------------------------------

def test_get_existing_key(project, capsys):
    (project / ".env").write_text("FOO=secretval\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    capsys.readouterr()
    assert main(["get", "FOO"]) == 0
    assert capsys.readouterr().out == "secretval"


def test_get_missing_key_returns_1(project, capsys):
    (project / ".env").write_text("FOO=bar\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    capsys.readouterr()
    assert main(["get", "MISSING"]) == 1
    assert "error" in capsys.readouterr().err.lower()


def test_get_missing_key_with_default(project, capsys):
    (project / ".env").write_text("FOO=bar\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    capsys.readouterr()
    assert main(["get", "MISSING", "--default", "fallback"]) == 0
    assert capsys.readouterr().out == "fallback"


def test_get_no_trailing_newline(project, capsys):
    (project / ".env").write_text("KEY=value\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    capsys.readouterr()
    assert main(["get", "KEY"]) == 0
    assert capsys.readouterr().out == "value"


def test_get_plain_key(project, capsys):
    (project / ".env").write_text("PUBLIC=visible\nSECRET=shh\n")
    assert main(["init"]) == 0
    assert main(["encrypt", "--plain-key", "PUBLIC"]) == 0
    capsys.readouterr()
    assert main(["get", "PUBLIC"]) == 0
    assert capsys.readouterr().out == "visible"


def test_get_asymmetric(project, capsys):
    prv, pub = crypto.generate_recipient_keypair()
    (project / ".env").write_text("TOKEN=mysecret\n")
    assert main(["encrypt", "-r", pub]) == 0
    prv_file = project / core.PRIVATE_KEY_FILE_NAME
    prv_file.write_text(prv + "\n")
    capsys.readouterr()
    assert main(["get", "TOKEN"]) == 0
    assert capsys.readouterr().out == "mysecret"


# --- set command -------------------------------------------------------------

def test_set_changes_existing_value(project, capsys):
    from dotseal import parser as _parser
    (project / ".env").write_text("FOO=old\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    assert main(["set", "FOO=new"]) == 0
    assert main(["decrypt", ".env.enc", "out.env"]) == 0
    entries = {e.key: e.value for e in _parser.parse((project / "out.env").read_text()).entries()}
    assert entries["FOO"] == "new"


def test_set_adds_new_key(project, capsys):
    (project / ".env").write_text("EXISTING=val\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    assert main(["set", "NEW_KEY=myvalue"]) == 0
    capsys.readouterr()
    assert main(["get", "NEW_KEY"]) == 0
    assert capsys.readouterr().out == "myvalue"


def test_set_unchanged_ciphertext_preserved(project):
    from dotseal import parser as _parser
    (project / ".env").write_text("KEEP=same\nCHANGE=old\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    before = {e.key: e.value for e in _parser.parse((project / ".env.enc").read_text()).entries()}
    assert main(["set", "CHANGE=new"]) == 0
    after = {e.key: e.value for e in _parser.parse((project / ".env.enc").read_text()).entries()}
    assert after["KEEP"] == before["KEEP"]
    assert after["CHANGE"] != before["CHANGE"]


def test_set_invalid_key_name(project, capsys):
    (project / ".env").write_text("FOO=bar\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    assert main(["set", "123INVALID=val"]) == 1
    assert "error" in capsys.readouterr().err.lower()


def test_set_missing_equals(project, capsys):
    (project / ".env").write_text("FOO=bar\n")
    assert main(["init"]) == 0
    assert main(["encrypt"]) == 0
    assert main(["set", "NOEQUALSSIGN"]) == 1
    assert "error" in capsys.readouterr().err.lower()


def test_set_on_missing_file(project, capsys):
    assert main(["init"]) == 0
    assert main(["set", "FOO=bar", "nonexistent.env.enc"]) == 1
    assert "error" in capsys.readouterr().err.lower()


def test_set_asymmetric(project):
    prv, pub = crypto.generate_recipient_keypair()
    (project / ".env").write_text("TOKEN=old\n")
    assert main(["encrypt", "-r", pub]) == 0
    prv_file = project / core.PRIVATE_KEY_FILE_NAME
    prv_file.write_text(prv + "\n")
    assert main(["set", "TOKEN=new"]) == 0
    enc = (project / ".env.enc").read_text()
    assert core.file_mode(enc) == "asymmetric"
    assert core.get_value(enc, "TOKEN", private_key=prv) == "new"
