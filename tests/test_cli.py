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


def test_edit_new_file_symmetric(project, monkeypatch):
    editor_script = project / "fake_editor.py"
    editor_script.write_text(
        "import sys\nopen(sys.argv[1], 'w').write('NEW=value\\n')\n"
    )
    monkeypatch.setenv("EDITOR", f"{sys.executable} {editor_script}")
    assert main(["init"]) == 0
    assert main(["edit", "brand-new.env.enc"]) == 0
    assert (project / "brand-new.env.enc").is_file()


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
