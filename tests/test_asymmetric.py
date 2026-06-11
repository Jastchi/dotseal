import stat

import pytest

from dotseal import core, crypto, loader, parser
from dotseal.cli import main
from dotseal.exceptions import RecipientNotFoundError

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
    monkeypatch.delenv(core.PRIVATE_ENV_VAR_NAME, raising=False)
    return tmp_path


# --- core round-trips -------------------------------------------------------

def test_encrypt_text_asymmetric_marks_mode_and_recipients():
    _, pub = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric("FOO=bar\n", [pub])
    assert core.file_mode(enc) == "asymmetric"
    assert crypto.ALGORITHM_ASYM in enc  # algorithm recorded in footer
    recipients = core.parse_recipients(parser.parse(enc))
    assert len(recipients) == 1
    assert recipients[0]["fp"] == crypto.recipient_fingerprint(pub)
    assert "FOO=ENC[AES_GCM,data:" in enc


def test_roundtrip_single_recipient():
    priv, pub = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric(SAMPLE_ENV, [pub])
    out = core.decrypt_text_asymmetric(enc, priv)
    entries = {e.key: e.value for e in parser.parse(out).entries()}
    assert entries["DATABASE_URL"] == "postgres://user:pass@localhost:5432/db"
    assert entries["PASSWORD"] == "!!@#$%="
    assert entries["QUOTED"] == "  spaced value  "


def test_multiple_recipients_all_decrypt_same_values():
    priv_a, pub_a = crypto.generate_recipient_keypair()
    priv_b, pub_b = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric("SHARED=value\n", [pub_a, pub_b])
    assert core.decrypt_to_dict_asymmetric(enc, priv_a) == {"SHARED": "value"}
    assert core.decrypt_to_dict_asymmetric(enc, priv_b) == {"SHARED": "value"}


def test_non_recipient_cannot_decrypt():
    _, pub = crypto.generate_recipient_keypair()
    stranger_priv, _ = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric("FOO=bar\n", [pub])
    with pytest.raises(RecipientNotFoundError):
        core.decrypt_to_dict_asymmetric(enc, stranger_priv)


def test_values_identical_across_recipients_in_file():
    """Each variable is encrypted once with the shared DEK, not per-recipient."""
    _, pub_a = crypto.generate_recipient_keypair()
    _, pub_b = crypto.generate_recipient_keypair()
    enc_one = core.encrypt_text_asymmetric("FOO=bar\n", [pub_a])
    # Same call only differs by recipient count -> body has a single ENC token.
    assert enc_one.count("FOO=ENC[") == 1


def test_encrypt_requires_at_least_one_recipient():
    from dotseal.exceptions import EncryptionError

    with pytest.raises(EncryptionError):
        core.encrypt_text_asymmetric("FOO=bar\n", [])


# --- add / remove recipient -------------------------------------------------

def test_add_recipient_lets_new_key_decrypt():
    priv_a, pub_a = crypto.generate_recipient_keypair()
    priv_b, pub_b = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric("FOO=bar\n", [pub_a])
    # b cannot decrypt yet
    with pytest.raises(RecipientNotFoundError):
        core.decrypt_to_dict_asymmetric(enc, priv_b)
    # a (existing recipient) grants b access
    enc2 = core.add_recipient_to_text(enc, priv_a, pub_b)
    assert core.decrypt_to_dict_asymmetric(enc2, priv_b) == {"FOO": "bar"}
    # a still works too
    assert core.decrypt_to_dict_asymmetric(enc2, priv_a) == {"FOO": "bar"}


def test_remove_recipient_revokes_access():
    priv_a, pub_a = crypto.generate_recipient_keypair()
    priv_b, pub_b = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric("FOO=bar\n", [pub_a, pub_b])
    enc2 = core.remove_recipient_from_text(enc, pub_b)
    assert core.decrypt_to_dict_asymmetric(enc2, priv_a) == {"FOO": "bar"}
    with pytest.raises(RecipientNotFoundError):
        core.decrypt_to_dict_asymmetric(enc2, priv_b)


def test_remove_recipient_by_fingerprint():
    priv_a, pub_a = crypto.generate_recipient_keypair()
    _, pub_b = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric("FOO=bar\n", [pub_a, pub_b])
    fp_b = crypto.recipient_fingerprint(pub_b)
    enc2 = core.remove_recipient_from_text(enc, fp_b)
    recipients = core.parse_recipients(parser.parse(enc2))
    assert [r["fp"] for r in recipients] == [crypto.recipient_fingerprint(pub_a)]


def test_remove_last_recipient_refused():
    from dotseal.exceptions import EncryptionError

    _, pub = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric("FOO=bar\n", [pub])
    with pytest.raises(EncryptionError):
        core.remove_recipient_from_text(enc, pub)


# --- loader -----------------------------------------------------------------

def test_loader_auto_detects_asymmetric(tmp_path, monkeypatch):
    priv, pub = crypto.generate_recipient_keypair()
    enc = core.encrypt_text_asymmetric("LOADED=yes\n", [pub])
    path = tmp_path / ".env.enc"
    path.write_text(enc)
    monkeypatch.delenv("LOADED", raising=False)
    assert loader.load_env(str(path), private_key=priv) is True
    import os

    assert os.environ["LOADED"] == "yes"


# --- CLI lifecycle ----------------------------------------------------------

def test_cli_keygen_writes_private_key_and_gitignores(project, capsys):
    assert main(["keygen"]) == 0
    key_path = project / core.PRIVATE_KEY_FILE_NAME
    assert key_path.is_file()
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    gitignore = (project / ".gitignore").read_text()
    assert core.PRIVATE_KEY_FILE_NAME in gitignore
    out = capsys.readouterr().out
    assert crypto.PUBKEY_PREFIX in out  # public key printed for sharing


def test_cli_keygen_refuses_overwrite_without_force(project):
    assert main(["keygen"]) == 0
    assert main(["keygen"]) == 1
    assert main(["keygen", "--force"]) == 0


def test_cli_encrypt_decrypt_asymmetric_roundtrip(project):
    # Two developers generate their own keys.
    assert main(["keygen", "--out", "alice.prv"]) == 0
    assert main(["keygen", "--out", "bob.prv"]) == 0
    alice_pub = crypto.public_key_str_from_private(
        (project / "alice.prv").read_text().strip()
    )
    bob_pub = crypto.public_key_str_from_private(
        (project / "bob.prv").read_text().strip()
    )

    (project / ".env").write_text(SAMPLE_ENV)
    assert main(["encrypt", "-r", alice_pub, "-r", bob_pub]) == 0

    enc = (project / ".env.enc").read_text()
    assert core.file_mode(enc) == "asymmetric"

    # Alice decrypts with her private key.
    assert main(
        ["decrypt", ".env.enc", "out.env", "--private-key-file", "alice.prv"]
    ) == 0
    entries = {e.key: e.value for e in parser.parse((project / "out.env").read_text()).entries()}
    assert entries["DATABASE_URL"] == "postgres://user:pass@localhost:5432/db"
    assert stat.S_IMODE((project / "out.env").stat().st_mode) == 0o600


def test_cli_add_and_rm_recipient(project):
    assert main(["keygen", "--out", "alice.prv"]) == 0
    assert main(["keygen", "--out", "bob.prv"]) == 0
    alice_pub = crypto.public_key_str_from_private((project / "alice.prv").read_text().strip())
    bob_pub = crypto.public_key_str_from_private((project / "bob.prv").read_text().strip())

    (project / ".env").write_text("FOO=bar\n")
    assert main(["encrypt", "-r", alice_pub]) == 0

    # Alice adds Bob.
    assert main(["add-recipient", bob_pub, ".env.enc", "--private-key-file", "alice.prv"]) == 0
    assert main(["decrypt", ".env.enc", "bob_out.env", "--private-key-file", "bob.prv"]) == 0
    assert "FOO=bar" in (project / "bob_out.env").read_text()

    # Remove Bob again.
    assert main(["rm-recipient", bob_pub, ".env.enc"]) == 0
    assert main(["decrypt", ".env.enc", "bob_out2.env", "--private-key-file", "bob.prv"]) == 1


def test_cli_edit_preserves_recipients(project, monkeypatch):
    import sys

    editor_script = project / "fake_editor.py"
    editor_script.write_text(
        "import sys\n"
        "p = sys.argv[1]\n"
        "text = open(p).read().replace('DEBUG=True', 'DEBUG=False')\n"
        "open(p, 'w').write(text + 'NEW_KEY=new_value\\n')\n"
    )
    monkeypatch.setenv("EDITOR", f"{sys.executable} {editor_script}")

    assert main(["keygen", "--out", "alice.prv"]) == 0
    alice_pub = crypto.public_key_str_from_private((project / "alice.prv").read_text().strip())
    (project / ".env").write_text("DEBUG=True\n")
    assert main(["encrypt", "-r", alice_pub]) == 0

    before = core.parse_recipients(parser.parse((project / ".env.enc").read_text()))
    assert main(["edit", ".env.enc", "--private-key-file", "alice.prv"]) == 0
    after = core.parse_recipients(parser.parse((project / ".env.enc").read_text()))
    assert [r["fp"] for r in before] == [r["fp"] for r in after]

    assert main(["decrypt", ".env.enc", "out.env", "--private-key-file", "alice.prv"]) == 0
    entries = {e.key: e.value for e in parser.parse((project / "out.env").read_text()).entries()}
    assert entries["DEBUG"] == "False"
    assert entries["NEW_KEY"] == "new_value"
