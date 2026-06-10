import os

import pytest

from secure_dotenv import core, crypto, loader
from secure_dotenv.exceptions import KeyFingerprintMismatchError


@pytest.fixture
def key_str():
    return crypto.generate_master_key()


def _write_enc(tmp_path, key_str, mapping):
    key_bytes = crypto.load_key_bytes(key_str)
    body = "\n".join(f"{k}={v}" for k, v in mapping.items()) + "\n"
    enc = core.encrypt_text(body, key_bytes)
    path = tmp_path / ".env.enc"
    path.write_text(enc)
    return str(path)


def test_loader_injects_into_environ_without_writing_files(tmp_path, key_str, monkeypatch):
    enc_path = _write_enc(tmp_path, key_str, {"DATABASE_URL": "postgres://x", "DEBUG": "True"})
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DEBUG", raising=False)

    before = set(os.listdir(tmp_path))
    loaded = loader.load_secure_dotenv(enc_path, master_key=key_str)
    after = set(os.listdir(tmp_path))

    assert before == after  # no side-effect files created
    assert os.environ["DATABASE_URL"] == "postgres://x"
    assert os.environ["DEBUG"] == "True"
    assert loaded == {"DATABASE_URL": "postgres://x", "DEBUG": "True"}


def test_loader_respects_existing_env_by_default(tmp_path, key_str, monkeypatch):
    enc_path = _write_enc(tmp_path, key_str, {"FOO": "from-file"})
    monkeypatch.setenv("FOO", "from-process")
    loader.load_secure_dotenv(enc_path, master_key=key_str)
    assert os.environ["FOO"] == "from-process"


def test_loader_override_true_overwrites(tmp_path, key_str, monkeypatch):
    enc_path = _write_enc(tmp_path, key_str, {"FOO": "from-file"})
    monkeypatch.setenv("FOO", "from-process")
    loader.load_secure_dotenv(enc_path, master_key=key_str, override=True)
    assert os.environ["FOO"] == "from-file"


def test_loader_uses_env_var_for_key(tmp_path, key_str, monkeypatch):
    enc_path = _write_enc(tmp_path, key_str, {"SECRET": "shh"})
    monkeypatch.setenv(core.ENV_VAR_NAME, key_str)
    monkeypatch.delenv("SECRET", raising=False)
    loader.load_secure_dotenv(enc_path)
    assert os.environ["SECRET"] == "shh"


def test_loader_wrong_key_raises(tmp_path, key_str, monkeypatch):
    enc_path = _write_enc(tmp_path, key_str, {"SECRET": "shh"})
    monkeypatch.delenv(core.ENV_VAR_NAME, raising=False)
    other = crypto.generate_master_key()
    with pytest.raises(KeyFingerprintMismatchError):
        loader.load_secure_dotenv(enc_path, master_key=other)


def test_loader_missing_file(tmp_path, key_str):
    with pytest.raises(FileNotFoundError):
        loader.load_secure_dotenv(str(tmp_path / "nope.env.enc"), master_key=key_str)
