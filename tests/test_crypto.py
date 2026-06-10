import base64

import pytest

from dotseal import crypto
from dotseal.exceptions import DecryptionError, InvalidMasterKeyError


def test_generate_master_key_is_32_bytes_base64():
    key = crypto.generate_master_key()
    raw = base64.b64decode(key, validate=True)
    assert len(raw) == crypto.KEY_SIZE


def test_load_key_bytes_roundtrip():
    key = crypto.generate_master_key()
    assert crypto.load_key_bytes(key) == base64.b64decode(key)


@pytest.mark.parametrize("bad", ["", "   ", "not-base64!!!", base64.b64encode(b"short").decode()])
def test_load_key_bytes_rejects_invalid(bad):
    with pytest.raises(InvalidMasterKeyError):
        crypto.load_key_bytes(bad)


def test_fingerprint_is_stable_and_short():
    raw = base64.b64decode(crypto.generate_master_key())
    fp1 = crypto.key_fingerprint(raw)
    fp2 = crypto.key_fingerprint(raw)
    assert fp1 == fp2
    assert len(fp1) == 16
    # different key -> different fingerprint (overwhelmingly likely)
    other = base64.b64decode(crypto.generate_master_key())
    assert crypto.key_fingerprint(other) != fp1


def test_encrypt_decrypt_roundtrip():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    token = crypto.encrypt_value(key, "postgres://u:p@h/db", aad="DATABASE_URL")
    assert token.startswith("ENC[AES_GCM,data:") and token.endswith("]")
    assert crypto.decrypt_value(key, token, aad="DATABASE_URL") == "postgres://u:p@h/db"


def test_encrypt_is_nondeterministic():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    a = crypto.encrypt_value(key, "same", aad="K")
    b = crypto.encrypt_value(key, "same", aad="K")
    assert a != b  # fresh nonce each time


def test_wrong_key_fails_cleanly():
    k1 = crypto.load_key_bytes(crypto.generate_master_key())
    k2 = crypto.load_key_bytes(crypto.generate_master_key())
    token = crypto.encrypt_value(k1, "secret", aad="K")
    with pytest.raises(DecryptionError):
        crypto.decrypt_value(k2, token, aad="K")


def test_aad_mismatch_fails():
    """A ciphertext for one key name must not decrypt under another (no swapping)."""
    key = crypto.load_key_bytes(crypto.generate_master_key())
    token = crypto.encrypt_value(key, "secret", aad="ADMIN_TOKEN")
    with pytest.raises(DecryptionError):
        crypto.decrypt_value(key, token, aad="GUEST_TOKEN")


def test_tampered_ciphertext_fails():
    key = crypto.load_key_bytes(crypto.generate_master_key())
    token = crypto.encrypt_value(key, "secret", aad="K")
    # flip a character inside the payload
    payload = token[len(crypto.ENC_PREFIX):-1]
    flipped = ("A" if payload[0] != "A" else "B") + payload[1:]
    tampered = f"{crypto.ENC_PREFIX}{flipped}]"
    with pytest.raises(DecryptionError):
        crypto.decrypt_value(key, tampered, aad="K")


@pytest.mark.parametrize("value", ["", "!!@#$%=", "héllo wörld", "a" * 5000, "line1\nline2"])
def test_roundtrip_edge_values(value):
    key = crypto.load_key_bytes(crypto.generate_master_key())
    token = crypto.encrypt_value(key, value, aad="K")
    assert crypto.decrypt_value(key, token, aad="K") == value
