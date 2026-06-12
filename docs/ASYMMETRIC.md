# Asymmetric Mode

The symmetric master key is great for one person or a small trusted team — but it has to be distributed out-of-band, and revoking one person means rotating the key for everyone. For teams, dotseal offers an **opt-in asymmetric mode** modeled on SOPS + `age`, using **X25519** — still pure Python, still zero extra dependencies.

## How it works (envelope encryption)

1. A single random **data key (DEK)** encrypts every value in the file (exactly like the symmetric path).
2. The DEK is then **wrapped** once per recipient using their X25519 public key (ephemeral-static ECDH → HKDF-SHA256 → AES-256-GCM).
3. Each developer unwraps the DEK with their own private key, then decrypts the values.

The body grows `O(variables)`; the recipient header grows `O(developers)`. Adding a teammate appends one small header line — **no value re-encryption, and no secret is ever transferred between people.**

## Workflow

```bash
# 1. Each developer generates their own key pair, once.
#    Writes .dotseal.prv (gitignored, mode 0600) and prints the PUBLIC key.
dotseal keygen

# 2. Encrypt for one or more recipients (their public keys, dsk-pub-...).
dotseal encrypt --recipient dsk-pub-ALICE... --recipient dsk-pub-BOB...

# 3. Each recipient decrypts with their own private key (auto-discovered
#    from .dotseal.prv, or pass it explicitly).
dotseal decrypt --private-key-file .dotseal.prv

# 4. Grant a new teammate access later (you must already be a recipient).
dotseal add-recipient dsk-pub-CAROL... .env.enc --private-key-file .dotseal.prv

# 5. Revoke a teammate's slot.
dotseal rm-recipient dsk-pub-CAROL... .env.enc
```

Public keys (`dsk-pub-...`) are safe to commit/share; private keys (`dsk-prv-...`) must stay secret. You can keep a list of recipients in a file (one `dsk-pub-...` per line, `#` comments allowed) and pass it with `--recipients-file`.

## Key resolution

The private key is resolved in this order (first match wins):

1. An explicit `--private-key` argument (CLI) or `private_key=` argument (loader).
2. An explicit `--private-key-file` path (an error if the file does not exist).
3. The `DOTSEAL_PRIVATE_KEY` environment variable.
4. A local `.dotseal.prv` file (searched for in the current directory and upward).

`dotseal decrypt`, `dotseal edit`, and `load_env()` **auto-detect** whether a file is symmetric or asymmetric from its metadata — you just supply the matching key material.

## Same name, different value per developer?

Envelope encryption gives every recipient the **same** value for a variable. If you genuinely need different developers to receive *different values for the same variable name*, that requires storing one ciphertext per developer for that variable — a separate "per-recipient override" concept that is not part of this release.

## Revocation caveat

`rm-recipient` drops a recipient's wrapped-DEK slot but does **not** rotate the DEK, so a removed recipient can still decrypt older committed versions from git history. To fully revoke, re-encrypt from cleartext (which generates a fresh DEK).

## Programmatic API

```python
from dotseal import (
    generate_recipient_keypair,
    encrypt_text_asymmetric,
    decrypt_text_asymmetric,
)

priv, pub = generate_recipient_keypair()
enc = encrypt_text_asymmetric("FOO=bar\n", [pub])   # -> ".env.enc" text
cleartext = decrypt_text_asymmetric(enc, priv)       # -> ".env" text
```

See also [File Format](FILE_FORMAT.md) for the `v=2` on-disk layout, [Usage and CLI](USAGE.md) for command details, and [Key Management](KEY_MANAGEMENT.md) for rotation and handling guidance.
