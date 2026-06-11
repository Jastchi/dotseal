# dotseal

[![Tests](https://github.com/Jastchi/dotseal/actions/workflows/test.yml/badge.svg)](https://github.com/Jastchi/dotseal/actions/workflows/test.yml)
[![Lint](https://github.com/Jastchi/dotseal/actions/workflows/lint.yml/badge.svg)](https://github.com/Jastchi/dotseal/actions/workflows/lint.yml)
[![codecov](https://codecov.io/github/Jastchi/dotseal/graph/badge.svg?token=N2N2FHGQBU)](https://codecov.io/github/Jastchi/dotseal)
[![PyPI](https://img.shields.io/pypi/v/dotseal)](https://pypi.org/project/dotseal/)
[![Python](https://img.shields.io/pypi/pyversions/dotseal)](https://pypi.org/project/dotseal/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Git-friendly encrypted `.env` files with cleartext keys and sealed values — an offline-first environment-variable manager for Python, inspired by [Mozilla SOPS](https://github.com/getsops/sops) but built natively for the Python ecosystem.

`dotseal` performs **structural encryption**: it leaves your `.env` **keys in cleartext** and encrypts only the **values**. The result is a `.env.enc` file you can safely commit, review in pull requests, and merge — because the diff still shows *which* variables changed, just not their secret contents.

```diff
  DATABASE_URL=ENC[AES_GCM,data:Zm9vYmFy...]
- DEBUG=ENC[AES_GCM,data:TXVzaWM=]
+ DEBUG=ENC[AES_GCM,data:b3RoZXI=]
  API_KEY=ENC[AES_GCM,data:c2VjcmV0...]
```

- **No OS dependencies.** Pure Python on top of [`cryptography`](https://cryptography.io). No `age`, `gpg`, `sops`, `openssl` CLI, or Go binaries required.
- **Authenticated encryption.** AES-256-GCM (AEAD) with a fresh nonce per value.
- **Tamper-evident & swap-proof.** Each value is bound to its variable name as Additional Authenticated Data (AAD), so ciphertext can't be moved between keys.
- **Runtime loader.** Decrypt straight into `os.environ` — no cleartext file ever touches disk.
- **Two modes.** A simple **symmetric** master key (default) for solo/small trusted teams, or **asymmetric** multi-recipient envelope encryption (X25519, opt-in) so a team shares one file without ever exchanging a secret.

---

![dotseal demo](.github/demo.gif)

---

## Installation

```bash
pip install dotseal
```

Requires Python 3.8+. Using `uv`? `uv add dotseal`.

**VS Code / Cursor extension:** download the latest `.vsix` from [GitHub Releases](https://github.com/Jastchi/dotseal/releases) and install via *Extensions: Install from VSIX*.

---

## Quickstart

```bash
# 1. Generate a master key (saved to .dotseal.key and gitignored)
dotseal init

# 2. Write a normal .env file
cat > .env <<'EOF'
DATABASE_URL=postgres://user:pass@localhost:5432/db
DEBUG=True
API_KEY=super-secret
EOF

# 3. Encrypt it → .env.enc (commit this; never commit .env or the key)
dotseal encrypt

# 4. Decrypt when you need it back
dotseal decrypt
```

### What gets committed?

| File                  | Commit it? | Contents                                  |
| --------------------- | ---------- | ----------------------------------------- |
| `.env.enc`            | ✅ Yes      | Keys in cleartext, values encrypted       |
| `.env`                | ❌ No       | Full cleartext secrets                    |
| `.dotseal.key`        | ❌ **Never**| The symmetric master key (auto-added to `.gitignore`) |
| `.dotseal.prv`        | ❌ **Never**| Your asymmetric private key (auto-added to `.gitignore`) |
| `dsk-pub-...`         | ✅ Yes      | Recipient **public** keys are safe to commit/share |

---

## Python Usage

Drop-in replacement for `python-dotenv` — call it once at startup and your secrets are available through `os.environ`:

```python
from dotseal import load_env

load_env()  # reads .env.enc, decrypts into os.environ — no cleartext file on disk
os.getenv("DATABASE_URL")
```

The key is resolved automatically from `DOTSEAL_MASTER_KEY` or `.dotseal.key`. See [Runtime Loader](#runtime-loader-no-cleartext-on-disk) for the full API.

---

## CLI Reference

### `dotseal init`
Generates a new cryptographically secure master key (symmetric mode), writes it to `.dotseal.key` (mode `0600`), and adds it to `.gitignore` (creating one if needed). Prints the key **fingerprint** (not the key) so you can verify which key encrypted a file. Use `--force` to replace an existing key (this makes existing `.env.enc` files undecryptable).

### `dotseal keygen`
Generates an **X25519 recipient key pair** (asymmetric mode). Writes the private key to `.dotseal.prv` (mode `0600`, auto-gitignored) and prints the public key (`dsk-pub-...`) to share with whoever encrypts for you. Options: `--out <path>` to choose where the private key is written, `--force` to overwrite, and `--print` to print both halves to stdout instead of touching disk.

### `dotseal encrypt [input] [output]`
Encrypts the values of a cleartext env file. Defaults: `.env` → `.env.enc`. Idempotent — values that are already encrypted are left untouched. Pass `-r/--recipient <dsk-pub-...>` (repeatable) or `--recipients-file <path>` to use asymmetric multi-recipient mode; otherwise it uses the symmetric master key.

### `dotseal decrypt [input] [output]`
Decrypts values back to cleartext. Defaults: `.env.enc` → `.env`. Auto-detects symmetric vs. asymmetric from the file. The output is written with owner-only (`0600`) permissions since it contains secrets.

### `dotseal edit [file]`
SOPS-style editing. Decrypts `.env.enc` to a temporary file (mode `0600`), opens it in `$EDITOR` (falling back to `nano`), and re-encrypts on save. For asymmetric files the original data key and recipient list are preserved automatically. The temp file is securely overwritten and deleted afterward. If the file doesn't exist yet, you get a fresh template to start from.

### `dotseal add-recipient <pubkey> [file]`
Grants a new recipient access to an existing asymmetric file by wrapping its data key for the new public key. Requires a private key that is already a recipient (to unwrap the data key). Does not re-encrypt any values.

### `dotseal rm-recipient <pubkey-or-fingerprint> [file]`
Removes a recipient's wrapped-key slot from an asymmetric file. Does not rotate the data key (see the revocation caveat above).

### Common options
`encrypt`, `decrypt`, and `edit` accept the symmetric key options:

- `-k, --key <base64>` — provide the master key directly (overrides env var and key file).
- `--key-file <path>` — use a specific key file instead of auto-discovery.

`decrypt`, `edit`, and the recipient commands accept the asymmetric key options:

- `--private-key <dsk-prv-...>` — provide the recipient private key directly.
- `--private-key-file <path>` — use a specific private key file instead of auto-discovery.

---

## Key Management

The master key is resolved in this order (first match wins):

1. An explicit `--key` argument (CLI) or `master_key=` argument (loader).
2. The `DOTSEAL_MASTER_KEY` environment variable.
3. A local `.dotseal.key` file (searched for in the current directory and upward through parent directories).

The key is a base64-encoded 32-byte (AES-256) value. Generate one programmatically with:

```python
from dotseal import generate_master_key
print(generate_master_key())
```

---

## Asymmetric mode (multi-recipient, share without sharing a secret)

The symmetric master key is great for one person or a small trusted team — but it has to be distributed out-of-band, and revoking one person means rotating the key for everyone. For teams, dotseal offers an **opt-in asymmetric mode** modeled on SOPS + `age`, using **X25519** (the same elliptic-curve primitive `age` uses) — still pure Python, still zero extra dependencies.

### How it works (envelope encryption)

1. A single random **data key (DEK)** encrypts every value in the file (exactly like the symmetric path).
2. The DEK is then **wrapped** once per recipient using their X25519 public key (ephemeral-static ECDH → HKDF-SHA256 → AES-256-GCM).
3. Each developer unwraps the DEK with their own private key, then decrypts the values.

The body grows `O(variables)`; the recipient header grows `O(developers)`. Adding a teammate appends one small header line — **no value re-encryption, and no secret is ever transferred between people.**

### Workflow

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

### Key resolution for asymmetric files

The private key is resolved in this order (first match wins):

1. An explicit `--private-key` argument (CLI) or `private_key=` argument (loader).
2. The `DOTSEAL_PRIVATE_KEY` environment variable.
3. A local `.dotseal.prv` file (searched for in the current directory and upward).

`dotseal decrypt`, `dotseal edit`, and `load_env()` **auto-detect** whether a file is symmetric or asymmetric from its metadata — you just supply the matching key material.

### Same name, different value per developer?

Envelope encryption gives every recipient the **same** value for a variable. If you genuinely need different developers to receive *different values for the same variable name*, that requires storing one ciphertext per developer for that variable — a separate "per-recipient override" concept that is not part of this release.

> **Revocation caveat:** `rm-recipient` drops a recipient's wrapped-DEK slot but does **not** rotate the DEK, so a removed recipient can still decrypt older committed versions from git history. To fully revoke, re-encrypt from cleartext (which generates a fresh DEK).

### Programmatic API

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

---

## Runtime Loader (no cleartext on disk)

`load_env` is a **drop-in replacement for `python-dotenv`'s `load_dotenv`** — it just reads an encrypted `.env.enc` instead of a cleartext `.env`. Call it once at startup and your secrets are available as ordinary environment variables through the `os` module:

```python
import os
from dotseal import load_env

# Resolves the key from DOTSEAL_MASTER_KEY or .dotseal.key
load_env()                                # reads ".env.enc" by default

os.getenv("DATABASE_URL")                 # now available, like any env var
```

Signature:

```python
def load_env(
    dotenv_path: str = ".env.enc",
    *,
    master_key: str | None = None,
    private_key: str | None = None,
    override: bool = False,
    encoding: str = "utf-8",
) -> bool:
    ...
```

The mode is auto-detected: pass `master_key` for symmetric files, or `private_key` for asymmetric ones (both fall back to their respective env vars / key files).

- `override=False` (default): existing process env vars win (12-factor friendly).
- `override=True`: decrypted values overwrite anything already in `os.environ`.
- Returns `True` if at least one variable was set (matching `load_dotenv`). Want the values as a `dict` instead? Use `decrypt_to_dict` (below).

Other programmatic helpers:

```python
from dotseal import encrypt_text, decrypt_text, decrypt_to_dict, load_key_bytes

key = load_key_bytes("BASE64KEY==")
enc = encrypt_text("FOO=bar\n", key)      # -> ".env.enc" text
cleartext = decrypt_text(enc, key)        # -> ".env" text
mapping = decrypt_to_dict(enc, key)       # -> {"FOO": "bar"}
```

---

## File Format

### Symmetric (`v=1`)

```env
# Generated by dotseal. DO NOT EDIT VALUES MANUALLY.
DATABASE_URL=ENC[AES_GCM,data:<base64(nonce ‖ ciphertext ‖ tag)>]
DEBUG=ENC[AES_GCM,data:...]
# dotseal: v=1 alg=AES_GCM key_fp=7ef08b59e6a945e4
```

- Each value's payload is `base64(12-byte nonce ‖ ciphertext ‖ GCM tag)`.
- The variable name is bound as AAD, so values cannot be swapped between keys.
- The trailing `# dotseal:` metadata line records the algorithm and a **key fingerprint** (a one-way hash of the key). On decrypt, the fingerprint is checked first so a wrong key fails fast with a clear message instead of a cryptic crypto error.
- Comments and blank lines are preserved. Values containing spaces, `#`, or newlines are safely quoted/escaped on decryption.

### Asymmetric (`v=2`, multi-recipient)

```env
# Generated by dotseal. DO NOT EDIT VALUES MANUALLY.
DATABASE_URL=ENC[AES_GCM,data:...]
DEBUG=ENC[AES_GCM,data:...]
# dotseal:recipient fp=<fp> ephem=<base64 ephemeral pubkey> enc=<base64 wrapped DEK>
# dotseal:recipient fp=<fp> ephem=<base64 ephemeral pubkey> enc=<base64 wrapped DEK>
# dotseal: v=2 alg=AES_GCM+X25519
```

- Values are encrypted **once** with a shared data key (DEK), so the body is identical regardless of how many recipients there are.
- Each `# dotseal:recipient` line is the DEK wrapped for one recipient: `fp` is that recipient's public-key fingerprint, `ephem` is the per-wrap ephemeral X25519 public key, and `enc` is `base64(nonce ‖ AES-GCM(wrapped DEK))`.
- The footer's `alg=AES_GCM+X25519` / `v=2` is how dotseal auto-detects the mode on decrypt.

---

## CI/CD Integration

The pattern is always the same: provide the master key via the `DOTSEAL_MASTER_KEY` environment variable (from your platform's secret store), commit only `.env.enc`, and either decrypt to a file or load at runtime.

### GitHub Actions

Store the key as a repository/environment **secret** named `DOTSEAL_MASTER_KEY`.

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      DOTSEAL_MASTER_KEY: ${{ secrets.DOTSEAL_MASTER_KEY }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install dotseal

      # Option A: decrypt to a real .env for tools that expect a file
      - run: dotseal decrypt .env.enc .env

      # Option B: load at runtime inside your app (no cleartext file)
      - run: python -c "from dotseal import load_env; load_env(); import app"
```

### Docker

Bake only the encrypted file into the image and pass the key at runtime:

```dockerfile
FROM python:3.12-slim
WORKDIR /app
RUN pip install dotseal
COPY .env.enc .
COPY . .
# App calls load_env() on startup.
CMD ["python", "main.py"]
```

```bash
docker run -e DOTSEAL_MASTER_KEY="$(cat .dotseal.key)" my-image
```

```python
# main.py
from dotseal import load_env
load_env()   # picks up DOTSEAL_MASTER_KEY from the container env
```

### Kubernetes

Store the master key in a `Secret` and expose it as `DOTSEAL_MASTER_KEY`:

```yaml
env:
  - name: DOTSEAL_MASTER_KEY
    valueFrom:
      secretKeyRef:
        name: dotseal
        key: master-key
```

---

## Security Notes & Limitations

- **AES-256-GCM** provides confidentiality *and* integrity. Tampered ciphertext or a wrong key is rejected rather than silently producing garbage.
- **AAD binding** prevents an attacker who can edit the committed `.env.enc` from relocating a high-privilege secret onto a low-privilege variable name.
- **Key fingerprint** is a domain-separated SHA-256 hash truncated to 8 bytes; it reveals nothing about the key itself.
- **Memory hygiene is best-effort.** dotseal overwrites the mutable key buffers it controls, but Python's immutable `str`/`bytes` and garbage collector mean secrets can still linger in memory. Do not rely on this for protection against an attacker with live process access.
- **The master key is the whole ballgame (symmetric mode).** Anyone with the key can decrypt everything. Rotate it by re-encrypting with `dotseal init --force` followed by `encrypt`, and store it only in trusted secret managers.
- **Asymmetric mode** uses X25519 ECDH + HKDF-SHA256 + AES-256-GCM envelope encryption (the `age` construction). Multiple recipients can share one file without exchanging a secret; revocation via `rm-recipient` does not rotate the data key, so re-encrypt from cleartext for full revocation.
- All recipients of an asymmetric file decrypt the **same** value for a given variable. Per-recipient *different* values for the same variable name are not supported.
- dotseal does **not** integrate cloud KMS / Vault / PGP backends (a SOPS feature); it stays offline-first and pure Python.

---

## Development

```bash
uv venv && uv pip install -e ".[dev]"
uv run pytest
```

CI runs the full test suite on Python 3.8 through 3.14 (see `.github/workflows/test.yml`).

The test suite covers crypto round-trips, edge-case values (empty strings, `!!@#$%=`, unicode, multi-line, large), structural parsing, the runtime loader (asserting no side-effect files are written), and the full CLI lifecycle including `edit`.

## License

MIT
