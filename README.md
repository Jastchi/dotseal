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

Requires Python 3.9+. Using `uv`? `uv add dotseal`.

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

## Runtime Loader

`load_env` is a **drop-in replacement for `python-dotenv`'s `load_dotenv`** — call it once at startup and secrets are available through `os.environ`, with no cleartext file on disk:

```python
import os
from dotseal import load_env

load_env()  # reads ".env.enc"; key from DOTSEAL_MASTER_KEY or .dotseal.key
os.getenv("DATABASE_URL")
```

- `override=False` (default): existing process env vars win (12-factor friendly).
- `override=True`: decrypted values overwrite `os.environ`.
- Pass `master_key` for symmetric files or `private_key` for asymmetric ones (both fall back to env vars / key files). Mode is auto-detected from file metadata.

Other helpers: `encrypt_text`, `decrypt_text`, `decrypt_to_dict`, `load_key_bytes`. Run `dotseal <command> --help` for the full CLI and API surface.

---

## CLI Reference

| Command | Purpose |
| ------- | ------- |
| `init` | Generate a symmetric master key (`.dotseal.key`, mode `0600`, auto-gitignored) |
| `keygen` | Generate an X25519 recipient key pair (asymmetric mode) |
| `encrypt [in] [out]` | Seal values (default `.env` → `.env.enc`); idempotent for same-key ciphertexts |
| `decrypt [in] [out]` | Unseal values (default `.env.enc` → `.env`, mode `0600`) |
| `edit [file]` | SOPS-style edit in `$EDITOR`; unchanged values keep their ciphertext |
| `add-recipient <pubkey> [file]` | Grant access to an asymmetric file without re-encrypting values |
| `rm-recipient <fp> [file]` | Remove a recipient slot (does not rotate the data key) |

**`edit` notes:** GUI editors must block until closed (`EDITOR="code --wait"`). If re-encryption fails, edits are preserved in a `0600` temp file so nothing is lost.

**Key options:** `-k/--key`, `--key-file` (symmetric); `--private-key`, `--private-key-file` (asymmetric). See `dotseal <command> --help` for all flags.

---

## Key Management

The master key is resolved in this order (first match wins):

1. An explicit `--key` argument (CLI) or `master_key=` argument (loader).
2. An explicit `--key-file` path (an error if the file does not exist).
3. The `DOTSEAL_MASTER_KEY` environment variable.
4. A local `.dotseal.key` file (searched upward from the current directory).

```python
from dotseal import generate_master_key
print(generate_master_key())  # base64-encoded 32-byte AES-256 key
```

---

## Asymmetric Mode

For teams that need to share a file **without exchanging a secret**, dotseal supports opt-in **X25519 multi-recipient** envelope encryption:

```bash
dotseal keygen
dotseal encrypt --recipient dsk-pub-ALICE... --recipient dsk-pub-BOB...
dotseal decrypt --private-key-file .dotseal.prv
```

Public keys (`dsk-pub-...`) are safe to commit; private keys (`dsk-prv-...`) are not. `rm-recipient` does not rotate the data key — a removed recipient can still decrypt older git history. Re-encrypt from cleartext for full revocation.

Full guide: [docs/ASYMMETRIC.md](docs/ASYMMETRIC.md).

---

## CI/CD

Set `DOTSEAL_MASTER_KEY` from your platform's secret store, commit only `.env.enc`, then decrypt to a file or call `load_env()` at runtime:

```yaml
env:
  DOTSEAL_MASTER_KEY: ${{ secrets.DOTSEAL_MASTER_KEY }}
steps:
  - run: pip install dotseal
  - run: dotseal decrypt .env.enc .env          # or load_env() in your app
```

Docker, Kubernetes, and fuller examples: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

---

## Security & Limitations

- **Integrity is per value, not per file.** An attacker with write access can delete, duplicate, or replay old ciphertexts from git history — review `.env.enc` diffs like any other change.
- **Memory hygiene is best-effort.** Python's immutable strings and GC mean secrets can linger in process memory.
- **The master key is the whole ballgame (symmetric mode).** Store it only in trusted secret managers; rotate with `decrypt` → `init --force` → `encrypt`.
- **No KMS / Vault / PGP backends** — dotseal stays offline-first and pure Python.

Report vulnerabilities privately via [SECURITY.md](SECURITY.md). On-disk layout: [docs/FILE_FORMAT.md](docs/FILE_FORMAT.md).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, checks, and PR guidelines.

## License

MIT
