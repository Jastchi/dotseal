# secure-dotenv

An offline-first, **Git-friendly** encrypted environment-variable manager for Python, inspired by [Mozilla SOPS](https://github.com/getsops/sops) but built natively for the Python ecosystem.

`secure-dotenv` performs **structural encryption**: it leaves your `.env` **keys in cleartext** and encrypts only the **values**. The result is a `.env.enc` file you can safely commit, review in pull requests, and merge — because the diff still shows *which* variables changed, just not their secret contents.

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

---

## Installation

```bash
pip install secure-dotenv
```

Requires Python 3.9+.

---

## Quickstart

```bash
# 1. Generate a master key (saved to .secure-dotenv.key and gitignored)
secure-dotenv init

# 2. Write a normal .env file
cat > .env <<'EOF'
DATABASE_URL=postgres://user:pass@localhost:5432/db
DEBUG=True
API_KEY=super-secret
EOF

# 3. Encrypt it → .env.enc (commit this; never commit .env or the key)
secure-dotenv encrypt

# 4. Decrypt when you need it back
secure-dotenv decrypt
```

### What gets committed?

| File                  | Commit it? | Contents                                  |
| --------------------- | ---------- | ----------------------------------------- |
| `.env.enc`            | ✅ Yes      | Keys in cleartext, values encrypted       |
| `.env`                | ❌ No       | Full cleartext secrets                    |
| `.secure-dotenv.key`  | ❌ **Never**| The master key (auto-added to `.gitignore`) |

---

## CLI Reference

### `secure-dotenv init`
Generates a new cryptographically secure master key, writes it to `.secure-dotenv.key` (mode `0600`), and adds it to `.gitignore` (creating one if needed). Prints the key **fingerprint** (not the key) so you can verify which key encrypted a file. Use `--force` to replace an existing key (this makes existing `.env.enc` files undecryptable).

### `secure-dotenv encrypt [input] [output]`
Encrypts the values of a cleartext env file. Defaults: `.env` → `.env.enc`. Idempotent — values that are already encrypted are left untouched.

### `secure-dotenv decrypt [input] [output]`
Decrypts values back to cleartext. Defaults: `.env.enc` → `.env`. The output is written with owner-only (`0600`) permissions since it contains secrets.

### `secure-dotenv edit [file]`
SOPS-style editing. Decrypts `.env.enc` to a temporary file (mode `0600`), opens it in `$EDITOR` (falling back to `nano`), and re-encrypts on save. The temp file is securely overwritten and deleted afterward. If the file doesn't exist yet, you get a fresh template to start from.

### Common options
All commands except `init` accept:

- `-k, --key <base64>` — provide the master key directly (overrides env var and key file).
- `--key-file <path>` — use a specific key file instead of auto-discovery.

---

## Key Management

The master key is resolved in this order (first match wins):

1. An explicit `--key` argument (CLI) or `master_key=` argument (loader).
2. The `SECURE_DOTENV_MASTER_KEY` environment variable.
3. A local `.secure-dotenv.key` file (searched for in the current directory and upward through parent directories).

The key is a base64-encoded 32-byte (AES-256) value. Generate one programmatically with:

```python
from secure_dotenv import generate_master_key
print(generate_master_key())
```

---

## Runtime Loader (no cleartext on disk)

`load_env` is a **drop-in replacement for `python-dotenv`'s `load_dotenv`** — it just reads an encrypted `.env.enc` instead of a cleartext `.env`. Call it once at startup and your secrets are available as ordinary environment variables through the `os` module:

```python
import os
from secure_dotenv import load_env

# Resolves the key from SECURE_DOTENV_MASTER_KEY or .secure-dotenv.key
load_env()                                # reads ".env.enc" by default

os.getenv("DATABASE_URL")                 # now available, like any env var
```

Signature:

```python
def load_env(
    dotenv_path: str = ".env.enc",
    *,
    master_key: str | None = None,
    override: bool = False,
    encoding: str = "utf-8",
) -> bool:
    ...
```

- `override=False` (default): existing process env vars win (12-factor friendly).
- `override=True`: decrypted values overwrite anything already in `os.environ`.
- Returns `True` if at least one variable was set (matching `load_dotenv`). Want the values as a `dict` instead? Use `decrypt_to_dict` (below).

Other programmatic helpers:

```python
from secure_dotenv import encrypt_text, decrypt_text, decrypt_to_dict, load_key_bytes

key = load_key_bytes("BASE64KEY==")
enc = encrypt_text("FOO=bar\n", key)      # -> ".env.enc" text
cleartext = decrypt_text(enc, key)        # -> ".env" text
mapping = decrypt_to_dict(enc, key)       # -> {"FOO": "bar"}
```

---

## File Format

```env
# Generated by secure-dotenv. DO NOT EDIT VALUES MANUALLY.
DATABASE_URL=ENC[AES_GCM,data:<base64(nonce ‖ ciphertext ‖ tag)>]
DEBUG=ENC[AES_GCM,data:...]
# secure-dotenv: v=1 alg=AES_GCM key_fp=7ef08b59e6a945e4
```

- Each value's payload is `base64(12-byte nonce ‖ ciphertext ‖ GCM tag)`.
- The variable name is bound as AAD, so values cannot be swapped between keys.
- The trailing `# secure-dotenv:` metadata line records the algorithm and a **key fingerprint** (a one-way hash of the key). On decrypt, the fingerprint is checked first so a wrong key fails fast with a clear message instead of a cryptic crypto error.
- Comments and blank lines are preserved. Values containing spaces, `#`, or newlines are safely quoted/escaped on decryption.

---

## CI/CD Integration

The pattern is always the same: provide the master key via the `SECURE_DOTENV_MASTER_KEY` environment variable (from your platform's secret store), commit only `.env.enc`, and either decrypt to a file or load at runtime.

### GitHub Actions

Store the key as a repository/environment **secret** named `SECURE_DOTENV_MASTER_KEY`.

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      SECURE_DOTENV_MASTER_KEY: ${{ secrets.SECURE_DOTENV_MASTER_KEY }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install secure-dotenv

      # Option A: decrypt to a real .env for tools that expect a file
      - run: secure-dotenv decrypt .env.enc .env

      # Option B: load at runtime inside your app (no cleartext file)
      - run: python -c "from secure_dotenv import load_env; load_env(); import app"
```

### Docker

Bake only the encrypted file into the image and pass the key at runtime:

```dockerfile
FROM python:3.12-slim
WORKDIR /app
RUN pip install secure-dotenv
COPY .env.enc .
COPY . .
# App calls load_env() on startup.
CMD ["python", "main.py"]
```

```bash
docker run -e SECURE_DOTENV_MASTER_KEY="$(cat .secure-dotenv.key)" my-image
```

```python
# main.py
from secure_dotenv import load_env
load_env()   # picks up SECURE_DOTENV_MASTER_KEY from the container env
```

### Kubernetes

Store the master key in a `Secret` and expose it as `SECURE_DOTENV_MASTER_KEY`:

```yaml
env:
  - name: SECURE_DOTENV_MASTER_KEY
    valueFrom:
      secretKeyRef:
        name: secure-dotenv
        key: master-key
```

---

## Security Notes & Limitations

- **AES-256-GCM** provides confidentiality *and* integrity. Tampered ciphertext or a wrong key is rejected rather than silently producing garbage.
- **AAD binding** prevents an attacker who can edit the committed `.env.enc` from relocating a high-privilege secret onto a low-privilege variable name.
- **Key fingerprint** is a domain-separated SHA-256 hash truncated to 8 bytes; it reveals nothing about the key itself.
- **Memory hygiene is best-effort.** secure-dotenv overwrites the mutable key buffers it controls, but Python's immutable `str`/`bytes` and garbage collector mean secrets can still linger in memory. Do not rely on this for protection against an attacker with live process access.
- **The master key is the whole ballgame.** Anyone with the key can decrypt everything. Rotate it by re-encrypting with `secure-dotenv init --force` followed by `encrypt`, and store it only in trusted secret managers.
- This tool is a single-key symmetric scheme. It does **not** implement multi-recipient/asymmetric key sharing (a SOPS + `age`/KMS feature).

---

## Development

```bash
uv venv && uv pip install -e ".[dev]"
uv run pytest
```

The test suite covers crypto round-trips, edge-case values (empty strings, `!!@#$%=`, unicode, multi-line, large), structural parsing, the runtime loader (asserting no side-effect files are written), and the full CLI lifecycle including `edit`.

## License

MIT
