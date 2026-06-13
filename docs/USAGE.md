# Usage and CLI

## Install

```bash
pip install dotseal
```

Requires Python 3.9+.

## Quickstart (symmetric mode)

```bash
# Generate a new key in .dotseal.key (gitignored, mode 0600)
dotseal init

# Encrypt .env -> .env.enc
dotseal encrypt

# Decrypt .env.enc -> .env
dotseal decrypt
```

Commit `.env.enc`; do not commit `.env` or private key files.

## Runtime loading

`load_env` is a drop-in alternative to `python-dotenv` style startup loading:

```python
import os
from dotseal import load_env

load_env()
print(os.getenv("DATABASE_URL"))
```

- `override=False` (default): existing process variables win.
- `override=True`: decrypted values overwrite process variables.
- Mode is auto-detected from metadata (`v=1` symmetric, `v=2` asymmetric).

Asymmetric runtime example:

```bash
export DOTSEAL_PRIVATE_KEY="dsk-prv-..."
python -c "from dotseal import load_env; load_env('.env.enc')"
```

## CLI reference

| Command | Purpose |
| --- | --- |
| `init` | Generate symmetric master key (`.dotseal.key`) |
| `keygen` | Generate asymmetric recipient keypair |
| `encrypt [in] [out]` | Encrypt values (`.env` -> `.env.enc` by default) |
| `decrypt [in] [out]` | Decrypt values (`.env.enc` -> `.env` by default) |
| `edit [file]` | Edit encrypted file safely in `$EDITOR` |
| `add-recipient <pubkey> [file]` | Add recipient to asymmetric file |
| `rm-recipient <pubkey-or-fingerprint> [file]` | Remove recipient slot from asymmetric file |

Key options:

- Symmetric: `--key`, `--key-file`
- Asymmetric: `--private-key`, `--private-key-file`
- Selective encryption: `--plain-key KEY` (repeatable), `--plain-key-regex REGEX` (repeatable; full key match)

## See also

- [Key Management](KEY_MANAGEMENT.md)
- [Asymmetric Mode](ASYMMETRIC.md)
- [File Format](FILE_FORMAT.md)
