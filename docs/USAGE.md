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

### Selective encryption policy

`--plain-key` and `--plain-key-regex` control which variable names stay plaintext in
the encrypted file. The chosen policy is recorded in the file footer (`plain_keys=…`,
`plain_regex=…`).

**Re-running `encrypt` on an already encrypted file is idempotent:** existing
`ENC[…]` values are left unchanged. Only new cleartext values are encrypted according
to the current policy. The footer metadata is always rewritten, so it may describe a
policy that does not match values that were encrypted in a previous run.

| Goal | Command |
| --- | --- |
| Encrypt new cleartext keys under an updated policy | `dotseal encrypt` (on `.env` or a partially encrypted file) |
| Make a previously **plaintext** key encrypted | `dotseal encrypt --plain-key …` or `dotseal edit --plain-key …` |
| Make a previously **encrypted** key plaintext | `dotseal decrypt`, edit `.env`, then `dotseal encrypt --plain-key …`, **or** `dotseal edit --plain-key …` |

`dotseal edit` decrypts to a temp file, applies the policy on save, and can both seal
and unseal keys. Re-running `encrypt` alone cannot downgrade `ENC[…]` back to plain.

## See also

- [Key Management](KEY_MANAGEMENT.md)
- [Asymmetric Mode](ASYMMETRIC.md)
- [File Format](FILE_FORMAT.md)
