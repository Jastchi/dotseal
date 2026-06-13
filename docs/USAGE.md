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

## Command examples

```bash
# Symmetric setup
dotseal init
dotseal init --force              # replace an existing .dotseal.key (breaks old .env.enc files)

# Asymmetric keypair
dotseal keygen                    # writes .dotseal.prv (mode 0600) and prints the public key
dotseal keygen --print            # stdout only; nothing written to disk
dotseal keygen --out /path/to/my.prv

# Encrypt / decrypt (defaults: .env -> .env.enc and back)
dotseal encrypt
dotseal encrypt secrets.env out.enc
dotseal decrypt out.enc secrets.env

# Override key lookup (see Key Management for resolution order)
dotseal encrypt --key-file /run/secrets/dotseal.key
dotseal decrypt --private-key "dsk-prv-..."

# Asymmetric encrypt for multiple recipients
dotseal encrypt -r dsk-pub-alice... -r dsk-pub-bob...
dotseal encrypt --recipients-file team-pubkeys.txt

# Selective encryption: keep some keys readable in the committed file
dotseal encrypt --plain-key PUBLIC --plain-key DEBUG
dotseal encrypt --plain-key-regex 'PUBLIC_.+'

# Edit in place (decrypt -> $EDITOR -> re-encrypt; temp file is securely deleted)
dotseal edit
dotseal edit staging.env.enc --plain-key FEATURE_FLAG

# Recipient management (asymmetric files only)
dotseal add-recipient dsk-pub-newhire... .env.enc
dotseal rm-recipient 3f2a1b9c .env.enc   # fingerprint or full public key
```

## Flag behavior

### Symmetric keys (`init`, `encrypt`, `decrypt`, `edit`)

| Flag | Behavior |
| --- | --- |
| `--key` | Master key string (base64). Overrides env var and key file. |
| `--key-file` | Explicit path to a key file. Error if missing. Otherwise `.dotseal.key` is discovered upward from the input file directory. |
| `--force` (`init` only) | Overwrite an existing `.dotseal.key`. Existing `.env.enc` files encrypted with the old key become undecryptable. |

Resolution order when flags are omitted: `--key` → `--key-file` → `DOTSEAL_MASTER_KEY` → `.dotseal.key`. See [Key Management](KEY_MANAGEMENT.md).

### Asymmetric keys (`keygen`, `encrypt`, `decrypt`, `edit`, `add-recipient`)

| Flag | Behavior |
| --- | --- |
| `--private-key` | Recipient private key (`dsk-prv-…`). Overrides env var and key file. |
| `--private-key-file` | Explicit path to a private key file. Error if missing. Otherwise `.dotseal.prv` is discovered upward. |
| `-r` / `--recipient` | Recipient public key (`dsk-pub-…`). Repeatable. Passing any recipient switches `encrypt` / `edit` to asymmetric mode. |
| `--recipients-file` | One public key per line (`#` comments allowed). Combined with `-r`. |
| `--print` (`keygen` only) | Print private + public keys to stdout; do not write `.dotseal.prv`. |
| `--out` (`keygen` only) | Where to write the private key (default: `.dotseal.prv` in the current directory). |

Private key resolution order: `--private-key` → `--private-key-file` → `DOTSEAL_PRIVATE_KEY` → `.dotseal.prv`.

`add-recipient` requires a holder of an existing recipient private key to re-wrap the file's data key for the new public key. `rm-recipient` removes a recipient slot from the current file but does not rotate the data key; older git commits may still be decryptable by the removed recipient. See [Asymmetric Mode](ASYMMETRIC.md).

### Selective encryption (`encrypt`, `edit`)

| Flag | Behavior |
| --- | --- |
| `--plain-key KEY` | Keep this variable name unencrypted. Repeatable. |
| `--plain-key-regex REGEX` | Keep variable names matching this regex unencrypted. Repeatable. Uses Python `re.fullmatch` (entire key must match). |

Omit both flags to encrypt every value. On re-encrypt, omitting them preserves the policy stored in the file footer.

### Selective encryption policy

`--plain-key` and `--plain-key-regex` control which variable names stay plaintext in
the encrypted file. The chosen policy is recorded in the file footer (`plain_keys=…`,
`plain_re=…`). See [File Format](FILE_FORMAT.md) for token syntax.

Example committed file:

```env
PUBLIC=production
SECRET=ENC[AES_GCM,data:Zm9vYmFy...]
# dotseal: v=1 alg=AES_GCM key_fp=7ef08b59e6a945e4 plain_keys=PUBLIC
```

**Re-running `encrypt` on an already encrypted file is idempotent:** existing
`ENC[…]` values are left unchanged. Only new cleartext values are encrypted according
to the current policy. The footer metadata is always rewritten, so it may describe a
policy that does not match values that were encrypted in a previous run.

Passing only one of `--plain-key` / `--plain-key-regex` replaces that side of the
policy while keeping the other from the existing footer (for example, new explicit
keys but the same regex rules).

When a policy override would seal keys that were previously plaintext, dotseal prints a
warning listing the affected key names before writing.

| Goal | Command |
| --- | --- |
| Encrypt new cleartext keys under an updated policy | `dotseal encrypt` (on `.env` or a partially encrypted file) |
| Make a previously **plaintext** key encrypted | `dotseal encrypt --plain-key …` or `dotseal edit --plain-key …` |
| Make a previously **encrypted** key plaintext | `dotseal decrypt`, edit `.env`, then `dotseal encrypt --plain-key …`, **or** `dotseal edit --plain-key …` |

`dotseal edit` decrypts to a temp file, applies the policy on save, and can both seal
and unseal keys. Re-running `encrypt` alone cannot downgrade `ENC[…]` back to plain.

Decrypted output files are written with mode `0600`.

## Security considerations

- **Cleartext values are intentional.** Keys listed in `plain_keys` or matched by
  `plain_re` are stored as readable `KEY=value` lines in `.env.enc`. They are visible
  in git diffs, pull requests, and full repository history. Anyone with repo access can
  read them without a decryption key. Use selective encryption only for non-secret
  configuration (feature flags, public URLs, environment labels).
- **Variable names are always cleartext.** Even fully encrypted entries expose the key
  name in the committed file. Do not put sensitive information in key names.
- **Sealed values hide content, not existence.** Diffs show which keys changed; they do
  not reveal old or new secret values without the key.
- **Private keys and `.env` stay out of git.** See [Key Management](KEY_MANAGEMENT.md).

## See also

- [Key Management](KEY_MANAGEMENT.md)
- [Asymmetric Mode](ASYMMETRIC.md)
- [File Format](FILE_FORMAT.md)
