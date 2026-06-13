# Key Management

## Symmetric key resolution

For symmetric files, key resolution order is:

1. `--key` CLI option or `master_key=` API argument.
2. `--key-file` CLI option (error if path is missing).
3. `DOTSEAL_MASTER_KEY` environment variable.
4. Local `.dotseal.key` (searched upward from current directory).

## Asymmetric private key resolution

For asymmetric files, private key resolution order is:

1. `--private-key` CLI option or `private_key=` API argument.
2. `--private-key-file` CLI option (error if path is missing).
3. `DOTSEAL_PRIVATE_KEY` environment variable.
4. Local `.dotseal.prv` (searched upward from current directory).

## Generation

```python
from dotseal import generate_master_key, generate_recipient_keypair

master = generate_master_key()
private_key, public_key = generate_recipient_keypair()
```

## Rotation

### When to use which command

| Scenario | Command |
|---|---|
| Master key compromised / periodic key rotation | `dotseal rotate --new-key-file .dotseal.key` |
| Teammate left; fully revoke future access | `rm-recipient` then `rotate` with remaining pubkeys |
| New teammate; grant access | `add-recipient` only — no DEK rotation needed |
| Changed one secret value | `dotseal set KEY=VALUE` |

### Symmetric key rotation

`dotseal rotate` decrypts with the old master key and re-encrypts with the new one, generating fresh nonces and a new key fingerprint. The file's `plain_keys` / `plain_key_regex` policy is preserved automatically.

```bash
# 1. Generate a new key (keeps the old one around temporarily)
cp .dotseal.key .dotseal.key.old
dotseal init --force

# 2. Rotate the file (old key falls back to ambient if --old-key-file is omitted)
dotseal rotate .env.enc \
  --old-key-file .dotseal.key.old \
  --new-key-file .dotseal.key

# 3. Update CI/CD to use the new DOTSEAL_MASTER_KEY value
# 4. Delete the old key file
rm .dotseal.key.old
```

If your current ambient key (env var or `.dotseal.key`) is the old key, you can omit `--old-key-file`:

```bash
dotseal rotate .env.enc --new-key-file /path/to/new.key
```

Inspect the result without overwriting:

```bash
dotseal rotate .env.enc --new-key-file .dotseal.key --output /tmp/test.enc
dotseal decrypt /tmp/test.enc /tmp/test.env
```

> **Note:** Old git commits remain decryptable with the old key. If the old key was compromised, rotate all secrets themselves (not just the key).

### Asymmetric revocation (after `rm-recipient`)

`rm-recipient` drops a recipient's slot from the current file but does not rotate the data key — the removed recipient can still decrypt older committed versions. To fully revoke access to *new* ciphertext:

```bash
# 1. Remove the departing teammate's slot
dotseal rm-recipient .env.enc dsk-pub-THEIR_FINGERPRINT

# 2. Collect the remaining teammates' public keys in recipients.txt (one per line)
# 3. Rotate: fresh DEK, wrapped only for the remaining recipients
dotseal rotate .env.enc \
  --recipients-file recipients.txt \
  --private-key-file .dotseal.prv

# Everyone NOT in recipients.txt loses access to the new ciphertext.
# They can still decrypt old commits where they were a recipient.
```

### Asymmetric revocation note

- `rm-recipient` removes the recipient slot from current file state.
- It does not rotate the existing data key (DEK), so older git history may remain decryptable by removed recipients.
- For full revocation, use `dotseal rotate` with `--recipients-file` after `rm-recipient`.

## Handling rules

- Never commit `.dotseal.key` or `.dotseal.prv`.
- Store keys in a secret manager for CI/CD.
- Treat key compromise as full secret compromise for corresponding encrypted history.

## See also

- [Usage and CLI](USAGE.md)
- [Asymmetric Mode](ASYMMETRIC.md)
- [Deployment](DEPLOYMENT.md)
