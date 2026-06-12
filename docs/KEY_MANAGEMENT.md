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

## Rotation guidance

Symmetric rotation:

1. Decrypt with current key.
2. Generate a fresh key (`dotseal init --force` or equivalent).
3. Re-encrypt from cleartext.

Asymmetric revocation note:

- `rm-recipient` removes the recipient slot from current file state.
- It does not rotate the existing data key (DEK), so older git history may remain decryptable by removed recipients.
- For full revocation, re-encrypt from cleartext to generate a new DEK.

## Handling rules

- Never commit `.dotseal.key` or `.dotseal.prv`.
- Store keys in a secret manager for CI/CD.
- Treat key compromise as full secret compromise for corresponding encrypted history.

See also:

- [Usage and CLI](USAGE.md)
- [Asymmetric mode](ASYMMETRIC.md)
- [Deployment](DEPLOYMENT.md)
