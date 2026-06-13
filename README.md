# dotseal

[![Tests](https://github.com/Jastchi/dotseal/actions/workflows/test.yml/badge.svg)](https://github.com/Jastchi/dotseal/actions/workflows/test.yml)
[![Lint](https://github.com/Jastchi/dotseal/actions/workflows/lint.yml/badge.svg)](https://github.com/Jastchi/dotseal/actions/workflows/lint.yml)
[![CodeQL](https://github.com/Jastchi/dotseal/actions/workflows/codeql.yml/badge.svg)](https://github.com/Jastchi/dotseal/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/github/Jastchi/dotseal/graph/badge.svg?token=N2N2FHGQBU)](https://codecov.io/github/Jastchi/dotseal)
[![PyPI](https://img.shields.io/pypi/v/dotseal)](https://pypi.org/project/dotseal/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://pypi.org/project/dotseal/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Git-friendly encrypted `.env` files with cleartext keys and sealed values.

`dotseal` encrypts only variable values, so you can safely commit `.env.enc`, review diffs, and keep secrets out of git history.

```diff
  DATABASE_URL=ENC[AES_GCM,data:Zm9vYmFy...]
- DEBUG=ENC[AES_GCM,data:TXVzaWM=]
+ DEBUG=ENC[AES_GCM,data:b3RoZXI=]
  API_KEY=ENC[AES_GCM,data:c2VjcmV0...]
```

## Installation

```bash
pip install dotseal
```

Requires Python 3.9+. Using `uv`? `uv add dotseal`.

## Quickstart

```bash
# 1) Generate a local key (saved to .dotseal.key and gitignored)
dotseal init

# 2) Encrypt .env -> .env.enc (commit .env.enc only)
dotseal encrypt

# 3) Decrypt when needed
dotseal decrypt
```

Runtime load (no cleartext file required):

```python
from dotseal import load_env

load_env()  # reads .env.enc and injects decrypted values into os.environ
```

## Not sure which mode to use?

- Solo or small trusted setup: start with symmetric mode (`dotseal init` + `dotseal encrypt`).
- Team sharing without distributing one shared secret: use asymmetric mode.
- If you are unsure, start symmetric and switch later when sharing/revocation needs grow.
- Details: [Asymmetric mode](https://github.com/Jastchi/dotseal/blob/main/docs/ASYMMETRIC.md), [Key management](https://github.com/Jastchi/dotseal/blob/main/docs/KEY_MANAGEMENT.md).

## What gets committed?

| File | Commit it? | Why |
| --- | --- | --- |
| `.env.enc` | Yes | Encrypted values with reviewable keys |
| `.env` | No | Cleartext secrets |
| `.dotseal.key` | Never | Symmetric master key |
| `.dotseal.prv` | Never | Asymmetric private key |
| `dsk-pub-...` | Yes | Asymmetric public keys are safe to share |

## Documentation

Use the docs as the source of truth for all details:

- [Documentation index](https://github.com/Jastchi/dotseal/blob/main/docs/README.md)
- [Usage and CLI](https://github.com/Jastchi/dotseal/blob/main/docs/USAGE.md)
- [Key management and rotation](https://github.com/Jastchi/dotseal/blob/main/docs/KEY_MANAGEMENT.md)
- [Asymmetric mode](https://github.com/Jastchi/dotseal/blob/main/docs/ASYMMETRIC.md)
- [CI/CD and deployment](https://github.com/Jastchi/dotseal/blob/main/docs/DEPLOYMENT.md)
- [On-disk file format](https://github.com/Jastchi/dotseal/blob/main/docs/FILE_FORMAT.md)
- [Editor integration](https://github.com/Jastchi/dotseal/blob/main/docs/EDITORS.md)

## Security

- AES-256-GCM authenticated encryption with per-value nonces.
- Variable names are bound as AAD, so ciphertext cannot be swapped across keys.
- Integrity is per value (review `.env.enc` changes like code changes).
- Selective encryption (`--plain-key`, `--plain-key-regex`) leaves chosen values readable in the committed file and in git history; use only for non-secrets.

Report vulnerabilities privately via [SECURITY.md](https://github.com/Jastchi/dotseal/blob/main/SECURITY.md).

## Contributing

See [CONTRIBUTING.md](https://github.com/Jastchi/dotseal/blob/main/CONTRIBUTING.md).

## License

MIT
