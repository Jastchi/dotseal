# Contributing to dotseal

Thanks for taking the time to contribute. dotseal is a security-focused tool, so correctness and careful review matter more than speed.

## Before you start

- Check [open issues](https://github.com/Jastchi/dotseal/issues) to avoid duplicating work.
- For non-trivial changes, open an issue first so we can align on the approach before you write code.
- Security vulnerabilities must **not** be reported via issues — see [SECURITY.md](SECURITY.md).

## Setup

```bash
git clone https://github.com/Jastchi/dotseal.git
cd dotseal
uv sync --extra dev
prek install
```

[prek](https://github.com/j178/prek) is a drop-in replacement for [pre-commit](https://pre-commit.com) — same `.pre-commit-config.yaml` format, but a single Rust binary with no Python runtime required. Hooks run faster and share toolchains instead of creating isolated virtualenvs per hook.

## Running tests and checks

```bash
prek run --all-files   # lint + type checks (same hooks as git commit)
uv run pytest          # full test suite
```

Individual commands if you prefer:

```bash
uv run ruff check .    # linting
uv run ty check        # type checking
```

All checks must pass before a PR is merged.

CI runs the full test suite on Python 3.9 through 3.14 (see `.github/workflows/test.yml`). The test suite covers crypto round-trips, edge-case values (empty strings, `!!@#$%=`, unicode, multi-line, large), structural parsing, the runtime loader (asserting no side-effect files are written), and the full CLI lifecycle including `edit`.

## Making a change

1. Fork the repo and create a branch from `main`:
   ```bash
   git checkout -b fix/short-description
   # or
   git checkout -b feat/short-description
   ```
2. Write your change and add or update tests.
3. Run the full check suite locally (see above).
4. Open a pull request against `main`.

Branch naming: `fix/`, `feat/`, `docs/`, or `chore/` prefix followed by a short kebab-case description.

## Commit style

Use the imperative mood in the subject line: `Add`, `Fix`, `Remove`, not `Added`, `Fixed`, `Removed`.

```
Fix nonce reuse when encrypting empty values

Previously, a zero-length value path bypassed the nonce generation
and always wrote the same 12-byte sequence.
```

## Cryptography changes

Any change to the encryption, decryption, key derivation, or AAD binding logic requires a clear explanation in the PR of why the change is safe. These PRs will receive extra scrutiny. See [docs/FILE_FORMAT.md](docs/FILE_FORMAT.md) for the on-disk layout.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Be respectful and constructive.
