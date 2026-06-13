# dotseal for VS Code and Cursor

Edit dotseal encrypted env files (`.env.enc`, `.env.production.enc`, and other dotenv-style names) as decrypted virtual documents. The extension opens a native editor buffer with cleartext values, then re-encrypts the real encrypted file on save.

The extension is self-contained TypeScript and does not require Python or the `dotseal` CLI at runtime.

## Usage

1. Open a workspace that contains an encrypted env file (e.g. `.env.enc`, `.env.production.enc`) and the matching `.dotseal.key`, or set `DOTSEAL_MASTER_KEY` before launching the editor.
2. Open the encrypted file.
3. The extension automatically redirects the file to a `dotseal:` virtual document that displays decrypted `.env` content.
4. Edit normally and save. The real encrypted file on disk is updated with encrypted values.

You can also run **Dotseal: Open Encrypted Env** from the command palette.

## Key Resolution

The extension resolves the master key in this order:

1. `dotseal.masterKey` setting, if provided.
2. `dotseal.keyFile` setting, if provided.
3. `DOTSEAL_MASTER_KEY` environment variable.
4. A `.dotseal.key` file discovered by walking upward from the encrypted env file's directory.

Prefer `DOTSEAL_MASTER_KEY` or `.dotseal.key` over storing key material in editor settings.

## Settings

- `dotseal.autoOpen`: automatically redirect dotenv-style encrypted env files (`.env.enc`, `.env.production.enc`, …) to the decrypted virtual editor. Defaults to `true`.
- `dotseal.keyFile`: optional path to a key file.
- `dotseal.masterKey`: optional base64 master key. This is supported for convenience, but storing secrets in editor settings is discouraged.
- `dotseal.plaintextKeys`: exact variable names to keep unencrypted when the extension creates a new encrypted file.
- `dotseal.plaintextKeyRegex`: regex patterns; keys that fully match any pattern are kept unencrypted when the extension creates a new encrypted file.

## Security Notes

Cleartext is not written to a `.env` file or temporary file by this extension. It lives in the VS Code/Cursor editor buffer and extension process memory while the virtual document is open.

This is still best-effort protection. Editor features, extensions, crash reporting, remote development hosts, or manual copy/paste can expose cleartext once it is displayed. Treat an open decrypted buffer like any other visible secret.

This initial version does not mask values or implement per-value reveal. The `dotseal:` document is a normal native editor buffer so existing editor features work naturally.

## Development

### Prerequisites

- [Node.js](https://nodejs.org) (LTS)
- [uv](https://docs.astral.sh/uv/) — only needed to run the Python conformance tests

### Setup

```bash
cd editors/vscode
npm install
```

### Running the extension locally

Open the `editors/vscode` folder in VS Code, then press **F5**. This starts esbuild in watch mode and launches a second **Extension Development Host** window with the extension loaded.

- Any `.ts` change triggers an automatic rebuild.
- After a rebuild, press `Ctrl+Shift+P` → **Developer: Reload Window** in the Extension Development Host to pick up the new code.
- Stop the session with **Shift+F5**.

### Test fixture

`test-project/` is a small [uv](https://docs.astral.sh/uv/) project for manual testing. It contains a committed `.env` with fake values; `.dotseal.key` and `.env.enc` are gitignored and generated locally.

**F5** runs `npm run watch`, which creates those fixtures automatically when they are missing. You can also generate them manually with `test-project/setup.sh`.

Open the Extension Development Host, then open `test-project/.env.enc`. The extension should redirect it to a decrypted virtual document.

> `.dotseal.key` is gitignored. The `.env` is committed because the values are fake, but never commit a real `.env` with actual secrets.

### Checks and tests

```bash
npm run check   # TypeScript type-check (no emit)
npm test        # unit tests + Python conformance tests
```

The test suite includes TypeScript unit tests and `conformance.test.ts`, which compares crypto, parser, core, and key-discovery behavior against the Python package in this repository.

### Packaging

To produce a `.vsix` for local installation:

```bash
npm install -g @vscode/vsce
vsce package
code --install-extension dotseal-vscode-*.vsix
```
