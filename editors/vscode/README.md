# dotseal for VS Code and Cursor

Edit dotseal `.env.enc` files as decrypted virtual documents. The extension opens a native editor buffer with cleartext values, then re-encrypts the real `.env.enc` file on save.

The extension is self-contained TypeScript and does not require Python or the `dotseal` CLI at runtime.

## Usage

1. Open a workspace that contains `.env.enc` and the matching `.dotseal.key`, or set `DOTSEAL_MASTER_KEY` before launching the editor.
2. Open `.env.enc`.
3. The extension automatically redirects the file to a `dotseal:` virtual document that displays decrypted `.env` content.
4. Edit normally and save. The real `.env.enc` file is updated with encrypted values.

You can also run **Dotseal: Open Encrypted Env** from the command palette.

## Key Resolution

The extension resolves the master key in this order:

1. `dotseal.masterKey` setting, if provided.
2. `dotseal.keyFile` setting, if provided.
3. `DOTSEAL_MASTER_KEY` environment variable.
4. A `.dotseal.key` file discovered by walking upward from the `.env.enc` file's directory.

Prefer `DOTSEAL_MASTER_KEY` or `.dotseal.key` over storing key material in editor settings.

## Settings

- `dotseal.autoOpen`: automatically redirect `.env.enc` files to the decrypted virtual editor. Defaults to `true`.
- `dotseal.keyFile`: optional path to a key file.
- `dotseal.masterKey`: optional base64 master key. This is supported for convenience, but storing secrets in editor settings is discouraged.

## Security Notes

Cleartext is not written to a `.env` file or temporary file by this extension. It lives in the VS Code/Cursor editor buffer and extension process memory while the virtual document is open.

This is still best-effort protection. Editor features, extensions, crash reporting, remote development hosts, or manual copy/paste can expose cleartext once it is displayed. Treat an open decrypted buffer like any other visible secret.

This initial version does not mask values or implement per-value reveal. The `dotseal:` document is a normal native editor buffer so existing editor features work naturally.

## Development

```bash
npm install
npm run check
npm test
```

The test suite includes TypeScript unit tests and cross-language conformance checks against the Python package in this repository.
