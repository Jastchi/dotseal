# Editor Integration

## VS Code / Cursor extension

Download the latest `.vsix` from [GitHub Releases](https://github.com/Jastchi/dotseal/releases), then install it via "Extensions: Install from VSIX..." in VS Code or Cursor.

The extension helps with encrypted `.env.enc` workflows inside the editor, while encryption and decryption remain handled by the `dotseal` CLI and library.

See [editors/vscode/README.md](../editors/vscode/README.md) for settings. Note that `dotseal.plaintextKeys` and `dotseal.plaintextKeyRegex` apply only when the extension creates a new encrypted file; later saves reuse the policy in the file footer.
