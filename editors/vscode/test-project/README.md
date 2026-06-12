# Extension test project

A tiny sample workspace for manually testing the dotseal VS Code extension
(`F5` / "Run Extension" in `editors/vscode`).

The committed `.env` contains only fake values. The master key and the
encrypted file are **not** committed — they are generated locally and
gitignored.

Pressing **F5** in `editors/vscode` runs `npm run watch`, which creates
`.dotseal.key` and `.env.enc` automatically when they are missing. You can
also generate them manually:

```bash
./setup.sh   # creates .dotseal.key and .env.enc (both gitignored)
```

Then open this folder in the Extension Development Host and open `.env.enc`.
