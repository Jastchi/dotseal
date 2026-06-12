#!/bin/sh
# Regenerate the gitignored fixtures (.dotseal.key, .env.enc) used when
# manually testing the extension (F5 / "Run Extension"). The committed .env
# contains only fake values; the key and the encrypted file are generated
# locally and never committed.
set -eu
cd "$(dirname "$0")"

uv run --project ../../.. python - <<'PY'
from dotseal.cli import main

rc = main(["init", "--force"])
if rc == 0:
    rc = main(["encrypt", ".env", ".env.enc"])
raise SystemExit(rc)
PY

echo "Fixtures ready: .dotseal.key and .env.enc (both gitignored)."
