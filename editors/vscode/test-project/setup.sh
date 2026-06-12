#!/bin/sh
# Regenerate the gitignored fixtures (.dotseal.key, .env.enc) used when
# manually testing the extension (F5 / "Run Extension"). The committed .env
# contains only fake values; the key and the encrypted file are generated
# locally and never committed.
set -eu
cd "$(dirname "$0")"

run_python() {
  if command -v uv >/dev/null 2>&1; then
    uv run --project ../../.. python "$@"
  elif command -v python >/dev/null 2>&1; then
    python "$@"
  else
    python3 "$@"
  fi
}

run_python - <<'PY'
from dotseal.cli import main

rc = main(["init", "--force"])
if rc == 0:
    rc = main(["encrypt", ".env", ".env.enc"])
raise SystemExit(rc)
PY

echo "Fixtures ready: .dotseal.key and .env.enc (both gitignored)."
