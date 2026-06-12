#!/bin/sh
# Generate test-project/.dotseal.key and .env.enc when missing (F5 manual testing).
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIXTURE_DIR="$ROOT/test-project"

if [ -f "$FIXTURE_DIR/.dotseal.key" ] && [ -f "$FIXTURE_DIR/.env.enc" ]; then
  exit 0
fi

echo "test-project fixtures missing; running setup.sh..."
exec sh "$FIXTURE_DIR/setup.sh"
