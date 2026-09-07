#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
exec docker run --rm -i \
  --network "container:switchboard-taskns-1" \
  --env-file .dev/env \
  -v "$PWD/scripts:/app/scripts:ro" \
  -w /app switchboard-dev:latest python scripts/dev-smoke.py
