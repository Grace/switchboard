#!/bin/sh
# Tear down containers and volumes. Keeps .dev/env so the next dev-up reuses keys.
set -eu
cd "$(dirname "$0")/.."
set -a; [ -s .dev/env ] && . ./.dev/env; set +a
exec docker compose -f docker-compose.dev.yml down -v --remove-orphans
