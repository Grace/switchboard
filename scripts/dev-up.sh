#!/bin/sh
# Bring up the local stack and leave it serving. Idempotent: rerunning reuses
# the keys and tokens already in .dev/env.
set -eu
cd "$(dirname "$0")/.."
COMPOSE="docker compose -f docker-compose.dev.yml"
NS="switchboard-taskns-1"

# `docker compose run` cannot attach to a service that uses
# network_mode: service:, so one-off jobs that must live inside the shared
# namespace are launched with docker run and --network container:.
in_namespace() {
  docker run --rm -i \
    --user 0:0 \
    --network "container:$NS" \
    --env-file .dev/env \
    -e MIGRATION_DATABASE_URL=postgresql://postgres:devonly@postgres:5432/switchboard \
    -v "$PWD/scripts:/app/scripts:ro" \
    -v switchboard_gwconfig:/config \
    -w /app switchboard-dev:latest "$@"
}

mkdir -p .dev
if [ ! -s .dev/env ]; then
  : > .dev/env                     # placeholder so compose can parse env_file
  echo "building images"
  $COMPOSE build devtools gateway >/dev/null
  echo "generating signing key and tokens"
  $COMPOSE run --rm --no-deps -T dbinit scripts/devstack.py keys > .dev/env.tmp
  mv .dev/env.tmp .dev/env
  chmod 0600 .dev/env
  echo "  wrote .dev/env (Ed25519 seed and bearer tokens; gitignored, local only)"
fi

# Compose interpolates ${APP_DB_PASSWORD} at parse time from the shell, not from
# env_file, so these have to be exported here too.
set -a
. ./.dev/env
set +a

$COMPOSE build devtools gateway >/dev/null
echo "starting postgres"
$COMPOSE up -d postgres
echo "applying migrations and creating the runtime login"
$COMPOSE run --rm -T dbinit
echo "starting the shared namespace, mock provider and control plane"
# Recreate together so nothing is left attached to a stale namespace.
$COMPOSE up -d --force-recreate taskns mockprovider controlplane
echo "provisioning tenant, principals and signed policy"
in_namespace scripts/devstack.py init
echo "starting gateway"
$COMPOSE up -d gatewayinit
$COMPOSE up -d --force-recreate gateway
echo
echo "stack is up. next: make dev-smoke"
