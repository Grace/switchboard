#!/bin/sh
# Remove what a deleted Switchboard stack leaves behind.
#
# Some resources are deliberately kept when the stack goes away, so that
# deleting a stack cannot destroy a customer's data by accident. The cost of
# that choice is that they keep billing until somebody removes them, and the
# person most likely to be surprised is whoever deployed the quickstart to
# evaluate it. This script finds them and, on confirmation, deletes them.
#
#   ./scripts/teardown.sh <stack-name> [--region <region>]
#
# It lists everything before touching anything, and deletes nothing without a
# typed confirmation.
set -eu

STACK=""
REGION="${AWS_REGION:-us-east-1}"
while [ $# -gt 0 ]; do
  case "$1" in
    --region) REGION="$2"; shift 2 ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) STACK="$1"; shift ;;
  esac
done
[ -n "$STACK" ] || { echo "usage: $0 <stack-name> [--region <region>]" >&2; exit 2; }

aws() { command aws --region "$REGION" "$@"; }

echo "Looking for resources left behind by stack '$STACK' in $REGION."
echo

# --- database snapshots -----------------------------------------------------
# DeletionPolicy: Snapshot means the final snapshot outlives the stack. It holds
# the data, so it is listed first and deleted last: removing the KMS key before
# the snapshot would leave an unreadable snapshot behind forever.
SNAPSHOTS=$(aws rds describe-db-snapshots --snapshot-type manual \
  --query "DBSnapshots[?starts_with(DBSnapshotIdentifier,\`${STACK}\`)].[DBSnapshotIdentifier,AllocatedStorage]" \
  --output text 2>/dev/null || true)

# --- secrets ----------------------------------------------------------------
SECRETS=$(aws secretsmanager list-secrets \
  --query "SecretList[?starts_with(Name,\`${STACK}/\`)].ARN" \
  --output text 2>/dev/null || true)

# --- log group --------------------------------------------------------------
LOGS=$(aws logs describe-log-groups --log-group-name-prefix "/ecs/${STACK}/" \
  --query 'logGroups[].logGroupName' --output text 2>/dev/null || true)

# --- KMS key ----------------------------------------------------------------
KEY=$(aws kms describe-key --key-id "alias/${STACK}-switchboard" \
  --query 'KeyMetadata.KeyId' --output text 2>/dev/null || true)

found=0
if [ -n "${SNAPSHOTS:-}" ]; then
  echo "Database snapshots (these hold your data):"
  echo "$SNAPSHOTS" | while read -r id gb; do
    [ -n "$id" ] && printf '    %-52s %s GB\n' "$id" "$gb"
  done
  found=1
fi
if [ -n "${SECRETS:-}" ]; then
  echo "Secrets (about \$0.40 each per month):"
  for a in $SECRETS; do printf '    %s\n' "$a"; done
  found=1
fi
if [ -n "${LOGS:-}" ]; then
  echo "Log groups (charged on stored volume):"
  for l in $LOGS; do printf '    %s\n' "$l"; done
  found=1
fi
if [ -n "${KEY:-}" ] && [ "$KEY" != "None" ]; then
  echo "KMS key (about \$1 per month):"
  printf '    %s\n' "$KEY"
  found=1
fi

if [ "$found" -eq 0 ]; then
  echo "Nothing left behind. This stack costs you nothing."
  exit 0
fi

cat <<EOF

Deleting these is irreversible. The snapshots are the only remaining copy of
the database; once they are gone the data is gone. Keep them if there is any
chance you want that data back.

EOF
printf "Type the stack name to delete everything listed above: "
read -r CONFIRM
[ "$CONFIRM" = "$STACK" ] || { echo "Not confirmed. Nothing was deleted."; exit 1; }

echo
for l in ${LOGS:-}; do
  aws logs delete-log-group --log-group-name "$l" && echo "deleted log group $l"
done
for a in ${SECRETS:-}; do
  aws secretsmanager delete-secret --secret-id "$a" --force-delete-without-recovery >/dev/null \
    && echo "deleted secret $a"
done
if [ -n "${SNAPSHOTS:-}" ]; then
  echo "$SNAPSHOTS" | while read -r id _; do
    [ -n "$id" ] || continue
    aws rds delete-db-snapshot --db-snapshot-identifier "$id" >/dev/null \
      && echo "deleted snapshot $id"
  done
fi
# Last, and only scheduled: AWS enforces a waiting period of at least seven
# days on key deletion, and anything encrypted with it becomes unreadable.
if [ -n "${KEY:-}" ] && [ "$KEY" != "None" ]; then
  aws kms schedule-key-deletion --key-id "$KEY" --pending-window-in-days 7 \
    --query 'DeletionDate' --output text \
    && echo "scheduled KMS key $KEY for deletion in 7 days"
fi

echo
echo "Done. The KMS key deletion is pending and can be cancelled with"
echo "  aws kms cancel-key-deletion --key-id $KEY --region $REGION"
