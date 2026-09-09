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

# The stack must be gone first. Run during a delete and the final snapshot is
# still being created, so it cannot be removed, the script stops there, and the
# KMS key is silently left behind — a partial cleanup that reports itself as an
# error rather than as unfinished work.
if STATUS=$(aws cloudformation describe-stacks --stack-name "$STACK" \
    --query 'Stacks[0].StackStatus' --output text 2>/dev/null); then
  echo "Stack '$STACK' still exists ($STATUS)." >&2
  case "$STATUS" in
    # These four never resolve on their own, so telling the operator to wait is
    # a dead end. Say what the stack is actually stuck on and how to get out.
    CREATE_FAILED|ROLLBACK_FAILED|DELETE_FAILED|UPDATE_ROLLBACK_FAILED)
      cat >&2 <<EOF

That status is terminal. It will not finish on its own, and a stack in
ROLLBACK_FAILED cannot be updated either, so there is no fixing it in place.

The usual cause is the database. CloudFormation snapshots it on the way out
(DeletionPolicy: Snapshot), and it cannot snapshot an instance that is still
creating, nor delete one at all while deletion protection is on. A create that
fails early therefore rolls back into ROLLBACK_FAILED every time.

Work down this list, re-running the delete after each step:

  # 1. Clear deletion protection, which Environment=production turns on.
  aws rds modify-db-instance --region $REGION \\
    --db-instance-identifier $STACK-postgres \\
    --no-deletion-protection --apply-immediately

  # 2. Delete again. Once the instance reaches 'available' it can be
  #    snapshotted, and the snapshot is what holds your data.
  aws cloudformation delete-stack --region $REGION --stack-name $STACK

  # 3. Only valid from DELETE_FAILED: keep the database, delete the rest.
  #    The instance then survives and bills until you remove it by hand.
  aws cloudformation delete-stack --region $REGION --stack-name $STACK \\
    --retain-resources Database

  # 4. Only valid from DELETE_FAILED, and last: drop the stack and orphan
  #    whatever it could not delete, including any snapshot in progress.
  aws cloudformation delete-stack --region $REGION --stack-name $STACK \\
    --deletion-mode FORCE_DELETE_STACK

Then run this script again to clear what the stack leaves behind.
EOF
      ;;
    *)
      echo "Wait for it to finish deleting, then run this again." >&2
      ;;
  esac
  echo "Nothing was touched." >&2
  exit 1
fi

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
# By alias first. Older stacks deleted the alias while retaining the key, so
# fall back to the stack tag, which survives either way.
KEY=$(aws kms describe-key --key-id "alias/${STACK}-switchboard" \
  --query 'KeyMetadata.KeyId' --output text 2>/dev/null || true)
if [ -z "${KEY:-}" ] || [ "$KEY" = "None" ]; then
  for k in $(aws kms list-keys --query 'Keys[].KeyId' --output text 2>/dev/null); do
    state=$(aws kms describe-key --key-id "$k" \
      --query 'KeyMetadata.[KeyManager,KeyState]' --output text 2>/dev/null || true)
    case "$state" in CUSTOMER*Enabled*) ;; *) continue ;; esac
    tagged=$(aws kms list-resource-tags --key-id "$k" \
      --query "Tags[?TagKey=='SwitchboardStack'&&TagValue=='${STACK}'].TagValue" \
      --output text 2>/dev/null || true)
    if [ -n "$tagged" ]; then KEY="$k"; break; fi
  done
fi

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
SNAPSHOT_FAILED=0
if [ -n "${SNAPSHOTS:-}" ]; then
  for id in $(echo "$SNAPSHOTS" | awk '{print $1}'); do
    [ -n "$id" ] || continue
    state=$(aws rds describe-db-snapshots --db-snapshot-identifier "$id" \
      --query 'DBSnapshots[0].Status' --output text 2>/dev/null || echo unknown)
    case "$state" in
      available|failed) ;;
      *) echo "snapshot $id is '$state' and cannot be deleted yet; run again shortly"
         SNAPSHOT_FAILED=1; continue ;;
    esac
    if aws rds delete-db-snapshot --db-snapshot-identifier "$id" >/dev/null 2>&1; then
      echo "deleted snapshot $id"
    else
      echo "could not delete snapshot $id"
      SNAPSHOT_FAILED=1
    fi
  done
fi
if [ "$SNAPSHOT_FAILED" -eq 1 ]; then
  echo
  echo "A snapshot survives, so the KMS key is being kept: deleting it would" >&2
  echo "make that snapshot permanently unreadable. Re-run once the snapshot is" >&2
  echo "available and the key will be scheduled then." >&2
  exit 1
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
