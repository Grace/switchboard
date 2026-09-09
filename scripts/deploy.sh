#!/bin/sh
# Deploy the Switchboard quickstart stack, or update one already deployed.
#
# This exists because the safety belonged to a script nobody deployed with.
# A hand-run `aws cloudformation deploy` rolls back on failure, and a rollback
# of a failed *create* always finds the database mid-creation, which cannot be
# snapshotted (DeletionPolicy: Snapshot) and so cannot be deleted. The stack
# lands in ROLLBACK_FAILED, which cannot be updated, and the only way out is by
# hand. Creating with --disable-rollback leaves CREATE_FAILED instead: the
# resources and their logs stay inspectable, and the delete that follows happens
# once the database has settled, so the snapshot succeeds.
#
#   ./scripts/deploy.sh --certificate <arn> --hostname <name> --image <uri>
#
# Checks the stack is in a deployable state, then runs preflight, and refuses to
# deploy if either fails. Creates real, billable infrastructure; see
# scripts/teardown.sh for removing what a delete leaves behind.
set -eu

REGION="${AWS_REGION:-us-east-1}"
STACK=switchboard
CERT=""; HOSTNAME=""; IMAGE=""
ENGINE_VERSION=18.6
ENVIRONMENT=evaluation
INSTANCE_CLASS=db.t4g.medium
MULTI_AZ=true
TEMPLATE=deploy/cloudformation/quickstart.yaml

while [ $# -gt 0 ]; do
  case "$1" in
    --region)          REGION="$2"; shift 2 ;;
    --stack)           STACK="$2"; shift 2 ;;
    --certificate)     CERT="$2"; shift 2 ;;
    --hostname)        HOSTNAME="$2"; shift 2 ;;
    --image)           IMAGE="$2"; shift 2 ;;
    --engine-version)  ENGINE_VERSION="$2"; shift 2 ;;
    --environment)     ENVIRONMENT="$2"; shift 2 ;;
    --instance-class)  INSTANCE_CLASS="$2"; shift 2 ;;
    --multi-az)        MULTI_AZ="$2"; shift 2 ;;
    -h|--help)         sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[ -n "$CERT" ] && [ -n "$HOSTNAME" ] && [ -n "$IMAGE" ] || {
  echo "usage: $0 --certificate <arn> --hostname <name> --image <uri>" >&2; exit 2; }

# A load balancer name is capped at 32 characters and CloudFormation builds it
# from the stack name, so a long stack name fails after the VPC, NAT gateway and
# database are already built. Refuse it here instead, for free.
case "$STACK" in
  ?????????????????????????*) echo "stack name '$STACK' is over 24 characters; the load balancer name would exceed its 32-character cap after the database is built." >&2; exit 2 ;;
esac

cd "$(dirname "$0")/.."
aws() { command aws --region "$REGION" "$@"; }
say() { printf '\n== %s ==\n' "$1"; }

set -- \
  "CertificateArn=$CERT" \
  "ControlPlaneHostname=$HOSTNAME" \
  "ControlPlaneImage=$IMAGE" \
  "EngineVersion=$ENGINE_VERSION" \
  "Environment=$ENVIRONMENT" \
  "DBInstanceClass=$INSTANCE_CLASS" \
  "MultiAZ=$MULTI_AZ"

STATUS=$(aws cloudformation describe-stacks --stack-name "$STACK" \
  --query 'Stacks[0].StackStatus' --output text 2>/dev/null || echo NONE)

case "$STATUS" in
  NONE) ;;
  CREATE_FAILED|ROLLBACK_FAILED|DELETE_FAILED|UPDATE_ROLLBACK_FAILED)
    echo "Stack '$STACK' is in $STATUS and cannot be deployed into." >&2
    echo "Run ./scripts/teardown.sh $STACK --region $REGION for the way out." >&2
    exit 1 ;;
  *_IN_PROGRESS)
    echo "Stack '$STACK' is $STATUS. Wait for it to settle." >&2; exit 1 ;;
esac

say "Preflight"
./scripts/preflight.sh --region "$REGION" --engine-version "$ENGINE_VERSION" \
  --instance-class "$INSTANCE_CLASS" --multi-az "$MULTI_AZ" \
  --certificate "$CERT" --image "$IMAGE" || {
  echo "preflight failed; nothing was deployed." >&2; exit 1; }

if [ "$STATUS" = NONE ]; then
  say "Create $STACK"
  # Parameters carry no spaces (preflight rejects a certificate that does), so
  # the split below is safe and is what turns the K=V list into --parameters.
  PARAMS=""
  for kv in "$@"; do
    PARAMS="$PARAMS ParameterKey=${kv%%=*},ParameterValue=${kv#*=}"
  done
  # --disable-rollback is the whole point of this script; see the header.
  # shellcheck disable=SC2086
  aws cloudformation create-stack --stack-name "$STACK" \
    --template-body "file://$TEMPLATE" \
    --capabilities CAPABILITY_IAM --disable-rollback \
    --parameters $PARAMS \
    --query StackId --output text
  echo "  waiting (allow ~25 minutes; Multi-AZ conversion dominates)"
  while :; do
    S=$(aws cloudformation describe-stacks --stack-name "$STACK" \
        --query 'Stacks[0].StackStatus' --output text 2>/dev/null || echo GONE)
    case "$S" in *_COMPLETE|*_FAILED|GONE) break ;; esac
    sleep 30
  done
else
  say "Update $STACK ($STATUS)"
  # Rollback stays on for updates. The database already exists and is available,
  # so a rollback can snapshot it; the failure mode this script guards against
  # is specific to a create.
  aws cloudformation deploy --stack-name "$STACK" \
    --template-file "$TEMPLATE" \
    --capabilities CAPABILITY_IAM --no-fail-on-empty-changeset \
    --parameter-overrides "$@"
  S=$(aws cloudformation describe-stacks --stack-name "$STACK" \
      --query 'Stacks[0].StackStatus' --output text 2>/dev/null || echo GONE)
fi

echo "  $S"
case "$S" in
  CREATE_COMPLETE|UPDATE_COMPLETE) ;;
  *)
    say "Failures"
    aws cloudformation describe-stack-events --stack-name "$STACK" \
      --query 'StackEvents[?ends_with(ResourceStatus, `_FAILED`)].[LogicalResourceId,ResourceStatusReason]' \
      --output text 2>/dev/null | head -5
    echo
    echo "The stack was created with --disable-rollback, so these resources and" >&2
    echo "their logs are still there to read. When you are done:" >&2
    echo "  aws cloudformation delete-stack --region $REGION --stack-name $STACK" >&2
    echo "  ./scripts/teardown.sh $STACK --region $REGION" >&2
    exit 1 ;;
esac

say "Outputs"
aws cloudformation describe-stacks --stack-name "$STACK" \
  --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' --output text

cat <<EOF

Point $HOSTNAME at the load balancer address above from wherever your sidecars
resolve it. The zone this stack creates is private to the VPC.
EOF
