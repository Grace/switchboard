#!/bin/sh
# Deploy the quickstart into a real account, verify it, and tear it down.
#
# Three template defects reached a real deployment because nothing but a
# deployment could find them: a Postgres version that did not exist in the
# region, an execution role that could not read a secret RDS had not created
# yet, and a retained KMS key whose alias was deleted with the stack. cfn-lint
# and validate-template accept all three. This makes the only check that would
# have caught them repeatable instead of a once-ever event.
#
#   ./scripts/deploy-test.sh --certificate <arn> --hostname <name> --image <uri>
#
# Costs roughly $0.26/hour while running and deletes everything at the end,
# including on failure unless --keep is given.
set -eu

REGION="${AWS_REGION:-us-east-1}"
STACK="switchboard-deploytest-$(date +%H%M%S)"
CERT=""; HOSTNAME=""; IMAGE=""; KEEP=0
ENGINE_VERSION=18.6

while [ $# -gt 0 ]; do
  case "$1" in
    --region)         REGION="$2"; shift 2 ;;
    --stack)          STACK="$2"; shift 2 ;;
    --certificate)    CERT="$2"; shift 2 ;;
    --hostname)       HOSTNAME="$2"; shift 2 ;;
    --image)          IMAGE="$2"; shift 2 ;;
    --engine-version) ENGINE_VERSION="$2"; shift 2 ;;
    # Leave the stack up for inspection. It keeps billing until removed.
    --keep)           KEEP=1; shift ;;
    -h|--help)        sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[ -n "$CERT" ] && [ -n "$HOSTNAME" ] && [ -n "$IMAGE" ] || {
  echo "usage: $0 --certificate <arn> --hostname <name> --image <uri>" >&2; exit 2; }

cd "$(dirname "$0")/.."
aws() { command aws --region "$REGION" "$@"; }
say() { printf '\n== %s ==\n' "$1"; }

FAILED=0
note_fail() { echo "  FAIL  $1"; FAILED=1; }
note_ok()   { echo "  ok    $1"; }

# Teardown runs even when verification fails: the failure is the finding, and
# leaving billable infrastructure behind to preserve it is the wrong trade.
cleanup() {
  [ "$KEEP" -eq 1 ] && { echo "--keep given; '$STACK' left running and billing."; return; }
  say "Teardown"
  if aws cloudformation describe-stacks --stack-name "$STACK" >/dev/null 2>&1; then
    aws cloudformation delete-stack --stack-name "$STACK" 2>/dev/null || true
    while aws cloudformation describe-stacks --stack-name "$STACK" >/dev/null 2>&1; do sleep 20; done
    echo "  stack deleted"
  else
    echo "  no stack was created"
  fi
  echo "$STACK" | ./scripts/teardown.sh "$STACK" --region "$REGION" 2>&1 | sed 's/^/  /' || true
}
trap cleanup EXIT

say "Preflight"
./scripts/preflight.sh --region "$REGION" --engine-version "$ENGINE_VERSION" \
  --certificate "$CERT" --image "$IMAGE" || exit 1

say "Deploy $STACK"
# --disable-rollback keeps failed resources and their logs inspectable; rollback
# deletes the evidence along with the resources.
aws cloudformation create-stack --stack-name "$STACK" \
  --template-body file://deploy/cloudformation/quickstart.yaml \
  --capabilities CAPABILITY_IAM --disable-rollback \
  --parameters \
    ParameterKey=CertificateArn,ParameterValue="$CERT" \
    ParameterKey=ControlPlaneHostname,ParameterValue="$HOSTNAME" \
    ParameterKey=ControlPlaneImage,ParameterValue="$IMAGE" \
    ParameterKey=EngineVersion,ParameterValue="$ENGINE_VERSION" \
    ParameterKey=Environment,ParameterValue=evaluation \
  --query StackId --output text
echo "  waiting (Multi-AZ conversion dominates; allow ~25 minutes)"

while :; do
  S=$(aws cloudformation describe-stacks --stack-name "$STACK" \
      --query 'Stacks[0].StackStatus' --output text 2>/dev/null || echo GONE)
  case "$S" in *_COMPLETE|*_FAILED|GONE) break ;; esac
  sleep 30
done
echo "  $S"

if [ "$S" != "CREATE_COMPLETE" ]; then
  say "Failures"
  aws cloudformation describe-stack-events --stack-name "$STACK" \
    --query 'StackEvents[?ResourceStatus==`CREATE_FAILED`].[LogicalResourceId,ResourceStatusReason]' \
    --output text 2>/dev/null | head -5
  exit 1
fi

say "Verify"

# The parameter group family is derived from the engine version by a template
# expression, so a wrong derivation fails exactly like a manual mismatch.
want_family="postgres$(printf '%s' "$ENGINE_VERSION" | cut -d. -f1)"
pg=$(aws rds describe-db-instances --db-instance-identifier "$STACK-postgres" \
  --query 'DBInstances[0].DBParameterGroups[0].DBParameterGroupName' --output text 2>/dev/null)
got_family=$(aws rds describe-db-parameter-groups --db-parameter-group-name "$pg" \
  --query 'DBParameterGroups[0].DBParameterGroupFamily' --output text 2>/dev/null)
[ "$got_family" = "$want_family" ] \
  && note_ok "parameter group family derived as $got_family" \
  || note_fail "parameter group family is $got_family, expected $want_family"

# Migrations, and the runtime login being a different principal from the
# migration owner. Collapsing those two would silently defeat row level security.
if aws logs tail "/ecs/$STACK/control" --since 40m --filter-pattern 'dbinit' 2>/dev/null \
   | grep -q 'switchboard_rt granted switchboard_app'; then
  note_ok "migrations applied and switchboard_rt created as a separate login"
else
  note_fail "no dbinit success line in the log group"
fi

running=$(aws ecs describe-services --cluster "$STACK-cluster" --services "$STACK-control" \
  --query 'services[0].runningCount' --output text 2>/dev/null || echo 0)
[ "${running:-0}" -ge 1 ] && note_ok "ECS service running $running task(s)" \
                          || note_fail "ECS service has no running tasks"

# From the stack's own output rather than a constructed name: the name is
# generated by CloudFormation now, and guessing one is what let a name-length
# defect survive until a real deployment.
TG=$(aws cloudformation describe-stacks --stack-name "$STACK" \
  --query 'Stacks[0].Outputs[?OutputKey==`TargetGroupArn`].OutputValue' --output text 2>/dev/null || true)
health=$(aws elbv2 describe-target-health --target-group-arn "$TG" \
  --query 'TargetHealthDescriptions[].TargetHealth.State' --output text 2>/dev/null || true)
case "${health:-}" in
  *healthy*) note_ok "load balancer targets healthy" ;;
  *) note_fail "target health: ${health:-none}" ;;
esac

# The load balancer is internal by design, so this has to run inside the VPC.
# It is the only check that exercises the TLS listener and the real certificate;
# target health only proves the plaintext check to the task.
SUBNETS=$(aws cloudformation describe-stack-resources --stack-name "$STACK" \
  --query 'StackResources[?LogicalResourceId==`PrivateSubnetA`||LogicalResourceId==`PrivateSubnetB`].PhysicalResourceId' \
  --output text | tr '\t' ',')
SG=$(aws cloudformation describe-stack-resources --stack-name "$STACK" \
  --query 'StackResources[?LogicalResourceId==`ControlPlaneSecurityGroup`].PhysicalResourceId' --output text)
probe="import urllib.request;r=urllib.request.urlopen(\"https://$HOSTNAME/readyz\",timeout=20);print(\"TLS_OK status=%d body=%s\"%(r.status,r.read().decode()[:60]))"
TASK=$(aws ecs run-task --cluster "$STACK-cluster" --task-definition "$STACK-bootstrap" \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[$SUBNETS],securityGroups=[$SG],assignPublicIp=DISABLED}" \
  --overrides "{\"containerOverrides\":[{\"name\":\"bootstrap\",\"command\":[\"-c\",\"$probe\"]}]}" \
  --query 'tasks[0].taskArn' --output text 2>/dev/null || true)
if [ -n "${TASK:-}" ] && [ "$TASK" != "None" ]; then
  while [ "$(aws ecs describe-tasks --cluster "$STACK-cluster" --tasks "$TASK" \
        --query 'tasks[0].lastStatus' --output text 2>/dev/null)" != "STOPPED" ]; do sleep 10; done
  sleep 12
  if aws logs tail "/ecs/$STACK/control" --since 5m --filter-pattern 'TLS_OK' 2>/dev/null | grep -q TLS_OK; then
    note_ok "TLS through the internal load balancer on the real certificate"
  else
    note_fail "TLS probe produced no TLS_OK line"
  fi
else
  note_fail "could not start the TLS probe task"
fi

say "Result"
[ "$FAILED" -eq 0 ] && echo "  PASS — deployed, verified, tearing down" \
                    || echo "  FAIL — see above; tearing down anyway"
exit "$FAILED"
