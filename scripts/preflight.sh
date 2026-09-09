#!/bin/sh
# Check the assumptions a Switchboard stack embeds, before spending anything.
#
# Templates carry region-specific assumptions that no linter can evaluate.
# cfn-lint and `aws cloudformation validate-template` both accept a Postgres
# version that does not exist in the target region; the failure only appears
# after the VPC, NAT gateway, load balancer and IAM roles have been built. This
# script asks the services themselves, creates nothing, and takes seconds.
#
#   ./scripts/preflight.sh --certificate <arn> --image <uri> [options]
#
# Options mirror the stack parameters, so what is checked is what will actually
# be deployed rather than the template defaults.
set -eu

REGION="${AWS_REGION:-us-east-1}"
ENGINE_VERSION=18.6
INSTANCE_CLASS=db.t4g.medium
STORAGE_TYPE=gp3
MULTI_AZ=true
CERT=""
IMAGE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --region)          REGION="$2"; shift 2 ;;
    --engine-version)  ENGINE_VERSION="$2"; shift 2 ;;
    --instance-class)  INSTANCE_CLASS="$2"; shift 2 ;;
    --storage-type)    STORAGE_TYPE="$2"; shift 2 ;;
    --multi-az)        MULTI_AZ="$2"; shift 2 ;;
    --certificate)     CERT="$2"; shift 2 ;;
    --image)           IMAGE="$2"; shift 2 ;;
    -h|--help)         sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

aws() { command aws --region "$REGION" "$@"; }

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }
skip() { printf '  skip  %s\n' "$1"; }

echo "Preflight for region $REGION"
echo

# --- database ---------------------------------------------------------------
# The class of failure that cost a deployment: a version that does not exist.
# The AWS CLI prints the literal string None for an empty result rather than
# nothing at all, so a bare emptiness test passes for a version that does not
# exist. Compare against the requested version instead.
FOUND=$(aws rds describe-db-engine-versions --engine postgres \
  --engine-version "$ENGINE_VERSION" \
  --query 'DBEngineVersions[0].EngineVersion' --output text 2>/dev/null || true)
if [ "$FOUND" = "$ENGINE_VERSION" ]; then
  pass "postgres $ENGINE_VERSION exists in $REGION"
else
  fail "postgres $ENGINE_VERSION does NOT exist in $REGION"
  echo "        available: $(aws rds describe-db-engine-versions --engine postgres \
      --query 'DBEngineVersions[].EngineVersion' --output text 2>/dev/null \
      | tr '\t' '\n' | tail -6 | tr '\n' ' ')"
fi

OPTS=$(aws rds describe-orderable-db-instance-options \
  --engine postgres --engine-version "$ENGINE_VERSION" \
  --db-instance-class "$INSTANCE_CLASS" \
  --query 'OrderableDBInstanceOptions[].[MultiAZCapable,StorageType]' \
  --output text 2>/dev/null || true)

if [ -n "$OPTS" ]; then
  pass "$INSTANCE_CLASS is orderable at postgres $ENGINE_VERSION"
  if echo "$OPTS" | awk '{print $2}' | grep -qx "$STORAGE_TYPE"; then
    pass "storage type $STORAGE_TYPE supported"
  else
    fail "storage type $STORAGE_TYPE NOT supported for that combination"
    echo "        supported: $(echo "$OPTS" | awk '{print $2}' | sort -u | tr '\n' ' ')"
  fi
  if [ "$MULTI_AZ" = "true" ]; then
    if echo "$OPTS" | grep -qi '^true'; then
      pass "Multi-AZ available"
    else
      fail "Multi-AZ requested but $INSTANCE_CLASS does not support it here"
    fi
  fi
else
  fail "$INSTANCE_CLASS is NOT orderable at postgres $ENGINE_VERSION in $REGION"
fi

# --- availability zones -----------------------------------------------------
# A DB subnet group spanning two zones is required for Multi-AZ, and the
# template lays subnets across the first two the region reports.
AZS=$(aws ec2 describe-availability-zones --filters Name=state,Values=available \
  --query 'length(AvailabilityZones)' --output text 2>/dev/null || echo 0)
if [ "${AZS:-0}" -ge 2 ]; then
  pass "$AZS availability zones (2 required)"
else
  fail "only ${AZS:-0} availability zones; the template needs 2"
fi

# --- quotas -----------------------------------------------------------------
check_quota() {
  used="$1"; code="$2"; svc="$3"; label="$4"
  limit=$(aws service-quotas get-service-quota --service-code "$svc" --quota-code "$code" \
    --query 'Quota.Value' --output text 2>/dev/null || echo "")
  [ -n "$limit" ] || { skip "$label quota not readable"; return; }
  limit=${limit%.*}
  if [ "$used" -lt "$limit" ]; then
    pass "$label: $used of $limit used"
  else
    fail "$label at quota: $used of $limit"
  fi
}
check_quota "$(aws ec2 describe-vpcs --query 'length(Vpcs)' --output text 2>/dev/null || echo 0)" \
  L-F678F1CE vpc "VPCs"
check_quota "$(aws ec2 describe-addresses --query 'length(Addresses)' --output text 2>/dev/null || echo 0)" \
  L-0263D0A3 ec2 "Elastic IPs"

# --- certificate ------------------------------------------------------------
if [ -n "$CERT" ]; then
  # Shape before anything else. `aws acm list-certificates --output text` prints
  # every match tab separated, so a command substitution that matched two
  # certificates hands this one argument holding both ARNs. Left to the checks
  # below, that value passes the region test (the substring is still in there)
  # and fails describe-certificate as MISSING, which reads as one wrong ARN
  # rather than as two right ones. Name it here, before any of that.
  CERT_OK=1
  case "$CERT" in
    *[[:space:]]*)
      CERT_OK=0
      fail "--certificate holds whitespace, so it is more than one ARN. Pass exactly one." ;;
  esac
  if [ "$CERT_OK" = 1 ] && ! printf '%s\n' "$CERT" | grep -Eq \
      '^arn:[^:]+:acm:[a-z0-9-]+:[0-9]{12}:certificate/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  then
    CERT_OK=0
    fail "--certificate is not an ACM certificate ARN: $CERT"
  fi

  if [ "$CERT_OK" = 1 ]; then
    ST=$(aws acm describe-certificate --certificate-arn "$CERT" \
      --query 'Certificate.Status' --output text 2>/dev/null || echo MISSING)
    case "$ST" in
      ISSUED) pass "certificate is ISSUED" ;;
      PENDING_VALIDATION) fail "certificate still PENDING_VALIDATION; the DNS record is not live yet" ;;
      *) fail "certificate status $ST" ;;
    esac
    # A certificate in another region is invisible to an ALB here.
    case "$CERT" in
      *":$REGION:"*) ;;
      *) fail "certificate is not in $REGION; a load balancer cannot use it" ;;
    esac
  fi
else
  skip "no --certificate given"
fi

# --- image ------------------------------------------------------------------
if [ -n "$IMAGE" ]; then
  case "$IMAGE" in
    *@sha256:*) pass "image is pinned by digest" ;;
    *) fail "image is not pinned by digest; the template requires @sha256:..." ;;
  esac
  # Only checkable when the repository is in this account. A Marketplace ECR
  # path belongs to AWS and is expected to be unreadable from here.
  REPO=$(printf '%s' "$IMAGE" | sed -n 's|^[0-9]*\.dkr\.ecr\.[^/]*/\([^@]*\)@.*|\1|p')
  DIGEST=$(printf '%s' "$IMAGE" | sed -n 's|.*@\(sha256:[0-9a-f]*\)$|\1|p')
  if [ -n "$REPO" ] && [ -n "$DIGEST" ]; then
    if aws ecr describe-images --repository-name "$REPO" --image-ids imageDigest="$DIGEST" \
         --query 'imageDetails[0].imageDigest' --output text >/dev/null 2>&1; then
      pass "image digest exists in $REPO"
    else
      skip "cannot read $REPO from this account (expected for Marketplace ECR)"
    fi
  fi
else
  skip "no --image given"
fi

echo
if [ "$FAIL" -eq 0 ]; then
  echo "Preflight passed. Nothing was created."
  exit 0
fi
echo "Preflight FAILED. Fix the above before deploying; each of these fails only"
echo "after billable resources have already been built."
exit 1
