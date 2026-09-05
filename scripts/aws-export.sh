#!/bin/sh
# aws-export.sh — collect the Bedrock configuration `switchboard controls -aws`
# reads, into a directory you can hand to someone else.
#
# It reads and writes nothing in your account. Every command here is a GET, so
# the worst case is an empty file and a line in the summary saying why.
#
# What it is for: an assessment tool that wants production credentials is a
# six-week security review. One that reads a directory somebody already had
# permission to produce is a conversation. This is the ninety seconds that
# produces the directory.
#
#   ./scripts/aws-export.sh [outdir]        # default: ./bedrock-export
#   AWS_PROFILE=prod AWS_REGION=us-east-1 ./scripts/aws-export.sh
#
# Then: switchboard controls -aws ./bedrock-export

set -eu

out="${1:-./bedrock-export}"

if ! command -v aws >/dev/null 2>&1; then
	echo "aws CLI not found. Install it, or export the four documents by hand —" >&2
	echo "docs/adapters.md lists them." >&2
	exit 1
fi

# Refuse to merge into an existing directory. A stale file from a previous
# account is worse than a missing one: it is read, believed and attributed to
# this export.
if [ -e "$out" ]; then
	echo "$out already exists. Remove it or name a different directory:" >&2
	echo "  the adapter reads every .json in there, and a file left over from" >&2
	echo "  another account would be read as belonging to this one." >&2
	exit 1
fi
mkdir -p "$out"

notes="$out/EXPORT-NOTES.txt"
: > "$notes"
note() { echo "$1" >> "$notes"; echo "  - $1"; }

echo "Identity and region"
who=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo unknown)
region=$(aws configure get region 2>/dev/null || echo "${AWS_REGION:-unknown}")
echo "account $who, region $region" >> "$notes"
echo "  account $who, region $region"

# 1. Model invocation logging. An empty object here is the answer, not a
#    failure: it means logging is not configured, which is a finding.
echo "Model invocation logging"
logging_ok=0
if aws bedrock get-model-invocation-logging-configuration --output json \
	> "$out/logging.json" 2>/dev/null; then
	logging_ok=1
	echo "  written"
else
	# Deliberately not written as an empty object. An empty object is Bedrock's
	# way of saying logging is switched off, which is a finding; a call that
	# could not be made says nothing at all, and writing the first when we mean
	# the second invents the finding.
	rm -f "$out/logging.json"
	note "get-model-invocation-logging-configuration failed or is not permitted, \
so whether invocation logging is configured is UNKNOWN from this export — not off. \
Re-run with a principal holding bedrock:GetModelInvocationLoggingConfiguration."
fi

# 2. Guardrails. The list form carries only summaries, and the fields that
#    decide the redaction rows — the PII entities and their BLOCK/ANONYMIZE
#    actions — come back only from get-guardrail. So list, then fetch each.
echo "Guardrails"
# Whether the list came back empty and whether it came back at all are
# different answers, and the whole report depends on not confusing them.
listed=0
ids=$(aws bedrock list-guardrails --query 'guardrails[].id' --output text 2>/dev/null) && listed=1
if [ "$listed" = 1 ] && { [ -z "$ids" ] || [ "$ids" = "None" ]; }; then
	ids=$(aws bedrock list-guardrails --query 'guardrails[].guardrailId' --output text 2>/dev/null) || true
fi
if [ "$listed" = 0 ]; then
	note "list-guardrails failed or is not permitted, so whether any guardrail \
exists is UNKNOWN from this export — not none. Re-run with a principal holding \
bedrock:ListGuardrails."
elif [ -z "$ids" ] || [ "$ids" = "None" ]; then
	note "Asked, and this account and region hold no guardrails. The content-policy \
row reads as absent, which is a real finding rather than a gap in the export."
else
	n=0
	for id in $ids; do
		n=$((n + 1))
		if aws bedrock get-guardrail --guardrail-identifier "$id" --output json \
			> "$out/guardrail-$n.json" 2>/dev/null; then
			echo "  guardrail $id"
		else
			rm -f "$out/guardrail-$n.json"
			note "get-guardrail failed for $id; it is listed but its policies were not read."
		fi
	done
fi

# 3. CloudTrail. Read for what it says about API-call logging — never credited
#    to the audit record of the completions themselves.
echo "CloudTrail"
if aws cloudtrail describe-trails --output json > "$out/cloudtrail.json" 2>/dev/null; then
	echo "  written"
else
	rm -f "$out/cloudtrail.json"
	note "describe-trails failed or is not permitted."
fi

# 4. Object Lock on the log bucket. This is the step the hand-written recipe
#    leaves as <that-bucket>: the bucket is named inside the logging config, so
#    take it from there rather than asking. If logging writes to CloudWatch
#    only, there is no bucket and no lock to read — say so rather than leaving
#    a silence that reads as "not checked".
echo "Object Lock on the log bucket"
if [ "$logging_ok" = 0 ]; then
	note "The log bucket is named inside the logging configuration, which could \
not be read, so Object Lock on it is UNKNOWN rather than absent."
	bucket=""
else
	bucket=$(aws bedrock get-model-invocation-logging-configuration \
		--query 'loggingConfig.s3Config.bucketName' --output text 2>/dev/null) || bucket=""
fi
if [ "$logging_ok" = 0 ]; then
	:
elif [ -z "$bucket" ] || [ "$bucket" = "None" ]; then
	note "Model invocation logging does not deliver to S3, so there is no log \
bucket to check Object Lock on. If logs are archived elsewhere, say where: \
immutability of the archive is the control, and no export can show it."
else
	echo "  bucket $bucket" >> "$notes"
	if aws s3api get-object-lock-configuration --bucket "$bucket" --output json \
		> "$out/objectlock.json" 2>/dev/null; then
		echo "  $bucket has an Object Lock configuration"
	else
		rm -f "$out/objectlock.json"
		note "Bucket $bucket has no Object Lock configuration, or it could not be \
read. Without it a log object can be overwritten or deleted, and the \
tamper-evidence row will say so."
	fi
fi

echo
echo "Wrote $(find "$out" -name '*.json' | wc -l | tr -d ' ') document(s) to $out"
if [ -s "$notes" ]; then
	echo "Notes in $notes — these are part of the answer, not errors to hide."
fi
echo
echo "Next:  switchboard controls -aws $out"
echo "       switchboard controls -aws $out -profile finra -json > controls.json"
