#!/bin/sh
# aws-invoice.sh — pull the provider's own account of what it served, into a
# file `switchboard reconcile` can read.
#
# It reads and writes nothing in your account. Every command here is a GET.
#
# What it is for: reconciling the log against the bill is the strongest test in
# an AI controls review, because the bill is the one record of these events that
# nobody in your organisation can edit. It is also the test almost nobody runs,
# because getting the numbers out is a morning's work. This is that morning.
#
#   ./scripts/aws-invoice.sh 2026-07 2026-09 [outfile]
#   AWS_PROFILE=prod AWS_REGION=us-east-1 ./scripts/aws-invoice.sh 2026-07 2026-09
#
# Then: switchboard reconcile -invoice ./bedrock-invoice.csv -period 2026-Q3
#
# Months are inclusive and are the provider's, which is to say UTC.

set -eu

start="${1:-}"
end="${2:-}"
out="${3:-./bedrock-invoice.csv}"

usage() {
	echo "usage: $0 FROM-MONTH TO-MONTH [outfile]   (e.g. $0 2026-07 2026-09)" >&2
	exit 2
}
case "$start" in [0-9][0-9][0-9][0-9]-[0-9][0-9]) ;; *) usage ;; esac
case "$end" in [0-9][0-9][0-9][0-9]-[0-9][0-9]) ;; *) usage ;; esac

if ! command -v aws >/dev/null 2>&1; then
	echo "aws CLI not found. Install it, or export the columns by hand —" >&2
	echo "docs/reconciliation.md gives the four-column format." >&2
	exit 1
fi

if [ -e "$out" ]; then
	echo "$out already exists. Remove it or name a different file: a stale" >&2
	echo "export from another account would be read as belonging to this one." >&2
	exit 1
fi

notes="$out.NOTES.txt"
: > "$notes"
note() { echo "$1" >> "$notes"; echo "  - $1"; }

acct=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo unknown)
echo "account $acct" >> "$notes"
echo "  account $acct, $start through $end inclusive"

# Cost Explorer, not CUR. CUR 2.0 is the better source and needs a Data Export
# configured and delivered to S3, which is a day's wait the first time; Cost
# Explorer answers now. What that costs you is the team split — see the end of
# this file.
#
# Usage types are written out verbatim rather than decoded here. switchboard
# already parses them, and a second parser in shell is a second place to be
# wrong about which suffix means a cache read.
echo "line_item_product_code,line_item_usage_type,line_item_usage_start_date,line_item_usage_amount,line_item_unblended_cost,line_item_currency_code" > "$out"

y=$(echo "$start" | cut -d- -f1)
m=$(echo "$start" | cut -d- -f2)
ey=$(echo "$end" | cut -d- -f1)
em=$(echo "$end" | cut -d- -f2)

# Strip the leading zero before any arithmetic. The shell reads 08 and 09 as
# octal and refuses them, which turns August and September into a parse error
# and every other month into a working script.
m=${m#0}
em=${em#0}

# Month arithmetic in shell rather than date(1): BSD date wants -v+1m and GNU
# date wants -d, and this script has to run on both.
cur=$(( y * 12 + m - 1 ))
last=$(( ey * 12 + em - 1 ))
if [ "$cur" -gt "$last" ]; then
	echo "$start is after $end." >&2
	exit 2
fi

rows=0
failed=0
while [ "$cur" -le "$last" ]; do
	my=$(( cur / 12 ))
	mm=$(( cur % 12 + 1 ))
	from=$(printf '%04d-%02d-01' "$my" "$mm")
	ny=$my
	nm=$(( mm + 1 ))
	if [ "$nm" -gt 12 ]; then nm=1; ny=$(( my + 1 )); fi
	to=$(printf '%04d-%02d-01' "$ny" "$nm")

	echo "  $from"
	# Each call is one Cost Explorer request. AWS charges $0.01 for each of
	# them, so a year is twelve cents — worth saying out loud, because it is
	# the one command in switchboard's tooling that is not free.
	if tmp=$(aws ce get-cost-and-usage \
		--time-period "Start=$from,End=$to" \
		--granularity MONTHLY \
		--metrics UsageQuantity UnblendedCost \
		--filter '{"Dimensions":{"Key":"SERVICE","Values":["Amazon Bedrock"]}}' \
		--group-by Type=DIMENSION,Key=USAGE_TYPE \
		--query 'ResultsByTime[0].Groups[].[Keys[0],Metrics.UsageQuantity.Amount,Metrics.UnblendedCost.Amount,Metrics.UnblendedCost.Unit]' \
		--output text 2>/dev/null); then
		if [ -n "$tmp" ]; then
			n=$(printf '%s\n' "$tmp" | awk -v d="$from" 'NF>=3 {
				printf "AmazonBedrock,%s,%sT00:00:00Z,%s,%s,%s\n", $1, d, $2, $3, ($4=="" ? "USD" : $4)
			}' | tee -a "$out" | wc -l)
			rows=$(( rows + n ))
		else
			# Asked, and this account billed no Bedrock usage that month. That
			# is an answer, and it is a different one from a call that failed.
			note "$from: asked, and this account has no Amazon Bedrock charges in it. \
If you expected some, check the region and the payer account — consolidated \
billing puts member usage on the payer's Cost Explorer, not the member's."
		fi
	else
		failed=1
		note "$from: get-cost-and-usage failed or is not permitted, so this month is \
UNKNOWN in this export — not zero. Re-run with a principal holding ce:GetCostAndUsage, \
and note that Cost Explorer must be enabled for the account once before it answers at all."
	fi
	cur=$(( cur + 1 ))
done

echo "  $rows line items → $out"

if [ "$failed" = 1 ]; then
	note "At least one month could not be read. switchboard will compare the months that \
are here and cannot know that the others are missing, so read the list above before \
reading the report."
fi

# The one thing this source cannot give you, said plainly rather than left to be
# discovered from an empty column.
note "This export carries no team. Cost Explorer cannot group by IAM principal or \
session tag — that data exists only in CUR 2.0 (AWS Data Exports) — so 'switchboard \
reconcile' will compare models and months and will report the per-team split as \
unknown. To reconcile the chargeback split as well, configure a CUR 2.0 export, \
activate the tag under Billing -> Cost allocation tags, and pass the CUR csv instead. \
That is the test that tells you whether your session tags are reaching the bill."

note "Cost Explorer rounds and restates. Figures for the current month, and for the \
few days after one closes, move. Reconcile closed months."

echo
echo "Written: $out"
echo "         $notes   <- read this first"
echo
# The whole range, not just the first month: a period naming one month would
# quietly reconcile a twelfth of what was just exported.
nd=$(printf '%04d-%02d-01' "$ny" "$nm")
echo "Next:    switchboard reconcile -invoice $out -period $start-01..$nd"
