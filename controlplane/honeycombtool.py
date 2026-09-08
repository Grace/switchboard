"""Provision the Honeycomb alerting for a Switchboard deployment.

The alerting for this gateway existed for a while only because someone made a
series of API calls by hand, which meant a deployer got the documented advice to
create triggers and no means of doing it. This creates the same two triggers, one
recipient and one board in any Honeycomb environment, from flags.

    python -m controlplane.honeycombtool \\
      --dataset Metrics --recipient ops@example.com

There is no --env flag. A v1 API key is scoped to one environment, so the key
already chooses it and a flag would only imply a choice that is not there. The
key is read from HONEYCOMB_API_KEY rather than an argument so it stays out of the
process table and shell history, as the signing seed does in policytool.

Three behaviours here are not incidental, and each one is a bruise:

Re-running is safe. Everything is matched by name and updated in place. That is
not tidiness: the Honeycomb free plan allows two triggers per team, so a second
blind create *cannot* succeed, and a provisioning tool that only works against an
empty account is a tool you cannot run twice.

Failures print the API's own words. Tooling in front of this API reported
"Failed to save trigger" for a plan-limit rejection and for an invalid
aggregation alike, which cost an hour of looking at the query. Calling the API
directly returned the real message immediately in both cases.

Every trigger's query is executed before this exits. Honeycomb will accept a
trigger whose query it refuses to run, show it as healthy in the trigger list,
and never fire it. Both triggers in the first account this ran against were in
exactly that state for hours. Creating a trigger is therefore not evidence that
the trigger works, and the only evidence that is, is running its query.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

API = "https://api.honeycomb.io"

BOARD_NAME = "Switchboard gateway"

PAGE_TRIGGER = "Lost service: every route returned nothing"
NOTIFY_TRIGGER = "Something needs a person: billing, metering or an ambiguous retry"


class Fatal(SystemExit):
    def __init__(self, msg):
        super().__init__(f"honeycombtool: {msg}")


def api(key: str, method: str, path: str, body=None):
    """One HTTP call, with the server's own error text preserved.

    urllib raises HTTPError before a caller can read the body, and the body is
    the only part worth having: "exceeded maximum 2 triggers for this team's
    plan" and "aggregate operation not allowed in Metrics dataset: RATE_SUM" are
    both actionable, and both arrive as a bare 400 or 422 otherwise.
    """
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)
    req.add_header("X-Honeycomb-Team", key)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace").strip()
        try:
            detail = json.loads(detail).get("error", detail)
        except Exception:
            pass
        if "isn't allowed" in detail or "not allowed" in detail:
            raise Fatal(
                f"{detail}\n"
                "  This looks like an ingest key. An ingest key can send telemetry and nothing\n"
                "  else, and the one in a gateway's OTLP headers is usually exactly that.\n"
                "  Create a Configuration key under Environment settings > API keys with:\n"
                "    Manage Triggers, Manage Boards, Manage Recipients, Run Queries\n"
                "  Run Queries is not optional here. Without it the triggers can still be\n"
                "  written but not verified, and an unverified trigger is the failure this\n"
                "  tool exists to prevent, so it stops rather than reporting a false success."
            )
        if "maximum" in detail and "plan" in detail:
            raise Fatal(
                f"{detail}\n"
                "  This is a plan limit, not a problem with the query. The free plan allows two\n"
                "  triggers per team; docs/DEPLOYMENT.md shows how four conditions fit into two."
            )
        raise Fatal(f"{method} {path} -> {e.code}: {detail}")
    except urllib.error.URLError as e:
        raise Fatal(f"{method} {path} -> {e.reason}")


def counter(column: str, name: str, window: int) -> dict:
    """A query for one cumulative counter over the trigger's own window.

    SUM, never RATE_SUM. On a Metrics dataset Honeycomb applies the counter's
    temporal aggregation before this one, so SUM over the window is the increase
    during it rather than the running total, and RATE_SUM is refused outright by
    the query engine. A trigger holding one is accepted and then never evaluates.
    """
    return {
        "calculations": [{"column": column, "op": "SUM", "name": name}],
        "time_range": window,
    }


def combined(columns: dict[str, str], window: int) -> dict:
    """Several counters reduced to one value, so one trigger can watch them all.

    A trigger query may hold only one aggregate -- a second is refused with
    "only one non-having aggregate is allowed" -- but a formula collapses many
    into one, and formulas are permitted on a Metrics dataset. This is what makes
    four alertable conditions fit in the free plan's two triggers.
    """
    return {
        "calculations": [
            {"column": col, "op": "SUM", "name": alias} for alias, col in columns.items()
        ],
        "formulas": [
            {"name": "needs_a_human", "expression": " + ".join("$" + a for a in columns)}
        ],
        "time_range": window,
    }


def triggers() -> list[dict]:
    """The two triggers, in the order their slots matter.

    The page stays alone. It is the only one of the four conditions that is an
    outage, and folding anything else into it would blunt the single alert that
    should wake someone.
    """
    return [
        {
            "name": PAGE_TRIGGER,
            "description": (
                "switchboard.empty_completion_failed_total increased: every route produced no "
                "output and the caller received a 503. This is lost service, not degraded "
                "service. Page. Recovered empty completions are deliberately not alerted - those "
                "are spend and latency, not an outage."
            ),
            "query": counter("switchboard.empty_completion_failed_total", "failed", 300),
            "threshold": {"op": ">", "value": 0},
            "frequency": 300,
            "alert_type": "on_change",
            "tags": [
                {"key": "service", "value": "switchboard"},
                {"key": "urgency", "value": "page"},
            ],
        },
        {
            "name": NOTIFY_TRIGGER,
            "description": (
                "One of three counters moved. They are watched together because the Honeycomb "
                "free plan allows two triggers in total, not because they belong together; open "
                "the Switchboard gateway board to see which one moved. account_failover_total: a "
                "provider account is out of credits, below its balance floor, or has lost its "
                "quota. usage_mismatch_total: a provider's own token totals did not add up, so "
                "metering taken from that response may be wrong and any invoice covering the "
                "window is suspect. idempotent_unknown_total: a retry was refused because the "
                "original outcome was ambiguous."
            ),
            "query": combined(
                {
                    "failover": "switchboard.account_failover_total",
                    "mismatch": "switchboard.usage_mismatch_total",
                    "unknown": "switchboard.idempotent_unknown_total",
                },
                900,
            ),
            "threshold": {"op": ">", "value": 0},
            "frequency": 900,
            "alert_type": "on_change",
            "tags": [
                {"key": "service", "value": "switchboard"},
                {"key": "urgency", "value": "notify"},
            ],
        },
    ]


def sums(*columns: str) -> dict:
    return {"calculations": [{"column": c, "op": "SUM"} for c in columns], "time_range": 86400}


def board_queries() -> list[tuple[str, str, dict]]:
    """The panels, in reading order. The first is the one an alert sends you to."""
    return [
        (
            "Which one moved",
            "The three counters behind the combined notify trigger, separately. This is the "
            "panel that trigger sends you to.",
            sums(
                "switchboard.account_failover_total",
                "switchboard.usage_mismatch_total",
                "switchboard.idempotent_unknown_total",
            ),
        ),
        (
            "Empty completions",
            "Total, recovered and failed. Recovered means a later route answered: the caller was "
            "served but two providers were paid and both were waited for. Failed means nobody "
            "answered.",
            sums(
                "switchboard.empty_completion_total",
                "switchboard.empty_completion_recovered_total",
                "switchboard.empty_completion_failed_total",
            ),
        ),
        (
            "Idempotency",
            "Replay is the mechanism working. Conflict is a reused key with a different body. "
            "Unknown is the sticky state, where the original outcome could not be established "
            "and the retry was refused rather than charged twice.",
            sums(
                "switchboard.idempotent_replay_total",
                "switchboard.idempotent_conflict_total",
                "switchboard.idempotent_unknown_total",
            ),
        ),
        (
            "Traffic, errors, retries",
            "Denominator for everything above. Retries and rate limiting without a matching rise "
            "in errors means the gateway absorbed provider trouble rather than passing it on.",
            sums(
                "switchboard.requests_total",
                "switchboard.errors_total",
                "switchboard.retries_total",
                "switchboard.rate_limited_total",
            ),
        ),
        (
            "Request duration (shape only)",
            "The counts are right and the shape is readable. Percentiles are not: traffic below "
            "the lowest bucket bound falls in a bucket with no lower edge, so a percentile there "
            "extrapolates below zero and reports a negative duration.",
            {
                "calculations": [
                    {"column": "switchboard.request_duration_milliseconds", "op": "HEATMAP"}
                ],
                "time_range": 86400,
            },
        ),
    ]


BOARD_TEXT = """## Start here when a trigger fires

Two triggers cover four conditions, because the Honeycomb free plan allows two triggers in total.
That is a plan limit, not a judgement that these conditions belong together.

**Lost service** pages on `empty_completion_failed_total`: every route produced no output and the
caller got a 503. That one names its own cause.

**Something needs a person** notifies on the sum of three counters, so it tells you that something
moved but not which. The first panel below is the answer.

`empty_completion_recovered_total` deliberately has no trigger. A later route answered, so the
caller was served; it is spend and latency rather than an outage. Watch it here instead."""


def find_by_name(items, name: str):
    """Exact-name match, or None. The whole idempotency story rests on this.

    Exact rather than fuzzy on purpose: a near-match that silently updated the
    wrong trigger would be worse than creating a duplicate, and on a capped plan
    a duplicate is refused loudly anyway.
    """
    for it in items or []:
        if it.get("name") == name:
            return it
    return None


def run_query(key: str, dataset: str, query_id: str, name: str):
    """Execute a trigger's query and fail if the engine will not run it.

    A trigger is not proven by having been accepted. Honeycomb stores one whose
    query it refuses, reports it as healthy, and never fires it.
    """
    started = api(key, "POST", f"/1/query_results/{dataset}", {"query_id": query_id})
    rid = started.get("id")
    for _ in range(20):
        res = api(key, "GET", f"/1/query_results/{dataset}/{rid}")
        if res.get("complete"):
            return
        time.sleep(0.5)
    raise Fatal(f"query for {name!r} did not complete; treat the trigger as unverified")


def apply(key: str, dataset: str, recipient: str | None, dry_run: bool = False) -> int:
    """Reconcile the account against the definitions above.

    --dry-run exists because the honest way to check a provisioning tool is to
    point it at an account that is already provisioned and confirm it wants to
    change nothing. Doing that for real would mean writing to a live account to
    prove that writing was unnecessary.
    """
    changed = []
    plan = []

    def write(kind, name, fn):
        if dry_run:
            plan.append(f"would {kind}: {name}")
            return None
        return fn()

    recipients = []
    if recipient:
        listed = api(key, "GET", "/1/recipients") or []
        existing = find_by_name(
            [{**r, "name": r.get("target") or r.get("address")} for r in listed], recipient
        )
        if existing:
            print(f"recipient exists: {recipient}")
            recipients = [existing["id"]]
        else:
            made = write("create recipient", recipient,
                         lambda: api(key, "POST", "/1/recipients",
                                     {"type": "email", "target": recipient}))
            if made:
                print(f"recipient created: {recipient}")
                recipients = [made["id"]]
                changed.append("recipient")

    have = api(key, "GET", f"/1/triggers/{dataset}") or []
    for spec in triggers():
        body = dict(spec, recipients=recipients)
        found = find_by_name(have, spec["name"])
        if found:
            got = write("update trigger", spec["name"],
                        lambda: api(key, "PUT", f"/1/triggers/{dataset}/{found['id']}", body))
            if got:
                print(f"trigger updated: {spec['name']}")
        else:
            got = write("create trigger", spec["name"],
                        lambda: api(key, "POST", f"/1/triggers/{dataset}", body))
            if got:
                print(f"trigger created: {spec['name']}")
                changed.append(spec["name"])
        # Verified even on a dry run, against the trigger already in place. The
        # point of the check is to catch a stored trigger whose query the engine
        # will not run, and that is exactly what a dry run should surface.
        qid = got["query_id"] if got else (found or {}).get("query_id")
        if qid:
            run_query(key, dataset, qid, spec["name"])
            print(f"  query runs: {spec['name']}")

    boards = api(key, "GET", "/1/boards") or []
    if find_by_name(boards, BOARD_NAME):
        print(f"board exists: {BOARD_NAME}")
    else:
        panels = [
            {
                "type": "text",
                "position": {"x_coordinate": 0, "y_coordinate": 0, "width": 12, "height": 5},
                "text_panel": {"content": BOARD_TEXT},
            }
        ]
        for i, (name, desc, spec) in enumerate(board_queries()):
            q = api(key, "POST", f"/1/queries/{dataset}", spec)
            ann = api(
                key,
                "POST",
                f"/1/query_annotations/{dataset}",
                {"name": name, "description": desc, "query_id": q["id"]},
            )
            panels.append(
                {
                    "type": "query",
                    "position": {
                        "x_coordinate": 0 if i % 2 == 0 else 6,
                        "y_coordinate": 5 + (i // 2) * 4,
                        "width": 6,
                        "height": 4,
                    },
                    "query_panel": {
                        "query_id": q["id"],
                        "query_annotation_id": ann["id"],
                        "query_style": "combo",
                        "dataset": dataset,
                    },
                }
            )
        made = write("create board", BOARD_NAME, lambda: api(
            key,
            "POST",
            "/1/boards",
            {
                "name": BOARD_NAME,
                "description": "What the two triggers cannot tell you: which counter moved, "
                "and what the gateway was doing when it did.",
                "type": "flexible",
                "panels": panels,
                "tags": [{"key": "service", "value": "switchboard"}],
            },
        ))
        if made:
            print(f"board created: {made['links']['board_url']}")
            changed.append(BOARD_NAME)

    print()
    if dry_run:
        print("\n".join(plan) if plan else "no changes; everything already exists")
    else:
        print("created: " + (", ".join(changed) if changed else
                             "nothing; everything already existed"))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m controlplane.honeycombtool",
        description="Create or update the Switchboard triggers, recipient and board in Honeycomb.",
    )
    ap.add_argument("--dataset", default="Metrics",
                    help="dataset holding the switchboard.* counters (default: Metrics)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--recipient", help="email address the triggers notify")
    g.add_argument("--no-recipient", action="store_true",
                   help="create the triggers notifying nobody; they will be visible in the "
                        "Honeycomb UI and will page no one, which is worse than having no "
                        "trigger because it reads as coverage. Required explicitly for that "
                        "reason rather than being the default.")
    ap.add_argument("--dry-run", action="store_true",
                    help="read the account and report what would change, writing nothing. "
                         "Trigger queries are still executed, since a stored trigger the engine "
                         "refuses to run is exactly what a dry run should catch.")
    a = ap.parse_args(argv)

    key = os.environ.get("HONEYCOMB_API_KEY", "").strip()
    if not key:
        raise Fatal("set HONEYCOMB_API_KEY to a key with permission to manage triggers and boards")
    return apply(key, a.dataset, None if a.no_recipient else a.recipient, a.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
