"""What is worth pinning in honeycombtool: the query shapes, and re-run safety.

Nothing here touches the network. The parts that talk to Honeycomb are thin
wrappers around urllib and would only be testing a mock of the API; the parts
that are easy to get silently wrong are the query specs, and getting one wrong
produces a trigger that is accepted and never fires.
"""
import pytest

from controlplane import alerting
from controlplane.honeycomb import (
    NEEDED,
    NOTIFY_TRIGGER,
    PAGE_TRIGGER,
    board_queries,
    combined,
    counter,
    find_by_name,
    main,
    triggers,
)


def calc_ops(query):
    return {c["op"] for c in query["calculations"]}


def test_counters_aggregate_with_sum_never_rate_sum():
    """RATE_SUM is refused on a Metrics dataset, and the refusal is invisible.

    Honeycomb stores a trigger holding one, lists it as healthy, and never
    evaluates it, because the query it would run is one the engine rejects. Both
    triggers in the first account this provisioned were in that state. SUM is
    correct as well as accepted: the counter's own temporal aggregation is
    applied first, so SUM over the window is the increase during it.
    """
    for spec in triggers():
        ops = calc_ops(spec["query"])
        assert ops == {"SUM"}, f"{spec['name']} aggregates with {ops}"
    for _, _, q in board_queries():
        assert "RATE_SUM" not in calc_ops(q)


def test_notify_trigger_reduces_three_counters_to_one_value():
    """A trigger query may hold only one aggregate; a formula is how three fit.

    Without the formula the API refuses the query outright with "only one
    non-having aggregate is allowed", which is what makes this the mechanism
    that fits four alertable conditions into the free plan's two triggers.
    """
    q = combined(alerting.by_urgency(alerting.NOTIFY), 900)
    notify = alerting.by_urgency(alerting.NOTIFY)
    assert len(q["calculations"]) == len(notify) == 3
    assert len(q["formulas"]) == 1
    assert q["formulas"][0]["expression"] == " + ".join("$" + c.key for c in notify)
    # Every alias the formula names has to exist as a calculation, or the
    # expression references nothing and the threshold compares against nothing.
    names = {c["name"] for c in q["calculations"]}
    for c in notify:
        assert c.key in names


def test_page_trigger_watches_only_lost_service():
    """The page stays alone deliberately.

    It is the only one of the four conditions that is an outage. Folding another
    counter in would mean the alert that should wake someone also fires for a
    billing problem, and an alert that cries wolf stops being a page.
    """
    page = next(t for t in triggers() if t["name"] == PAGE_TRIGGER)
    assert len(page["query"]["calculations"]) == 1
    assert "formulas" not in page["query"]
    assert page["query"]["calculations"][0]["column"] == "switchboard.empty_completion_failed_total"
    assert dict(page["tags"][1])["value"] == alerting.PAGE


def test_every_trigger_fires_above_zero():
    """These counters only move when something happened worth a person's time."""
    for spec in triggers():
        assert spec["threshold"] == {"op": ">", "value": 0}


def test_trigger_window_covers_its_evaluation_interval():
    """A window shorter than the frequency leaves gaps nothing ever looks at."""
    for spec in triggers():
        assert spec["query"]["time_range"] >= spec["frequency"]


def test_counter_helper_applies_the_otlp_prefix():
    """The bare name goes in, the dotted name comes out. alerting.py stores
    neither spelling, so this is where the OTLP one is added."""
    q = counter("x_total", "x", 300)
    assert q["calculations"] == [{"column": "switchboard.x_total", "op": "SUM", "name": "x"}]
    assert q["time_range"] == 300


def test_find_by_name_is_exact():
    """Re-run safety rests entirely on this, and a near-match would be worse
    than no match: it would silently rewrite a different trigger."""
    items = [{"name": "alpha", "id": "1"}, {"name": "alpha beta", "id": "2"}]
    assert find_by_name(items, "alpha")["id"] == "1"
    assert find_by_name(items, "alpha beta")["id"] == "2"
    assert find_by_name(items, "alph") is None
    assert find_by_name(items, "Alpha") is None
    assert find_by_name([], "alpha") is None
    # The API returns null rather than [] for an empty collection.
    assert find_by_name(None, "alpha") is None


def test_both_triggers_have_distinct_names():
    """Names are the identity used for updates, so a collision would make one
    trigger overwrite the other on every run."""
    names = [t["name"] for t in triggers()]
    assert len(set(names)) == len(names)
    assert set(names) == {PAGE_TRIGGER, NOTIFY_TRIGGER}


def test_descriptions_carry_the_counter_names():
    """The description is what arrives in the notification. The combined trigger
    cannot say which counter moved, so the text has to name all three or the
    alert is unactionable on its own."""
    notify = next(t for t in triggers() if t["name"] == NOTIFY_TRIGGER)
    for c in alerting.by_urgency(alerting.NOTIFY):
        assert c.metric in notify["description"]


def test_board_panels_are_described():
    """A panel with no description is a chart someone has to reverse-engineer
    while an alert is firing."""
    panels = board_queries()
    assert len(panels) >= 5
    for name, desc, q in panels:
        assert name and len(desc) > 40
        assert q["calculations"]


def test_every_needed_permission_is_explained():
    """The message a deployer gets has to name the switch to flip.

    The first key handed to this tool was a configuration key with two of these
    four switched off, and the tool's answer at the time was to guess it was an
    ingest key. /1/auth had the facts. Each permission therefore carries its own
    reason, so the failure says which one is missing and what it is for rather
    than restating that something is not allowed.
    """
    assert set(NEEDED) == {"triggers", "boards", "recipients", "queries"}
    for perm, why in NEEDED.items():
        assert why and not why.endswith("."), f"{perm} needs a reason phrase"


def test_config_key_is_read_from_its_own_variable(monkeypatch, capsys):
    """No fallback to HONEYCOMB_API_KEY, and the reason is not stylistic.

    That variable holds the ingest key, and the dev stack hands .dev/env to the
    gateway container wholesale -- so a configuration key placed there is
    readable by the data plane, which could then rewrite or delete the alerting
    that watches it. A fallback would make putting it in the wrong variable
    work, which is precisely how it would end up there.
    """
    monkeypatch.setenv("HONEYCOMB_API_KEY", "an-ingest-key")
    monkeypatch.delenv("HONEYCOMB_CONFIG_KEY", raising=False)
    with pytest.raises(SystemExit) as e:
        main(["--dataset", "Metrics", "--no-recipient"])
    msg = str(e.value)
    assert "HONEYCOMB_CONFIG_KEY" in msg
    assert "HONEYCOMB_API_KEY" in msg, "the message must say which variable NOT to use"


def test_recipient_choice_must_be_explicit(capsys):
    """Neither notifying nor not-notifying is a default.

    Both triggers once evaluated correctly and notified nobody for a session,
    which reads as coverage on a dashboard while being none. Silence is
    available but has to be typed.
    """
    with pytest.raises(SystemExit):
        main(["--dataset", "Metrics"])
