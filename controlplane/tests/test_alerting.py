"""The definitions, and the one property that made splitting them worth doing.

alerting.py exists so that "which counters matter and why" is written once and
each backend emitter applies its own spelling. The test that earns that split is
test_one_definition_produces_both_spellings: it is the regression guard for a
defect that already happened, where a trigger table was written in the /metrics
spelling, referenced Honeycomb columns that did not exist, was accepted, and
would silently never have fired.
"""
import pathlib
import re

import pytest

from controlplane import alerting, honeycomb, prometheus

REPO = pathlib.Path(__file__).resolve().parents[2]


def gateway_series() -> set[str]:
    """Every metric name the gateway actually publishes, read from the source.

    series() in telemetry.go is the single list both export paths are built
    from, and its own comment says it exists so the two cannot drift. This
    reaches into it so alerting.py cannot drift from *it* either -- a metric
    renamed in Go and not here produces an alert on a column that does not
    exist, which is precisely the failure this whole module is arranged to
    prevent.
    """
    src = (REPO / "internal/gateway/telemetry.go").read_text()
    block = src[src.index("s := []series{"):src.index("return s\n}")]
    names = set(re.findall(r'\{"([a-z_]+)",\s*"(?:counter|gauge)"', block))
    # log_dropped_total is appended conditionally, outside the literal.
    tail = src[src.index("m.LogDropped != nil"):]
    names.add(re.search(r'series\{"([a-z_]+)", "counter"', tail).group(1))
    names.add("request_duration_milliseconds")
    return names


def referenced() -> set[str]:
    names = {c.metric for c in alerting.CONDITIONS}
    names |= {m for p in alerting.PANELS for m in p.metrics}
    names |= set(alerting.NOT_ALERTED)
    names.add(alerting.LATENCY_METRIC)
    return names


def test_every_referenced_metric_exists_in_the_gateway():
    missing = referenced() - gateway_series()
    assert not missing, (
        f"alerting.py names metrics the gateway does not publish: {sorted(missing)}. "
        "An alert on a nonexistent metric is accepted by every backend here and never fires."
    )


def test_definitions_carry_no_prefix():
    """The prefix belongs to the emitter, because there are two of them.

    /metrics emits switchboard_<name> and OTLP emits switchboard.<name>. If a
    prefix leaked into a definition, one of the two emitters would produce a
    name with it applied twice and the other would be wrong.
    """
    for name in referenced():
        assert not name.startswith("switchboard"), f"{name} carries a prefix"


def test_one_definition_produces_both_spellings():
    """The whole reason this file is separate from the emitters.

    One condition, two backends, two spellings, neither written by hand.
    """
    cond = alerting.condition("lost_service")
    assert cond.metric == "empty_completion_failed_total"

    hny = honeycomb.counter(cond.metric, cond.key, cond.window)
    assert hny["calculations"][0]["column"] == "switchboard.empty_completion_failed_total"

    assert "switchboard_empty_completion_failed_total" in prometheus.expr(cond)
    assert "switchboard.empty_completion_failed_total" not in prometheus.expr(cond)


def test_exactly_one_condition_pages():
    """Two urgencies exist so the routing decision is unambiguous, and only an
    outage justifies waking someone. A second page-level condition should be a
    deliberate argument, not an accident of adding a counter."""
    paging = alerting.by_urgency(alerting.PAGE)
    assert len(paging) == 1
    assert paging[0].key == "lost_service"


def test_every_condition_is_actionable():
    """Detail text is what arrives in a notification at 3am. A condition whose
    description does not say what happened is an alert that becomes a habit of
    ignoring alerts."""
    for c in alerting.CONDITIONS:
        assert c.urgency in (alerting.PAGE, alerting.NOTIFY)
        assert len(c.summary) > 10
        assert len(c.detail) > 80, f"{c.key} needs a description someone can act on"
        assert c.window >= 60


def test_condition_keys_are_unique_and_identifier_safe():
    """Keys become formula aliases in Honeycomb and part of alert names in
    Prometheus, so a duplicate or an awkward character breaks one backend
    quietly."""
    keys = [c.key for c in alerting.CONDITIONS]
    assert len(set(keys)) == len(keys)
    for k in keys:
        assert re.fullmatch(r"[a-z][a-z0-9_]*", k), k


def test_recovered_completions_are_documented_as_not_alerted():
    """This one is repeatedly tempting to alert on and repeatedly wrong: the
    caller was served. Recording the reason is what stops it being re-litigated
    by whoever next reads a short list of alerts."""
    assert "empty_completion_recovered_total" in alerting.NOT_ALERTED
    assert "empty_completion_recovered_total" not in {c.metric for c in alerting.CONDITIONS}
    for metric, why in alerting.NOT_ALERTED.items():
        assert len(why) > 40, f"{metric} needs a reason, not a mention"


def test_not_alerted_and_conditions_do_not_overlap():
    assert not set(alerting.NOT_ALERTED) & {c.metric for c in alerting.CONDITIONS}


def test_condition_lookup_rejects_unknown_keys():
    with pytest.raises(KeyError):
        alerting.condition("no_such_condition")
