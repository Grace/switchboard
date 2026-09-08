"""The reporting logic, without a database.

fetch() is two SQL statements and would only be testing a mock. What is worth
pinning is the report: whether it correctly says the provider that answered was
one this policy allows, because that sentence is the whole point of recording the
policy version and a wrong one would be believed.
"""
import datetime
import json

import base64

from controlplane.replay import report, routes_of

WHEN = datetime.datetime(2026, 9, 8, 17, 35, tzinfo=datetime.timezone.utc)


def event(**over):
    e = {
        "request_id": "9b8341eecc1919f3cccc6dbabed7a83b",
        "status": 200, "attempts": 1, "provider": "openai", "policy_version": 3,
    }
    e.update(over)
    return {"event": e, "received_at": WHEN}


def envelope(routes):
    """The real shape: base64 canonical JSON under "payload", which is what the
    signature covers. An earlier version of this test invented a nested object
    and passed while the tool reported every request as inconsistent."""
    doc = json.dumps({"schema": 1, "tenant": "t", "version": 3, "routes": routes}).encode()
    return {"key_id": "dev-local", "payload": base64.b64encode(doc).decode(), "signature": "x"}


def policy(routes, version=3):
    return {"version": version, "created_at": WHEN, "envelope": envelope(routes)}


def test_marks_the_route_that_answered():
    out = report(event(), policy([
        {"provider": "openai", "model": "gpt-5-nano"},
        {"provider": "anthropic", "model": "claude-haiku-4-5-20251001"},
    ]))
    assert "1. openai:gpt-5-nano  <- answered" in out
    assert "2. anthropic:claude-haiku-4-5-20251001" in out
    assert "<- answered" not in out.split("2. anthropic")[1]


def test_model_is_derived_not_stored():
    """A policy forbids a repeated provider, so the provider determines the
    model. Nothing stores the model on the event and the report still names it."""
    out = report(event(provider="anthropic"), policy([
        {"provider": "openai", "model": "gpt-5-nano"},
        {"provider": "anthropic", "model": "claude-haiku-4-5-20251001"},
    ]))
    assert "consistent: anthropic is in this policy, serving claude-haiku-4-5-20251001" in out


def test_warns_when_the_provider_is_not_in_the_policy():
    """Either a bug or a policy that rotated mid-flight. Both are worth being
    told about, and silence here would make the report actively misleading."""
    out = report(event(provider="bedrock"), policy([{"provider": "openai", "model": "gpt-5-nano"}]))
    assert "WARNING" in out
    assert "bedrock answered but is not in policy v3" in out
    assert "consistent" not in out


def test_missing_policy_says_why_rather_than_failing():
    """A gateway can run a policy file directly with no control plane behind it.
    That is a supported mode, not a missing row, and the report should not imply
    the request never happened."""
    out = " ".join(report(event(), None).split())
    assert "not found in the policies table" in out
    assert "ran a policy file directly with no control plane behind it" in out


def test_event_without_a_policy_version_is_still_reported():
    """Events predating this field exist. They are less useful, not unusable."""
    out = report(event(policy_version=None), None)
    assert "(not recorded)" in out


def test_a_request_that_reached_no_provider_says_so():
    """A 401 or a policy refusal has no provider. Printing an empty field would
    read as missing data rather than as the answer."""
    out = report(event(provider=None, status=401, attempts=0), None)
    assert "(never reached one)" in out


def test_captured_content_is_included_when_present():
    out = report(event(), None, capture={
        "prompt": {"messages": [{"role": "user", "content": "hello"}]},
        "completion": {"choices": [{"message": {"content": "hi"}}]},
        "fault": "rate_limit",
    })
    assert "captured content:" in out
    assert "hello" in out and "hi" in out
    assert "fault: rate_limit" in out


def test_report_without_capture_shows_no_content_section():
    """Capture is off by default. A report that always printed an empty content
    heading would suggest something was lost rather than never collected."""
    assert "captured content:" not in report(event(), None)


def test_routes_are_decoded_from_the_signed_payload():
    routes = [{"provider": "openai", "model": "gpt-5-nano"}]
    assert routes_of(envelope(routes)) == routes
    assert routes_of({}) == []
    assert routes_of({"payload": "not base64 at all !!"}) == []


def test_an_undecodable_envelope_makes_no_claim_about_routes():
    """Reporting an unreadable envelope as an empty route list would make every
    request look inconsistent with its own policy. Silence beats a falsehood."""
    out = report(event(), {"version": 3, "created_at": WHEN, "envelope": {"payload": "!!"}})
    assert "could not" in out
    assert "WARNING" not in out
    assert "consistent" not in out
