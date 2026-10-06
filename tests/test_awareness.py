"""Tests for the security-awareness (anti-phishing training) subsystem.

These assert the ethical gates hold: a recipient outside the allowlist is
refused, a campaign without authorization is refused, the generated landing
page contains no credential-capture surface whatsoever, tracking tokens are
unique, and click metrics aggregate correctly.
"""

from __future__ import annotations

import re
from datetime import date

import pytest

from thursec.awareness import (
    Allowlist,
    Authorization,
    AuthorizationError,
    AllowlistError,
    Campaign,
    build_tracking_url,
    render_email_template,
    render_landing_page,
    tally_clicks,
)
from thursec.core.i18n import get_lang, set_lang


@pytest.fixture(autouse=True)
def _force_en():
    """The landing/e-mail assertions check English text; pin and restore it."""
    previous = get_lang()
    set_lang("en")
    try:
        yield
    finally:
        set_lang(previous)


def _auth():
    return Authorization.create("Jane Security", "2026-10-05")


def _allowlist():
    return Allowlist.from_entries(["corp.example", "ceo@vip.example"])


def _campaign(recipients, base_url="https://train.corp.example/awareness"):
    return Campaign(
        name="Q4 Phishing Drill",
        authorization=_auth(),
        allowlist=_allowlist(),
        base_url=base_url,
        recipients=recipients,
    )


# (a) recipient outside the allowlist is REFUSED -----------------------------

def test_recipient_outside_allowlist_is_refused():
    with pytest.raises(AllowlistError) as exc:
        _campaign(["alice@corp.example", "mallory@evil.example"])
    assert "evil.example" in str(exc.value)


def test_domain_and_explicit_email_allowlist_permit_valid_recipients():
    c = _campaign(["alice@corp.example", "ceo@vip.example"])
    assert c.recipients == ["alice@corp.example", "ceo@vip.example"]


def test_allowlist_matching_is_case_insensitive():
    c = _campaign(["Alice@CORP.Example"])
    assert c.recipients == ["alice@corp.example"]


def test_empty_allowlist_is_refused():
    with pytest.raises(AllowlistError):
        Allowlist.from_entries([])


# (b) missing authorization -> REFUSED ---------------------------------------

def test_missing_authorized_by_is_refused():
    with pytest.raises(AuthorizationError):
        Authorization.create("", "2026-10-05")


def test_missing_authorized_on_is_refused():
    with pytest.raises(AuthorizationError):
        Authorization.create("Jane Security", None)


def test_invalid_authorization_date_is_refused():
    with pytest.raises(AuthorizationError):
        Authorization.create("Jane Security", "not-a-date")


def test_campaign_requires_real_authorization_object():
    with pytest.raises(AuthorizationError):
        Campaign(
            name="x",
            authorization="Jane said ok",  # type: ignore[arg-type]
            allowlist=_allowlist(),
            base_url="https://x.example",
            recipients=["alice@corp.example"],
        )


# (c) landing page has NO credential capture ---------------------------------

def test_landing_page_has_no_credential_capture():
    html = render_landing_page(
        campaign_name="Q4 Phishing Drill",
        authorized_by="Jane Security",
        authorized_on=date(2026, 10, 5),
    )
    low = html.lower()
    assert 'type="password"' not in low
    assert "type='password'" not in low
    # No password input in any spacing/casing variant.
    assert not re.search(r"<input[^>]*password", low)
    # No form/login/input surface at all — nothing that could collect anything.
    assert "<form" not in low
    assert "<input" not in low
    assert "<textarea" not in low
    assert "<button" not in low
    # The word "password" only ever appears as a teaching point ("IT will never
    # ask for your password"), never attached to an input field.
    assert not re.search(r"(name|id|placeholder)\s*=\s*[\"'][^\"']*password", low)


def test_landing_page_is_educational_and_self_contained():
    html = render_landing_page()
    assert html.lstrip().startswith("<!doctype html>")
    assert "awareness" in html.lower()
    assert "report" in html.lower()


# (d) tokens are unique ------------------------------------------------------

def test_tokens_are_unique_per_recipient():
    recipients = [f"user{i}@corp.example" for i in range(50)]
    c = _campaign(recipients)
    tokens = c.token_values()
    assert len(tokens) == 50
    assert len(set(tokens)) == 50  # all unique
    # each recipient has exactly one token and a matching link
    for rt in c.tokens:
        assert rt.token in rt.tracking_url


def test_build_tracking_url_appends_token():
    assert build_tracking_url("https://x.example/p", "abc") == "https://x.example/p?t=abc"
    assert build_tracking_url("https://x.example/p?a=1", "abc") == "https://x.example/p?a=1&t=abc"


# (e) tally aggregates correctly ---------------------------------------------

def test_tally_clicks_aggregates_correctly():
    tokens = ["t1", "t2", "t3", "t4"]
    log = ["t1", "t1", "t3", "zz"]  # t1 twice (dedup), t3 once, zz unknown
    m = tally_clicks(tokens, log)
    assert m["sent"] == 4
    assert m["clicked"] == 2
    assert m["not_clicked"] == 2
    assert m["click_rate"] == 0.5
    assert m["unknown_hits"] == 1


def test_tally_clicks_handles_empty():
    m = tally_clicks([], [])
    assert m["sent"] == 0
    assert m["clicked"] == 0
    assert m["click_rate"] == 0.0


# Email template: text only, clearly marked simulation, no send function ------

def test_email_template_is_marked_simulation_and_has_no_send():
    import thursec.awareness.campaign as campaign_mod

    text = render_email_template(campaign_name="Q4 Phishing Drill", tracking_url="https://t/x?t=1")
    assert "SIMULATION NOTICE" in text
    assert "awareness" in text.lower()
    # There is deliberately no transport in the subsystem.
    for name in dir(campaign_mod):
        assert not name.lower().startswith("send")
        assert "smtp" not in name.lower()
