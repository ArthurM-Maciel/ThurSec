import json
from datetime import datetime, timedelta, timezone

import pytest

from thursec.core import i18n
from thursec.core.context import RunContext
from thursec.core.finding import Severity
from thursec.modules.recon.whois import (
    WhoisRdap,
    _parse_rdap,
)


@pytest.fixture(autouse=True)
def _english_findings():
    """Findings are i18n'd (pt by default). These tests assert the English
    wording, so pin the language to 'en' and restore it afterwards."""
    previous = i18n.get_lang()
    i18n.set_lang("en")
    try:
        yield
    finally:
        i18n.set_lang(previous)


def _rdap_payload(expiration="2030-01-01T00:00:00Z"):
    """A realistic RDAP domain object with events, nameservers, entities, status."""
    return {
        "objectClassName": "domain",
        "ldhName": "example.com",
        "status": ["client transfer prohibited", "server delete prohibited"],
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": expiration},
            {"eventAction": "last changed", "eventDate": "2024-08-14T07:01:44Z"},
            {"eventAction": "last update of RDAP database", "eventDate": "2026-01-01T00:00:00Z"},
        ],
        "nameservers": [
            {"ldhName": "A.IANA-SERVERS.NET"},
            {"ldhName": "b.iana-servers.net"},
            {"ldhName": "a.iana-servers.net"},  # dup / casing
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "handle": "376",
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"],
                    ],
                ],
            },
            {"roles": ["abuse"], "handle": "ignore-me"},
        ],
    }


def _ctx(target="example.com"):
    return RunContext(target=target)


def test_parse_registrar_dates_nameservers_status():
    info = _parse_rdap(_rdap_payload(), "example.com")
    assert info["registrar"] == "RESERVED-Internet Assigned Numbers Authority"
    assert info["events"]["registration"] == "1995-08-14T04:00:00Z"
    assert info["events"]["expiration"] == "2030-01-01T00:00:00Z"
    assert info["events"]["last-changed"] == "2024-08-14T07:01:44Z"
    # nameservers lowercased, deduped, sorted
    assert info["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert info["status"] == [
        "client transfer prohibited",
        "server delete prohibited",
    ]


async def test_run_emits_info_summary(monkeypatch):
    monkeypatch.setattr(
        WhoisRdap, "fetch", lambda self, domain: json.dumps(_rdap_payload())
    )
    findings = await WhoisRdap().run(_ctx())
    # future expiry => only the INFO summary finding
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.INFO
    assert "Domain registration data" in f.title
    assert f.metadata["registrar"] == "RESERVED-Internet Assigned Numbers Authority"
    assert f.metadata["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert "registrar:" in f.evidence
    assert "expiration: 2030-01-01T00:00:00Z" in f.evidence


async def test_run_flags_expires_soon(monkeypatch):
    soon = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
    monkeypatch.setattr(
        WhoisRdap,
        "fetch",
        lambda self, domain: json.dumps(_rdap_payload(expiration=soon)),
    )
    findings = await WhoisRdap().run(_ctx())
    assert len(findings) == 2
    expiry = next(f for f in findings if f.severity is Severity.MEDIUM)
    assert expiry.title == "Domain expires soon"
    assert "in 9 day(s)" in expiry.description or "in 10 day(s)" in expiry.description


async def test_run_flags_expired_as_high(monkeypatch):
    past = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    monkeypatch.setattr(
        WhoisRdap,
        "fetch",
        lambda self, domain: json.dumps(_rdap_payload(expiration=past)),
    )
    findings = await WhoisRdap().run(_ctx())
    high = next(f for f in findings if f.severity is Severity.HIGH)
    assert high.title == "Domain is expired"
    assert "expired" in high.description.lower()


async def test_run_normalizes_url_target(monkeypatch):
    captured = {}

    def fake_fetch(self, domain):
        captured["domain"] = domain
        return json.dumps(_rdap_payload())

    monkeypatch.setattr(WhoisRdap, "fetch", fake_fetch)
    await WhoisRdap().run(_ctx("https://example.com/path"))
    assert captured["domain"] == "example.com"


async def test_run_handles_fetch_error_without_raising(monkeypatch):
    def boom(self, domain):
        raise OSError("network unreachable")

    monkeypatch.setattr(WhoisRdap, "fetch", boom)
    findings = await WhoisRdap().run(_ctx())
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.LOW
    assert "Could not retrieve RDAP data" in f.title
    assert "network unreachable" in f.evidence


async def test_run_handles_bad_json_without_raising(monkeypatch):
    monkeypatch.setattr(WhoisRdap, "fetch", lambda self, domain: "not json{")
    findings = await WhoisRdap().run(_ctx())
    assert len(findings) == 1
    assert "Could not retrieve RDAP data" in findings[0].title
    assert findings[0].severity is Severity.LOW


async def test_run_handles_non_object_json(monkeypatch):
    monkeypatch.setattr(WhoisRdap, "fetch", lambda self, domain: "[]")
    findings = await WhoisRdap().run(_ctx())
    assert len(findings) == 1
    assert "Could not retrieve RDAP data" in findings[0].title
