import json

import pytest

from thursec.core.context import RunContext
from thursec.core.finding import Severity
from thursec.modules.recon.ct_subdomains import CtSubdomains, _extract_subdomains


# Sample crt.sh payload: multi-line name_value, wildcards, duplicates, casing,
# an apex entry, and an out-of-domain name that must be discarded.
_SAMPLE = json.dumps(
    [
        {"name_value": "www.example.com\n*.example.com"},
        {"name_value": "API.Example.com"},
        {"name_value": "www.example.com"},  # duplicate (different entry)
        {"name_value": "mail.example.com\napi.example.com"},  # dup within/across
        {"name_value": "example.com"},  # apex — kept (== domain)
        {"name_value": "evil.com\nshop.example.com.attacker.net"},  # out of scope
    ]
)


def _ctx(target="example.com"):
    return RunContext(target=target)


def test_extract_dedup_normalize_sort():
    subs = _extract_subdomains(json.loads(_SAMPLE), "example.com")
    assert subs == [
        "api.example.com",
        "example.com",
        "mail.example.com",
        "www.example.com",
    ]
    # wildcard prefix stripped, casing normalized, no out-of-scope names
    assert "evil.com" not in subs
    assert "shop.example.com.attacker.net" not in subs
    # sorted + deduped
    assert subs == sorted(subs)
    assert len(subs) == len(set(subs))


async def test_run_emits_info_finding(monkeypatch):
    monkeypatch.setattr(CtSubdomains, "fetch", lambda self, domain: _SAMPLE)
    findings = await CtSubdomains().run(_ctx())
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.INFO
    assert "Discovered 4 subdomains" in f.title
    assert f.metadata["count"] == 4
    assert f.metadata["subdomains"] == [
        "api.example.com",
        "example.com",
        "mail.example.com",
        "www.example.com",
    ]
    assert "www.example.com" in f.evidence


async def test_run_large_surface_is_low(monkeypatch):
    payload = json.dumps(
        [{"name_value": f"host{i}.example.com"} for i in range(60)]
    )
    monkeypatch.setattr(CtSubdomains, "fetch", lambda self, domain: payload)
    findings = await CtSubdomains().run(_ctx())
    f = findings[0]
    assert f.severity is Severity.LOW
    assert f.metadata["count"] == 60
    assert "attack surface" in f.recommendation.lower()
    # evidence is truncated with a "+N more" hint
    assert "more)" in f.evidence


async def test_run_normalizes_url_target(monkeypatch):
    captured = {}

    def fake_fetch(self, domain):
        captured["domain"] = domain
        return _SAMPLE

    monkeypatch.setattr(CtSubdomains, "fetch", fake_fetch)
    await CtSubdomains().run(_ctx("https://example.com/path"))
    assert captured["domain"] == "example.com"


async def test_run_handles_fetch_error_without_raising(monkeypatch):
    def boom(self, domain):
        raise OSError("network unreachable")

    monkeypatch.setattr(CtSubdomains, "fetch", boom)
    findings = await CtSubdomains().run(_ctx())
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.LOW
    assert "Could not query" in f.title
    assert "network unreachable" in f.evidence


async def test_run_handles_bad_json_without_raising(monkeypatch):
    monkeypatch.setattr(CtSubdomains, "fetch", lambda self, domain: "not json{")
    findings = await CtSubdomains().run(_ctx())
    assert len(findings) == 1
    assert "Could not query" in findings[0].title
