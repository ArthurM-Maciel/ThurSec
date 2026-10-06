"""Tests for the cookie security-flag audit module.

No network is used: the single HTTP touchpoint
(``CookieAudit._get_set_cookies``) is monkeypatched to return canned raw
``Set-Cookie`` header strings, so these run fast and offline while exercising
flag detection, the all-flags-set benign case, the no-cookies case, the
cookie-value-never-logged guarantee, and the argument-injection guard (which
must refuse a flag-shaped target *without* opening any socket).
"""

import pytest

from thursec.core.context import RunContext
from thursec.core.finding import Severity
from thursec.core.i18n import get_lang, set_lang
from thursec.modules.config_audit.cookies import CookieAudit


@pytest.fixture(autouse=True)
def _force_en():
    """These assertions check English text; pin the language and restore it."""
    previous = get_lang()
    set_lang("en")
    try:
        yield
    finally:
        set_lang(previous)


def _ctx(target="https://example.com", **options):
    return RunContext(target=target, options=options)


def _patch_get(monkeypatch, cookies, recorder=None):
    """Replace the HTTP layer with a fake returning raw Set-Cookie strings."""

    def fake_get(self, host, port, scheme, timeout=10.0):
        if recorder is not None:
            recorder.append((host, port, scheme))
        return list(cookies)

    monkeypatch.setattr(CookieAudit, "_get_set_cookies", fake_get)


# A session cookie with a secret value and NO security flags, plus a fully
# hardened cookie carrying Secure + HttpOnly + SameSite.
_SECRET_VALUE = "s3cr3t-session-token-DO-NOT-LOG"
_INSECURE_COOKIE = f"sid={_SECRET_VALUE}; Path=/"
_SECURE_COOKIE = "hardened=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"


async def test_detects_all_missing_flags_on_insecure_cookie(monkeypatch):
    _patch_get(monkeypatch, [_INSECURE_COOKIE])
    findings = await CookieAudit().run(_ctx())

    flags = {
        f.metadata.get("flag")
        for f in findings
        if f.metadata.get("cookie") == "sid"
    }
    assert flags == {"Secure", "HttpOnly", "SameSite"}

    by_flag = {
        f.metadata["flag"]: f.severity
        for f in findings
        if f.metadata.get("flag")
    }
    assert by_flag["Secure"] is Severity.MEDIUM
    assert by_flag["HttpOnly"] is Severity.MEDIUM
    assert by_flag["SameSite"] is Severity.LOW
    # Every finding for the cookie names it and carries a recommendation.
    for f in findings:
        if f.metadata.get("cookie") == "sid":
            assert "sid" in f.evidence
            assert f.recommendation


async def test_cookie_value_never_appears_in_findings(monkeypatch):
    _patch_get(monkeypatch, [_INSECURE_COOKIE])
    findings = await CookieAudit().run(_ctx())

    assert findings  # sanity: we did produce findings
    for f in findings:
        blob = " ".join(
            [f.title, f.description, f.recommendation, f.evidence, str(f.metadata)]
        )
        assert _SECRET_VALUE not in blob


async def test_secure_cookie_has_no_flag_findings(monkeypatch):
    _patch_get(monkeypatch, [_SECURE_COOKIE])
    findings = await CookieAudit().run(_ctx())

    # No missing-flag findings; just a single clean INFO result.
    assert not any(f.metadata.get("flag") for f in findings)
    info = [f for f in findings if f.title.startswith("Cookie flags OK")]
    assert len(info) == 1
    assert info[0].severity is Severity.INFO


async def test_mixed_cookies_flag_only_the_insecure_one(monkeypatch):
    _patch_get(monkeypatch, [_INSECURE_COOKIE, _SECURE_COOKIE])
    findings = await CookieAudit().run(_ctx())

    flagged = {f.metadata.get("cookie") for f in findings if f.metadata.get("flag")}
    assert flagged == {"sid"}
    assert any(f.title.startswith("Cookie flags OK: hardened") for f in findings)


async def test_samesite_none_without_secure_is_medium(monkeypatch):
    _patch_get(monkeypatch, ["tracker=x; HttpOnly; Secure; SameSite=None"])
    findings = await CookieAudit().run(_ctx())
    # Secure present, HttpOnly present -> only the SameSite=None/no-Secure... but
    # Secure IS present here, so SameSite=None is acceptable: clean result.
    assert any(f.title.startswith("Cookie flags OK") for f in findings)

    _patch_get(monkeypatch, ["tracker=x; HttpOnly; SameSite=None"])
    findings = await CookieAudit().run(_ctx())
    ss = [f for f in findings if f.metadata.get("flag") == "SameSite=None"]
    assert len(ss) == 1
    assert ss[0].severity is Severity.MEDIUM


async def test_secure_not_flagged_over_plain_http(monkeypatch):
    # Over cleartext HTTP, missing Secure is not actionable and not reported.
    _patch_get(monkeypatch, ["sid=v; HttpOnly; SameSite=Lax"])
    findings = await CookieAudit().run(_ctx(target="http://example.com"))
    assert not any(f.metadata.get("flag") == "Secure" for f in findings)
    assert any(f.title.startswith("Cookie flags OK") for f in findings)


async def test_no_cookies_reports_info(monkeypatch):
    _patch_get(monkeypatch, [])
    findings = await CookieAudit().run(_ctx())
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert "no cookies" in findings[0].title.lower()


async def test_connection_error_is_handled_finding(monkeypatch):
    def boom(self, host, port, scheme, timeout=10.0):
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr(CookieAudit, "_get_set_cookies", boom)
    findings = await CookieAudit().run(_ctx())
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.LOW
    assert "could not complete" in f.title.lower()
    assert "connection refused" in f.evidence


@pytest.mark.parametrize("bad", ["-x", "--foo", "-oN/tmp/x", "", "  ", "a b"])
async def test_unsafe_target_refused_without_request(monkeypatch, bad):
    calls: list = []

    def fake_get(self, host, port, scheme, timeout=10.0):  # pragma: no cover
        calls.append((host, port, scheme))
        raise AssertionError("must not request for an unsafe target")

    monkeypatch.setattr(CookieAudit, "_get_set_cookies", fake_get)
    findings = await CookieAudit().run(_ctx(target=bad))

    assert calls == []  # no request was ever made
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert "Refusing to scan" in findings[0].title


async def test_scheme_and_port_derived_from_target(monkeypatch):
    seen: list = []
    _patch_get(monkeypatch, [_SECURE_COOKIE], recorder=seen)
    await CookieAudit().run(_ctx(target="http://example.com:8080"))
    assert seen == [("example.com", 8080, "http")]
