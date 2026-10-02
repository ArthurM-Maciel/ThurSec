"""Tests for the Supabase posture audit — fully offline (no network).

The HTTP layer (``SupabaseAudit._request``) is isolated so each test monkeypatches
it with a router returning canned ``HttpResponse`` objects per URL. This exercises
the real posture logic without ever opening a socket.
"""

import json

from thursec.core.context import RunContext
from thursec.core.finding import Severity
from thursec.modules.config_audit.supabase_audit import (
    HttpResponse,
    SupabaseAudit,
    _base_url,
    _mask,
    _tables_from_openapi,
)

# A realistic-looking anon JWT (role=anon) and service key (role=service_role).
# These are fabricated, not real credentials.
_ANON_KEY = (
    "eyJhbGciOiJIUzI1NiJ9."
    "eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlIn0."
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)
_SERVICE_KEY = (
    "eyJhbGciOiJIUzI1NiJ9."
    "eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UifQ."
    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)
_URL = "https://abcdefgh.supabase.co"

_OPENAPI = json.dumps(
    {
        "definitions": {"customers": {}, "orders": {}, "public_posts": {}},
        "paths": {"/customers": {}, "/orders": {}, "/public_posts": {}, "/rpc/foo": {}},
    }
)


def _ctx(**options):
    return RunContext(target=_URL, options=options)


def _router(routes):
    """Build a fake _request(method, url, apikey, body=None) from a route map.

    ``routes`` maps a substring of the URL to an HttpResponse (or a callable).
    """

    def fake_request(self, method, url, apikey, body=None):
        for needle, resp in routes.items():
            if needle in url:
                return resp(url) if callable(resp) else resp
        return HttpResponse(404, {}, "")

    return fake_request


def _no_key_leak(findings, *keys):
    """Assert no raw key appears in any field of any finding."""
    blob = "\n".join(json.dumps(f.to_dict()) for f in findings)
    for key in keys:
        assert key not in blob, "raw credential leaked into a finding!"


# --- helpers ---------------------------------------------------------------
def test_mask_redacts_key():
    masked = _mask(_SERVICE_KEY)
    assert _SERVICE_KEY not in masked
    assert masked.startswith("eyJh")
    assert "len=" in masked


def test_base_url_normalizes():
    assert _base_url("abcdefgh.supabase.co") == "https://abcdefgh.supabase.co"
    assert _base_url("https://x.supabase.co/rest/v1/") == "https://x.supabase.co"
    assert _base_url("") == ""


def test_tables_from_openapi_skips_rpc():
    tables = _tables_from_openapi(_OPENAPI)
    assert "customers" in tables and "orders" in tables
    assert "rpc" not in tables


# --- scenario: RLS off → anon reads tables → HIGH --------------------------
async def test_anon_can_read_tables_is_high(monkeypatch):
    routes = {
        "/rest/v1/customers": HttpResponse(200, {}, json.dumps([{"id": 1, "email": "x"}])),
        "/rest/v1/orders": HttpResponse(200, {}, json.dumps([{"id": 9}])),
        "/rest/v1/public_posts": HttpResponse(200, {}, json.dumps([])),  # empty → safe
        "/rest/v1/": HttpResponse(200, {}, _OPENAPI),
        "/storage/v1/bucket": HttpResponse(200, {}, json.dumps([])),
        "/": HttpResponse(200, {"Strict-Transport-Security": "max-age=1"}, ""),
    }
    monkeypatch.setattr(SupabaseAudit, "_request", _router(routes))

    findings = await SupabaseAudit().run(_ctx(anon_key=_ANON_KEY))

    high = [f for f in findings if f.severity is Severity.HIGH]
    assert len(high) == 1
    f = high[0]
    assert "2 table(s)" in f.title
    assert set(f.metadata["exposed_tables"]) == {"customers", "orders"}
    assert "public_posts" not in f.metadata["exposed_tables"]
    _no_key_leak(findings, _ANON_KEY, _SERVICE_KEY)


# --- scenario: secure project → no exposure findings -----------------------
async def test_secure_project_no_exposure(monkeypatch):
    # Every table probe returns an empty array (RLS enforced).
    def resp_for(url):
        if url.endswith("/rest/v1/") or url.rstrip("/").endswith("/rest/v1"):
            return HttpResponse(200, {}, _OPENAPI)
        return HttpResponse(200, {}, json.dumps([]))

    routes = {
        "/rest/v1/": resp_for,
        "/storage/v1/bucket": HttpResponse(200, {}, json.dumps([{"name": "avatars", "public": False}])),
        "/": HttpResponse(200, {"Strict-Transport-Security": "max-age=1"}, ""),
    }
    monkeypatch.setattr(SupabaseAudit, "_request", _router(routes))

    findings = await SupabaseAudit().run(_ctx(anon_key=_ANON_KEY))

    assert not [f for f in findings if f.severity >= Severity.HIGH]
    titles = [f.title for f in findings]
    assert any("No anonymous data exposure" in t for t in titles)
    assert any("No public storage buckets" in t for t in titles)
    _no_key_leak(findings, _ANON_KEY)


# --- scenario: public storage bucket → MEDIUM ------------------------------
async def test_public_bucket_is_medium(monkeypatch):
    buckets = json.dumps(
        [
            {"name": "avatars", "public": True},
            {"name": "secrets", "public": False},
        ]
    )
    routes = {
        "/rest/v1/": HttpResponse(401, {}, ""),  # anon rejected, skip exposure probe
        "/storage/v1/bucket": HttpResponse(200, {}, buckets),
        "/": HttpResponse(200, {}, ""),
    }
    monkeypatch.setattr(SupabaseAudit, "_request", _router(routes))

    findings = await SupabaseAudit().run(
        _ctx(anon_key=_ANON_KEY, service_role_key=_SERVICE_KEY)
    )

    med = [f for f in findings if "public storage" in f.title]
    assert len(med) == 1
    assert med[0].severity is Severity.MEDIUM
    assert med[0].metadata["public_buckets"] == ["avatars"]
    _no_key_leak(findings, _ANON_KEY, _SERVICE_KEY)


# --- scenario: service_role key in client → CRITICAL -----------------------
async def test_service_key_in_client_is_critical(monkeypatch):
    routes = {
        "/rest/v1/": HttpResponse(401, {}, ""),
        "/storage/v1/bucket": HttpResponse(403, {}, ""),
        "/": HttpResponse(200, {}, ""),
    }
    monkeypatch.setattr(SupabaseAudit, "_request", _router(routes))

    findings = await SupabaseAudit().run(
        _ctx(service_role_key=_SERVICE_KEY, service_key_in_client=True)
    )

    crit = [f for f in findings if f.severity is Severity.CRITICAL]
    assert len(crit) == 1
    assert "client-side" in crit[0].title
    assert crit[0].metadata["role"] == "service_role"
    _no_key_leak(findings, _SERVICE_KEY)


# --- scenario: service_role key supplied but server-side → INFO ------------
async def test_service_key_server_side_is_info(monkeypatch):
    routes = {
        "/rest/v1/": HttpResponse(401, {}, ""),
        "/storage/v1/bucket": HttpResponse(403, {}, ""),
        "/": HttpResponse(200, {}, ""),
    }
    monkeypatch.setattr(SupabaseAudit, "_request", _router(routes))

    findings = await SupabaseAudit().run(_ctx(service_role_key=_SERVICE_KEY))

    sk = [f for f in findings if "service_role" in f.title]
    assert sk and sk[0].severity is Severity.INFO
    _no_key_leak(findings, _SERVICE_KEY)


# --- scenario: invalid credential / network error → finding, no exception --
async def test_invalid_credential_yields_finding(monkeypatch):
    def boom(self, method, url, apikey, body=None):
        raise OSError("Name or service not known")

    monkeypatch.setattr(SupabaseAudit, "_request", boom)

    findings = await SupabaseAudit().run(_ctx(anon_key=_ANON_KEY))

    assert findings  # no exception propagated
    assert all(f.severity <= Severity.LOW for f in findings)
    assert any("Could not complete" in f.title for f in findings)
    _no_key_leak(findings, _ANON_KEY)


# --- scenario: no credentials at all → INFO guidance -----------------------
async def test_no_credentials_is_info():
    findings = await SupabaseAudit().run(_ctx())
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert "No Supabase credentials" in findings[0].title


# --- redaction is airtight across a full rich run --------------------------
async def test_no_key_appears_raw_in_any_finding(monkeypatch):
    routes = {
        "/rest/v1/customers": HttpResponse(200, {}, json.dumps([{"id": 1}])),
        "/rest/v1/orders": HttpResponse(200, {}, json.dumps([{"id": 2}])),
        "/rest/v1/public_posts": HttpResponse(200, {}, json.dumps([{"id": 3}])),
        "/rest/v1/": HttpResponse(200, {}, _OPENAPI),
        "/storage/v1/bucket": HttpResponse(200, {}, json.dumps([{"name": "a", "public": True}])),
        "/": HttpResponse(200, {}, ""),
    }
    monkeypatch.setattr(SupabaseAudit, "_request", _router(routes))

    findings = await SupabaseAudit().run(
        _ctx(
            anon_key=_ANON_KEY,
            service_role_key=_SERVICE_KEY,
            service_key_in_client=True,
        )
    )
    assert findings
    _no_key_leak(findings, _ANON_KEY, _SERVICE_KEY)
