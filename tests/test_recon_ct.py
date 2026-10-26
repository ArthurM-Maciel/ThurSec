import json
import socket
import ssl
import urllib.error

import pytest

from thursec.core import i18n
from thursec.core.context import RunContext
from thursec.core.finding import Severity
from thursec.modules.recon import ct_subdomains
from thursec.modules.recon.ct_subdomains import CtSubdomains, _extract_subdomains


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


def _ctx(target="example.com", options=None):
    return RunContext(target=target, options=options or {})


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
    monkeypatch.setattr(CtSubdomains, "fetch", lambda self, domain, *_a: _SAMPLE)
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
    monkeypatch.setattr(CtSubdomains, "fetch", lambda self, domain, *_a: payload)
    findings = await CtSubdomains().run(_ctx())
    f = findings[0]
    assert f.severity is Severity.LOW
    assert f.metadata["count"] == 60
    assert "attack surface" in f.recommendation.lower()
    # evidence is truncated with a "+N more" hint
    assert "more)" in f.evidence


async def test_run_normalizes_url_target(monkeypatch):
    captured = {}

    def fake_fetch(self, domain, *_a):
        captured["domain"] = domain
        return _SAMPLE

    monkeypatch.setattr(CtSubdomains, "fetch", fake_fetch)
    await CtSubdomains().run(_ctx("https://example.com/path"))
    assert captured["domain"] == "example.com"


async def test_run_handles_fetch_error_without_raising(monkeypatch):
    def boom(self, domain, *_a):
        raise OSError("network unreachable")

    monkeypatch.setattr(CtSubdomains, "fetch", boom)
    findings = await CtSubdomains().run(_ctx())
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.LOW
    assert "Could not query" in f.title
    assert "network unreachable" in f.evidence


async def test_run_handles_bad_json_without_raising(monkeypatch):
    monkeypatch.setattr(CtSubdomains, "fetch", lambda self, domain, *_a: "not json{")
    findings = await CtSubdomains().run(_ctx())
    assert len(findings) == 1
    assert "Could not query" in findings[0].title


@pytest.mark.asyncio
async def test_timeout_option_reaches_fetch(monkeypatch):
    """A opção 'timeout' chega ao fetch; sem ela vale o padrão mais folgado."""
    seen = []
    monkeypatch.setattr(
        CtSubdomains, "fetch", lambda self, domain, timeout=None: seen.append(timeout) or _SAMPLE
    )

    await CtSubdomains().run(_ctx())
    assert seen[-1] == ct_subdomains._DEFAULT_TIMEOUT

    await CtSubdomains().run(_ctx(options={"timeout": 5}))
    assert seen[-1] == 5.0


def test_fetch_retries_once_on_transient_http_error(monkeypatch):
    """Um 502 do crt.sh é repetido uma vez; um 404 sobe na hora."""
    monkeypatch.setattr(ct_subdomains.time, "sleep", lambda _s: None)
    calls = []

    def flaky(req, timeout=None):
        calls.append(timeout)
        if len(calls) == 1:
            raise urllib.error.HTTPError(req.full_url, 502, "Bad Gateway", {}, None)

        class _Resp:
            def read(self):
                return _SAMPLE.encode()

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        return _Resp()

    monkeypatch.setattr(ct_subdomains.urllib.request, "urlopen", flaky)
    assert CtSubdomains().fetch("example.com") == _SAMPLE
    assert len(calls) == 2

    def not_found(req, timeout=None):
        calls.append(timeout)
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)

    monkeypatch.setattr(ct_subdomains.urllib.request, "urlopen", not_found)
    before = len(calls)
    with pytest.raises(urllib.error.HTTPError):
        CtSubdomains().fetch("example.com")
    assert len(calls) - before == 1


def test_fetch_retries_on_dropped_connection(monkeypatch):
    """Conexão derrubada/estourada também é repetida — é a falha mais comum."""
    monkeypatch.setattr(ct_subdomains.time, "sleep", lambda _s: None)
    calls = []

    class _Resp:
        def read(self):
            return _SAMPLE.encode()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def flaky(req, timeout=None):
        calls.append(timeout)
        if len(calls) == 1:
            raise urllib.error.URLError(TimeoutError("timed out"))
        return _Resp()

    monkeypatch.setattr(ct_subdomains.urllib.request, "urlopen", flaky)
    assert CtSubdomains().fetch("example.com") == _SAMPLE
    assert len(calls) == 2


def test_retry_delay_honours_retry_after_within_bounds():
    def _err(retry_after):
        return urllib.error.HTTPError(
            "https://crt.sh/", 429, "Too Many Requests", {"Retry-After": retry_after}, None
        )

    assert ct_subdomains._retry_delay(_err("10")) == 10.0
    assert ct_subdomains._retry_delay(_err("1")) == ct_subdomains._RETRY_DELAY
    assert ct_subdomains._retry_delay(_err("99999")) == ct_subdomains._MAX_RETRY_DELAY
    assert ct_subdomains._retry_delay(_err("depois")) == ct_subdomains._RETRY_DELAY


@pytest.mark.asyncio
async def test_bad_timeout_option_falls_back_to_default(monkeypatch):
    """--opt timeout=rapido usa o padrão em vez de virar achado de rede."""
    seen = []
    monkeypatch.setattr(
        CtSubdomains, "fetch", lambda self, domain, timeout=None: seen.append(timeout) or _SAMPLE
    )
    await CtSubdomains().run(_ctx(options={"timeout": "rapido"}))
    assert seen[-1] == ct_subdomains._DEFAULT_TIMEOUT
    await CtSubdomains().run(_ctx(options={"timeout": -5}))
    assert seen[-1] == ct_subdomains._DEFAULT_TIMEOUT


def test_fetch_gives_up_after_max_attempts(monkeypatch):
    """O 502 persistente do crt.sh sobe como erro depois de _MAX_ATTEMPTS."""
    monkeypatch.setattr(ct_subdomains.time, "sleep", lambda _s: None)
    calls = []

    def always_502(req, timeout=None):
        calls.append(timeout)
        raise urllib.error.HTTPError(req.full_url, 502, "Bad Gateway", {}, None)

    monkeypatch.setattr(ct_subdomains.urllib.request, "urlopen", always_502)
    with pytest.raises(urllib.error.HTTPError):
        CtSubdomains().fetch("example.com")
    assert len(calls) == ct_subdomains._MAX_ATTEMPTS


def test_total_budget_is_not_multiplied_by_the_retries(monkeypatch):
    """O timeout do operador é orçamento total: a soma das tentativas respeita."""
    clock = {"t": 0.0}
    monkeypatch.setattr(ct_subdomains.time, "monotonic", lambda: clock["t"])
    monkeypatch.setattr(ct_subdomains.time, "sleep", lambda s: clock.__setitem__("t", clock["t"] + s))

    budgets = []

    def slow_502(req, timeout=None):
        budgets.append(timeout)
        clock["t"] += timeout  # a tentativa consome o que lhe foi dado
        raise urllib.error.HTTPError(req.full_url, 502, "Bad Gateway", {}, None)

    monkeypatch.setattr(ct_subdomains.urllib.request, "urlopen", slow_502)
    with pytest.raises(urllib.error.HTTPError):
        CtSubdomains().fetch("example.com", timeout=10.0)

    # Nenhuma tentativa recebe mais do que sobra, e o total não passa do orçamento.
    assert sum(budgets) <= 10.0
    assert all(b > 0 for b in budgets)


def test_permanent_failures_are_not_retried(monkeypatch):
    """NXDOMAIN e falha de TLS não melhoram repetindo — sobem na primeira."""
    monkeypatch.setattr(ct_subdomains.time, "sleep", lambda _s: None)

    for reason in (socket.gaierror("nodename nor servname provided"),
                   ssl.SSLCertVerificationError("bad cert")):
        calls = []

        def permanent(req, timeout=None, _r=reason):
            calls.append(timeout)
            raise urllib.error.URLError(_r)

        monkeypatch.setattr(ct_subdomains.urllib.request, "urlopen", permanent)
        with pytest.raises(urllib.error.URLError):
            CtSubdomains().fetch("example.com")
        assert len(calls) == 1, f"{type(reason).__name__} não devia ser repetido"
