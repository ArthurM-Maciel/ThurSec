import json

from thursec.core.context import RunContext
from thursec.core.finding import Severity
from thursec.modules.recon.dns_enum import DnsEnum, _clean_txt, _parse_answer


def _doh(*datas):
    """Build a DoH JSON answer with one entry per ``data`` value."""
    return json.dumps(
        {"Status": 0, "Answer": [{"name": "x", "type": 0, "data": d} for d in datas]}
    )


# A healthy domain: has SPF (in TXT) and DMARC (at _dmarc.*).
_HEALTHY = {
    ("example.com", "A"): _doh("93.184.216.34"),
    ("example.com", "AAAA"): _doh("2606:2800:220:1:248:1893:25c8:1946"),
    ("example.com", "MX"): _doh("10 mail.example.com."),
    ("example.com", "NS"): _doh("a.iana-servers.net.", "b.iana-servers.net."),
    ("example.com", "TXT"): _doh('"v=spf1 include:_spf.google.com ~all"', '"misc=1"'),
    ("example.com", "CNAME"): _doh(),  # no CNAME at apex
    ("_dmarc.example.com", "TXT"): _doh('"v=DMARC1; p=reject; rua=mailto:d@example.com"'),
}

# An unhealthy domain: TXT present but no SPF; _dmarc has unrelated TXT only.
_UNHEALTHY = {
    ("bad.com", "A"): _doh("1.2.3.4"),
    ("bad.com", "AAAA"): _doh(),
    ("bad.com", "MX"): _doh("5 mx.bad.com."),
    ("bad.com", "NS"): _doh("ns1.bad.com."),
    ("bad.com", "TXT"): _doh('"google-site-verification=abc"'),
    ("bad.com", "CNAME"): _doh(),
    ("_dmarc.bad.com", "TXT"): _doh('"some=other"'),
}


def _fake_fetch(table):
    def fetch(self, name, rtype):
        return table[(name, rtype)]

    return fetch


def _ctx(target="example.com"):
    return RunContext(target=target)


def _titles(findings):
    return [f.title for f in findings]


# --- parsing ---------------------------------------------------------------
def test_parse_answer_extracts_data():
    recs = _parse_answer(json.loads(_doh("10 mail.example.com.", "20 mail2.example.com.")))
    assert recs == ["10 mail.example.com.", "20 mail2.example.com."]


def test_parse_answer_handles_missing_answer():
    assert _parse_answer({"Status": 3}) == []
    assert _parse_answer("garbage") == []


def test_clean_txt_unquotes_and_joins_chunks():
    assert _clean_txt('"v=spf1 ~all"') == "v=spf1 ~all"
    # Long TXT arrives as adjacent quoted chunks.
    assert _clean_txt('"part1" "part2"') == "part1part2"


# --- happy path ------------------------------------------------------------
async def test_run_emits_info_per_type_with_records(monkeypatch):
    monkeypatch.setattr(DnsEnum, "fetch", _fake_fetch(_HEALTHY))
    findings = await DnsEnum().run(_ctx("example.com"))

    info = [f for f in findings if f.severity is Severity.INFO]
    # A, AAAA, MX, NS, TXT -> 5 INFO findings (CNAME empty -> none).
    types = {f.metadata["type"] for f in info}
    assert types == {"A", "AAAA", "MX", "NS", "TXT"}

    mx = next(f for f in info if f.metadata["type"] == "MX")
    assert mx.metadata["records"] == ["10 mail.example.com."]
    assert "10 mail.example.com." in mx.evidence

    # Healthy domain: no SPF/DMARC hygiene findings.
    assert not any("SPF" in t for t in _titles(findings))
    assert not any("DMARC" in t for t in _titles(findings))


# --- hygiene checks --------------------------------------------------------
async def test_run_flags_missing_spf_and_dmarc(monkeypatch):
    monkeypatch.setattr(DnsEnum, "fetch", _fake_fetch(_UNHEALTHY))
    findings = await DnsEnum().run(_ctx("bad.com"))

    spf = next(f for f in findings if "SPF" in f.title)
    dmarc = next(f for f in findings if "DMARC" in f.title)
    assert spf.severity is Severity.LOW
    assert dmarc.severity is Severity.LOW
    assert spf.recommendation  # actionable
    assert dmarc.recommendation
    assert spf.metadata["check"] == "spf"
    assert dmarc.metadata["check"] == "dmarc"


async def test_run_normalizes_url_target(monkeypatch):
    seen = set()

    def fetch(self, name, rtype):
        seen.add(name)
        return _HEALTHY[(name, rtype)]

    monkeypatch.setattr(DnsEnum, "fetch", fetch)
    await DnsEnum().run(_ctx("https://example.com/some/path"))
    assert "example.com" in seen
    assert "_dmarc.example.com" in seen


# --- error path ------------------------------------------------------------
async def test_run_handles_fetch_error_without_raising(monkeypatch):
    def boom(self, name, rtype):
        raise OSError("network unreachable")

    monkeypatch.setattr(DnsEnum, "fetch", boom)
    findings = await DnsEnum().run(_ctx("example.com"))

    # Every lookup failed -> only handled error findings, no exception.
    assert findings
    assert all(f.severity is Severity.LOW for f in findings)
    assert all("Could not resolve" in f.title for f in findings)
    assert any("network unreachable" in f.evidence for f in findings)
    # A failed TXT lookup must NOT be misreported as "missing SPF".
    assert not any("SPF" in f.title for f in findings)


async def test_run_handles_bad_json_without_raising(monkeypatch):
    monkeypatch.setattr(DnsEnum, "fetch", lambda self, name, rtype: "not json{")
    findings = await DnsEnum().run(_ctx("example.com"))
    assert findings
    assert all("Could not resolve" in f.title for f in findings)
