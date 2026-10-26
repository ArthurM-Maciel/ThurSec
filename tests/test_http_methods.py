"""Tests for the HTTP methods & info-exposure module.

No network is used: the single HTTP touchpoint (``HttpMethods._options``) is
monkeypatched to return canned ``(status, headers)`` tuples, so these run fast
and offline while exercising detection, info-leak reporting, the benign case,
and the argument-injection guard (which must refuse a flag-shaped target
*without* opening any socket).
"""

import pytest

from thursec.core.context import RunContext
from thursec.core.finding import Severity
from thursec.core.i18n import get_lang, set_lang
from thursec.modules.vuln.http_methods import HttpMethods


@pytest.fixture(autouse=True)
def _force_english():
    """These tests assert the English finding text; pin the language to en."""
    prev = get_lang()
    set_lang("en")
    try:
        yield
    finally:
        set_lang(prev)


def _ctx(target="https://example.com", **options):
    return RunContext(target=target, options=options)


def _patch_options(monkeypatch, status, headers, recorder=None):
    """Replace the HTTP layer with a fake returning (status, headers)."""

    def fake_options(self, host, port, scheme, timeout=10.0, verify=True):
        if recorder is not None:
            recorder.append((host, port, scheme, verify))
        return status, headers

    monkeypatch.setattr(HttpMethods, "_options", fake_options)


# Headers with a dangerous Allow + Server/X-Powered-By info leak.
_DANGEROUS_HEADERS = {
    "Allow": "GET, HEAD, POST, PUT, DELETE, OPTIONS, TRACE",
    "Server": "Apache/2.4.29 (Ubuntu)",
    "X-Powered-By": "PHP/7.2.24",
}

# Benign: only safe methods, no info-leak headers.
_BENIGN_HEADERS = {
    "Allow": "GET, HEAD, OPTIONS",
    "Content-Length": "0",
}


async def test_detects_dangerous_methods(monkeypatch):
    _patch_options(monkeypatch, 200, _DANGEROUS_HEADERS)
    findings = await HttpMethods().run(_ctx())

    methods = {
        f.metadata.get("method")
        for f in findings
        if f.title.startswith("Dangerous HTTP method")
    }
    assert methods == {"PUT", "DELETE", "TRACE"}

    by_method = {
        f.metadata["method"]: f.severity
        for f in findings
        if f.metadata.get("method")
    }
    assert by_method["PUT"] is Severity.HIGH
    assert by_method["TRACE"] is Severity.MEDIUM
    assert by_method["DELETE"] is Severity.MEDIUM
    # Each dangerous finding carries the raw Allow header as evidence + a rec.
    trace = next(f for f in findings if f.metadata.get("method") == "TRACE")
    assert "TRACE" in trace.evidence
    assert trace.recommendation


async def test_detects_info_leak_headers(monkeypatch):
    _patch_options(monkeypatch, 200, _DANGEROUS_HEADERS)
    findings = await HttpMethods().run(_ctx())

    leaks = {
        f.metadata.get("header"): f.evidence
        for f in findings
        if f.title.startswith("Information exposure header")
    }
    assert "server" in leaks
    assert "Apache/2.4.29 (Ubuntu)" in leaks["server"]
    assert "x-powered-by" in leaks
    assert "PHP/7.2.24" in leaks["x-powered-by"]


async def test_benign_response_has_no_method_or_leak_findings(monkeypatch):
    _patch_options(monkeypatch, 200, _BENIGN_HEADERS)
    findings = await HttpMethods().run(_ctx())

    assert not any(f.title.startswith("Dangerous HTTP method") for f in findings)
    assert not any(
        f.title.startswith("Information exposure header") for f in findings
    )
    # Advertised-but-safe methods are recorded as a single INFO finding.
    info = [f for f in findings if "no dangerous verbs" in f.title]
    assert len(info) == 1
    assert info[0].severity is Severity.INFO


async def test_no_allow_header_reports_info(monkeypatch):
    _patch_options(monkeypatch, 204, {"Content-Length": "0"})
    findings = await HttpMethods().run(_ctx())
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert "no allow header" in findings[0].title.lower()


async def test_connection_error_is_handled_finding(monkeypatch):
    def boom(self, host, port, scheme, timeout=10.0, verify=True, check_hostname=True):
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr(HttpMethods, "_options", boom)
    findings = await HttpMethods().run(_ctx())
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.LOW
    assert "could not complete" in f.title.lower()
    assert "connection refused" in f.evidence


@pytest.mark.parametrize("bad", ["-x", "--foo", "-oN/tmp/x", "", "  ", "a b"])
async def test_unsafe_target_refused_without_request(monkeypatch, bad):
    calls: list = []

    def fake_options(self, host, port, scheme, timeout=10.0, verify=True):  # pragma: no cover
        calls.append((host, port, scheme, verify))
        raise AssertionError("must not request for an unsafe target")

    monkeypatch.setattr(HttpMethods, "_options", fake_options)
    findings = await HttpMethods().run(_ctx(target=bad))

    assert calls == []  # no request was ever made
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert "Refusing to scan" in findings[0].title


async def test_scheme_and_port_derived_from_target(monkeypatch):
    seen: list = []
    _patch_options(monkeypatch, 200, _BENIGN_HEADERS, recorder=seen)
    await HttpMethods().run(_ctx(target="http://example.com:8080"))
    assert seen == [("example.com", 8080, "http", True)]


# --- certificado recusado não é "porta errada" -----------------------------
import ssl as _ssl


def _verify_error(code, message):
    error = _ssl.SSLCertVerificationError(
        f"[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: {message}"
    )
    error.verify_code = code
    error.verify_message = message
    return error


async def test_certificado_recusado_vira_achado_de_certificado(monkeypatch):
    """Antes isso virava LOW 'verifique se o host serve HTTP(S) nesta porta'."""
    set_lang("pt")

    def boom(self, host, port, scheme, timeout=10.0, verify=True, check_hostname=True):
        raise _verify_error(10, "certificate has expired")

    monkeypatch.setattr(HttpMethods, "_options", boom)
    findings = await HttpMethods().run(_ctx())

    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert "expirado" in findings[0].title


async def test_quando_a_repeticao_falha_o_achado_nao_diz_que_seguiu(monkeypatch):
    """Nenhum teste cobria esse caminho, e era onde a descrição mentia."""
    set_lang("pt")

    def tls(self, host, port, scheme, timeout=10.0, verify=True, check_hostname=True):
        if verify:
            raise _verify_error(18, "self signed certificate")
        raise ConnectionResetError("connection reset by peer")

    monkeypatch.setattr(HttpMethods, "_options", tls)
    findings = await HttpMethods().run(_ctx(insecure_tls=True))

    assert len(findings) == 2
    # A descrição fala da configuração da execução, nunca do que este módulo
    # conseguiu: afirmar aqui que a auditoria seguiu seria falso, e separar o
    # desfecho na chave de dedup traria de volta a contagem dupla.
    assert "seguiu" not in findings[0].description
    assert "connection reset" in findings[1].evidence


async def test_faixa_de_rede_e_recusada_sem_abrir_socket(monkeypatch):
    chamadas: list = []

    def nunca(self, host, port, scheme, timeout=10.0, verify=True, check_hostname=True):
        chamadas.append(host)  # pragma: no cover
        raise AssertionError("não pode conectar a uma faixa")

    monkeypatch.setattr(HttpMethods, "_options", nunca)
    findings = await HttpMethods().run(_ctx(target="10.0.0.0/24"))

    assert chamadas == []
    assert len(findings) == 1
    assert "network range" in findings[0].title
