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

    def fake_get(self, host, port, scheme, timeout=10.0, verify=True):
        if recorder is not None:
            recorder.append((host, port, scheme, verify))
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
    def boom(self, host, port, scheme, timeout=10.0, verify=True, check_hostname=True):
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

    def fake_get(self, host, port, scheme, timeout=10.0, verify=True):  # pragma: no cover
        calls.append((host, port, scheme, verify))
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
    """Antes isso virava LOW 'verifique se o host oferece HTTP(S) nesta porta'."""
    set_lang("pt")

    def boom(self, host, port, scheme, timeout=10.0, verify=True, check_hostname=True):
        raise _verify_error(62, "Hostname mismatch")

    monkeypatch.setattr(CookieAudit, "_get_set_cookies", boom)
    findings = await CookieAudit().run(_ctx())

    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "não cobre este domínio" in findings[0].title
    assert findings[0].metadata["verify_code"] == 62


async def test_com_opt_in_repete_preservando_a_cadeia(monkeypatch):
    """A bandeira vale na repetição, e a repetição mantém o que dá para manter."""
    set_lang("pt")
    chamadas: list = []

    def tls(self, host, port, scheme, timeout=10.0, verify=True, check_hostname=True):
        chamadas.append((verify, check_hostname))
        # Só o nome está errado: sem exigi-lo, a cadeia continua válida.
        if check_hostname:
            raise _verify_error(62, "Hostname mismatch")
        return ["sid=abc; Path=/"]

    monkeypatch.setattr(CookieAudit, "_get_set_cookies", tls)
    findings = await CookieAudit().run(_ctx(insecure_tls=True))

    # Verificado -> dispensa só o nome. Nunca precisou chegar a CERT_NONE.
    assert chamadas == [(True, True), (True, False)]
    assert findings[0].metadata["verify_code"] == 62
    # Nada sai do canal não verificado sem a marca.
    assert all(f.metadata.get("tls_verified") is False for f in findings[1:])


async def test_so_cai_para_cert_none_quando_nem_a_cadeia_se_sustenta(monkeypatch):
    """Cair direto para CERT_NONE aceitaria o certificado de qualquer um."""
    set_lang("pt")
    chamadas: list = []

    def tls(self, host, port, scheme, timeout=10.0, verify=True, check_hostname=True):
        chamadas.append((verify, check_hostname))
        if verify:
            raise _verify_error(18, "self signed certificate")
        return ["sid=abc; Path=/"]

    monkeypatch.setattr(CookieAudit, "_get_set_cookies", tls)
    await CookieAudit().run(_ctx(insecure_tls=True))

    assert chamadas == [(True, True), (True, False), (False, False)]


async def test_a_bandeira_nao_rebaixa_uma_conexao_que_seria_verificada(monkeypatch):
    """Com certificado bom, insecure_tls não deve desligar a verificação."""
    chamadas: list = []

    def ok(self, host, port, scheme, timeout=10.0, verify=True, check_hostname=True):
        chamadas.append(verify)
        return ["sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"]

    monkeypatch.setattr(CookieAudit, "_get_set_cookies", ok)
    findings = await CookieAudit().run(_ctx(insecure_tls=True))

    assert chamadas == [True]
    assert all("tls_verified" not in f.metadata for f in findings)


async def test_quando_a_repeticao_falha_o_achado_nao_diz_que_seguiu(monkeypatch):
    """Nenhum teste cobria esse caminho, e era onde a descrição mentia."""
    set_lang("pt")

    def tls(self, host, port, scheme, timeout=10.0, verify=True, check_hostname=True):
        if verify:
            raise _verify_error(18, "self signed certificate")
        raise ConnectionResetError("connection reset by peer")

    monkeypatch.setattr(CookieAudit, "_get_set_cookies", tls)
    findings = await CookieAudit().run(_ctx(insecure_tls=True))

    assert len(findings) == 2
    # A descrição fala da configuração da execução, nunca do que este módulo
    # conseguiu: afirmar aqui que a auditoria seguiu seria falso, e separar o
    # desfecho na chave de dedup traria de volta a contagem dupla.
    assert "seguiu" not in findings[0].description
    assert "connection reset" in findings[1].evidence


async def test_faixa_de_rede_e_recusada_sem_abrir_socket(monkeypatch):
    """Auditar o endereço de rede e rotular com o /24 é relatar 254 hosts por um."""
    chamadas: list = []

    def nunca(self, host, port, scheme, timeout=10.0, verify=True, check_hostname=True):
        chamadas.append(host)  # pragma: no cover
        raise AssertionError("não pode conectar a uma faixa")

    monkeypatch.setattr(CookieAudit, "_get_set_cookies", nunca)
    findings = await CookieAudit().run(_ctx(target="10.0.0.0/24"))

    assert chamadas == []
    assert len(findings) == 1
    assert "network range" in findings[0].title
