"""Testes do módulo de TLS + cabeçalhos de segurança.

Nenhuma rede é usada: os dois pontos de contato (``_tls_info`` e
``_fetch_headers``) são monkeypatchados. O foco é a classificação de uma falha
de verificação de certificado — que é um defeito do alvo, e não uma falha de
conectividade — e a continuação opt-in da auditoria sobre TLS não verificado.
"""

import ssl
from datetime import datetime, timedelta, timezone

import pytest

from thursec.core.context import RunContext
from thursec.core.finding import Severity
from thursec.core.i18n import get_lang, set_lang
from thursec.core import tls as core_tls
from thursec.modules.config_audit import tls_headers as mod
from thursec.modules.config_audit.tls_headers import TlsHeadersAudit


@pytest.fixture(autouse=True)
def _force_pt():
    """As asserções checam o texto em português; fixe o idioma e restaure."""
    previous = get_lang()
    set_lang("pt")
    try:
        yield
    finally:
        set_lang(previous)


def _ctx(target="https://example.com", **options):
    return RunContext(target=target, options=options)


def _cert(days_valid=365):
    expires = datetime.now(timezone.utc) + timedelta(days=days_valid)
    return {"notAfter": expires.strftime("%b %d %H:%M:%S %Y GMT")}


def _verify_error(code, message):
    """Uma SSLCertVerificationError como o stdlib a entrega."""
    error = ssl.SSLCertVerificationError(
        f"[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: {message}"
    )
    error.verify_code = code
    error.verify_message = message
    error.reason = "CERTIFICATE_VERIFY_FAILED"
    return error


def _patch(monkeypatch, *, tls, headers=None, recorder=None):
    """Substitui a camada de rede. *tls* recebe (host, port, verify, check_hostname)."""

    def fake_tls_info(host, port, verify=True, check_hostname=True):
        if recorder is not None:
            recorder.append(("tls", host, port, verify, check_hostname))
        return tls(host, port, verify, check_hostname)

    def fake_fetch_headers(host, port, verify=True, check_hostname=True):
        if recorder is not None:
            recorder.append(("headers", host, port, verify, check_hostname))
        return dict(headers or {})

    monkeypatch.setattr(mod, "_tls_info", fake_tls_info)
    monkeypatch.setattr(mod, "_fetch_headers", fake_fetch_headers)


# --- classificação da falha de verificação ---------------------------------
@pytest.mark.parametrize(
    "code, expected_severity, expected_title",
    [
        (62, Severity.HIGH, "não cobre este domínio"),
        (10, Severity.CRITICAL, "expirado"),
        (23, Severity.CRITICAL, "revogado"),
        (18, Severity.HIGH, "autoassinado"),
        (20, Severity.HIGH, "incompleta"),
        (9, Severity.HIGH, "ainda não é válido"),
    ],
)
async def test_falha_de_verificacao_vira_achado_especifico(
    monkeypatch, code, expected_severity, expected_title
):
    """Um certificado que o cliente recusa é defeito do alvo, não falta de conexão."""

    def boom(host, port, verify, check_hostname=True):
        raise _verify_error(code, "detalhe do OpenSSL")

    _patch(monkeypatch, tls=boom)
    findings = await TlsHeadersAudit().run(_ctx())

    assert len(findings) == 1
    assert findings[0].severity is expected_severity
    assert expected_title in findings[0].title
    assert findings[0].metadata["verify_code"] == code


async def test_codigo_de_verificacao_desconhecido_nao_desce_para_medio():
    """Fora da tabela ainda é um certificado recusado — baixar para MÉDIO subnotifica."""
    severity, *_ = core_tls._VERIFY_FALLBACK
    assert severity is Severity.HIGH
    assert 999 not in core_tls._VERIFY_FAILURES


async def test_falha_de_conexao_continua_media(monkeypatch):
    """Porta fechada ou timeout não é defeito de certificado: segue MÉDIO."""

    def boom(host, port, verify, check_hostname=True):
        raise ConnectionRefusedError("connection refused")

    _patch(monkeypatch, tls=boom)
    findings = await TlsHeadersAudit().run(_ctx())

    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert "conexão TLS" in findings[0].title
    assert "connection refused" in findings[0].evidence


# --- continuação opt-in sobre TLS não verificado ---------------------------
async def test_sem_opt_in_a_auditoria_de_cabecalhos_para(monkeypatch):
    seen: list = []

    def boom(host, port, verify, check_hostname=True):
        raise _verify_error(62, "Hostname mismatch")

    _patch(monkeypatch, tls=boom, headers={"Server": "nginx"}, recorder=seen)
    findings = await TlsHeadersAudit().run(_ctx())

    assert len(findings) == 1
    # Nenhuma requisição HTTP foi feita a um servidor não verificado.
    assert [kind for kind, *_ in seen] == ["tls"]
    assert "insecure_tls=true" in findings[0].description


async def test_com_opt_in_a_auditoria_segue_e_fica_marcada(monkeypatch):
    seen: list = []

    def tls(host, port, verify, check_hostname):
        # Só o nome estava errado: sem exigir o nome, o certificado é legível.
        if check_hostname:
            raise _verify_error(62, "Hostname mismatch")
        return _cert(days_valid=200), "TLSv1.3"

    _patch(monkeypatch, tls=tls, headers={"Server": "nginx"}, recorder=seen)
    findings = await TlsHeadersAudit().run(_ctx(insecure_tls=True))

    # Tentou verificado, falhou, repetiu sem exigir o nome, e buscou cabeçalhos.
    assert ("tls", "example.com", 443, True, False) in seen
    # A cadeia seguiu validada, então a busca de cabeçalhos também a exige — mas
    # sem o nome, que é justamente o que falhou. Exigir os dois a mataria com o
    # mesmo erro; não exigir nenhum a enfraqueceria mais que o handshake.
    assert ("headers", "example.com", 443, True, False) in seen
    # A cadeia seguiu válida, então a validade do certificado foi mesmo conferida.
    assert any("Validade do certificado TLS OK" in f.title for f in findings)

    cert_finding = findings[0]
    assert cert_finding.severity is Severity.HIGH
    assert "não verificado" in cert_finding.description

    # Todo achado de cabeçalho carrega a marca de que o canal não foi verificado.
    header_findings = [f for f in findings if "Cabeçalho de segurança ausente" in f.title]
    assert header_findings
    assert all(f.metadata["tls_verified"] is False for f in header_findings)


async def test_opt_in_como_texto_falso_nao_desliga_a_verificacao(monkeypatch):
    """``insecure_tls=false`` vindo como string não pode virar verdadeiro."""

    def boom(host, port, verify, check_hostname=True):
        raise _verify_error(62, "Hostname mismatch")

    _patch(monkeypatch, tls=boom, headers={"Server": "nginx"})
    findings = await TlsHeadersAudit().run(_ctx(insecure_tls="false"))

    assert len(findings) == 1  # parou, como se a opção não tivesse sido passada


async def test_caminho_feliz_audita_cabecalhos_verificados(monkeypatch):
    seen: list = []
    _patch(
        monkeypatch,
        tls=lambda host, port, verify, check_hostname: (_cert(), "TLSv1.3"),
        headers={"Strict-Transport-Security": "max-age=31536000"},
        recorder=seen,
    )
    findings = await TlsHeadersAudit().run(_ctx())

    assert ("headers", "example.com", 443, True, True) in seen
    titles = [f.title for f in findings]
    assert any("Validade do certificado TLS OK" in t for t in titles)
    assert any("Protocolo TLS OK" in t for t in titles)
    # HSTS está presente, então não deve ser reportado como ausente.
    assert not any("strict-transport-security" in t for t in titles)


async def test_certificado_ilegivel_nao_vira_silencio_sobre_a_validade(monkeypatch):
    """Com CERT_NONE o stdlib devolve {}; calar seria igual a dizer "está em dia"."""

    def tls(host, port, verify, check_hostname):
        if verify:
            # Autoassinado: nem ignorar o nome salva a cadeia.
            raise _verify_error(18, "self signed certificate")
        return {}, "TLSv1.3"

    _patch(monkeypatch, tls=tls, headers={"Server": "nginx"})
    findings = await TlsHeadersAudit().run(_ctx(insecure_tls=True))

    nao_checada = [f for f in findings if "não foi verificada" in f.title]
    assert len(nao_checada) == 1
    assert nao_checada[0].severity is Severity.LOW
    assert nao_checada[0].metadata["tls_verified"] is False


async def test_todo_achado_do_canal_nao_verificado_leva_a_marca(monkeypatch):
    """Um consumidor que filtra por tls_verified não pode receber achado sem a marca."""

    def tls(host, port, verify, check_hostname):
        if verify:
            raise _verify_error(18, "self signed certificate")
        return {}, "TLSv1.3"

    _patch(monkeypatch, tls=tls, headers={"Server": "nginx/1.18.0"})
    findings = await TlsHeadersAudit().run(_ctx(insecure_tls=True))

    # O banner do servidor é o caso que mais importa: ele alimenta cve_lookup,
    # e pode ter vindo de qualquer coisa que atendeu naquele IP.
    banner = next(f for f in findings if "Banner do servidor" in f.title)
    assert banner.metadata["tls_verified"] is False

    # Fora o próprio achado do certificado, nada sai sem a marca.
    sem_marca = [
        f.title
        for f in findings
        if "verify_code" not in f.metadata and "tls_verified" not in f.metadata
    ]
    assert sem_marca == []


async def test_falha_de_rede_na_repeticao_vira_achado_de_conexao(monkeypatch):
    """Se nem o handshake sem verificação acontece, é falha de conexão mesmo."""

    def tls(host, port, verify, check_hostname):
        if verify and check_hostname:
            raise _verify_error(62, "Hostname mismatch")
        raise ConnectionResetError("connection reset by peer")

    _patch(monkeypatch, tls=tls)
    findings = await TlsHeadersAudit().run(_ctx(insecure_tls=True))

    assert len(findings) == 2
    assert findings[0].severity is Severity.HIGH  # o certificado
    assert findings[1].severity is Severity.MEDIUM  # a conexão
    assert "connection reset" in findings[1].evidence


def test_o_fake_de_rede_tem_a_mesma_assinatura_da_funcao_real():
    """Um mock mais permissivo que o original esconde erro de chamada.

    Foi o que aconteceu: ``_tls_info`` ganhou um argumento no chamador e não na
    definição, e como os testes substituem a função por um fake que aceitava os
    dois, a suíte passou inteira enquanto a execução real falhava com TypeError.
    """
    import inspect

    real = inspect.signature(mod._tls_info)
    assert list(real.parameters) == ["host", "port", "verify", "check_hostname"]

    real_headers = inspect.signature(mod._fetch_headers)
    assert list(real_headers.parameters) == ["host", "port", "verify", "check_hostname"]


async def test_cadeia_invalida_derruba_tambem_a_busca_de_cabecalhos(monkeypatch):
    """Quando nem a cadeia se sustenta, aí sim os cabeçalhos vêm sem verificação."""
    seen: list = []

    def tls(host, port, verify, check_hostname):
        if verify:
            raise _verify_error(18, "self signed certificate")
        return {}, "TLSv1.3"

    _patch(monkeypatch, tls=tls, headers={"Server": "nginx"}, recorder=seen)
    await TlsHeadersAudit().run(_ctx(insecure_tls=True))

    assert ("headers", "example.com", 443, False, False) in seen


async def test_quando_a_repeticao_falha_o_achado_nao_diz_que_seguiu(monkeypatch):
    """Dizer 'a auditoria seguiu' ao lado de 'não foi possível conectar' é mentira."""

    def tls(host, port, verify, check_hostname):
        if verify and check_hostname:
            raise _verify_error(62, "Hostname mismatch")
        raise ConnectionResetError("connection reset by peer")

    _patch(monkeypatch, tls=tls)
    findings = await TlsHeadersAudit().run(_ctx(insecure_tls=True))

    assert len(findings) == 2
    # A descrição fala da configuração da execução, nunca do que este módulo
    # conseguiu: afirmar aqui que a auditoria seguiu seria falso, e separar o
    # desfecho na chave de dedup traria de volta a contagem dupla.
    assert "seguiu" not in findings[0].description
    assert findings[1].severity is Severity.MEDIUM


async def test_porta_da_url_e_respeitada(monkeypatch):
    """Antes só o host era lido e a porta era sempre 443."""
    seen: list = []
    _patch(
        monkeypatch,
        tls=lambda host, port, verify, check_hostname: (_cert(), "TLSv1.3"),
        headers={},
        recorder=seen,
    )
    await TlsHeadersAudit().run(_ctx(target="https://example.com:8443"))

    assert ("tls", "example.com", 8443, True, True) in seen
    assert ("headers", "example.com", 8443, True, True) in seen


@pytest.mark.parametrize("bad", ["-oProxyCommand=x", "--foo", "", "  ", "a b"])
async def test_alvo_inseguro_e_recusado_sem_abrir_socket(monkeypatch, bad):
    """Era o único dos três módulos de rede sem essa guarda."""
    seen: list = []

    def nunca(host, port, verify=True, check_hostname=True):  # pragma: no cover
        seen.append(host)
        raise AssertionError("não pode abrir socket para alvo inseguro")

    monkeypatch.setattr(mod, "_tls_info", nunca)
    findings = await TlsHeadersAudit().run(_ctx(target=bad))

    assert seen == []
    assert len(findings) == 1
    assert "Recusando a varredura" in findings[0].title




async def test_faixa_de_rede_e_recusada(monkeypatch):
    seen: list = []

    def nunca(host, port, verify=True, check_hostname=True):  # pragma: no cover
        seen.append(host)
        raise AssertionError("não pode conectar a uma faixa")

    monkeypatch.setattr(mod, "_tls_info", nunca)
    findings = await TlsHeadersAudit().run(_ctx(target="10.0.0.0/24"))

    assert seen == []
    assert len(findings) == 1
    assert "faixa de rede" in findings[0].title


# --- a porta vem do alvo e das opções, igual para todos os módulos ---------
@pytest.mark.parametrize(
    "target, options, esperado",
    [
        ("alvo.com", {}, 443),
        ("alvo.com:8443", {}, 8443),
        ("https://alvo.com", {}, 443),
        ("https://alvo.com:9443", {}, 9443),
        # ``--opt port=`` vale aqui como vale nos outros: num alvo nu ou
        # https o esquema é TLS, então a porta do serviço é a porta TLS.
        ("alvo.com", {"port": 8443}, 8443),
        ("https://alvo.com", {"port": 8443}, 8443),
        # Porta escrita no alvo é explícita e vence a opção.
        ("alvo.com:9443", {"port": 8443}, 9443),
    ],
)
async def test_a_porta_e_lida_como_nos_outros_modulos(
    monkeypatch, target, options, esperado
):
    """Três regras especiais aqui já fizeram este módulo divergir dos outros."""
    seen: list = []
    _patch(
        monkeypatch,
        tls=lambda host, port, verify, check_hostname: (_cert(), "TLSv1.3"),
        headers={},
        recorder=seen,
    )
    await TlsHeadersAudit().run(RunContext(target=target, options=options))

    assert ("tls", "alvo.com", esperado, True, True) in seen


@pytest.mark.parametrize("target", ["http://alvo.com", "http://alvo.com:8080"])
async def test_alvo_em_texto_claro_e_dito_e_nao_adivinhado(monkeypatch, target):
    """Cair para 443 trocava em silêncio a porta escrita pelo operador."""
    seen: list = []

    def nunca(host, port, verify=True, check_hostname=True):  # pragma: no cover
        seen.append(port)
        raise AssertionError("não deve haver handshake num alvo http")

    monkeypatch.setattr(mod, "_tls_info", nunca)
    findings = await TlsHeadersAudit().run(_ctx(target=target))

    assert seen == []
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert "texto claro" in findings[0].title


async def test_a_porta_concorda_com_os_outros_modulos(monkeypatch):
    """O defeito que a leitura única existe para eliminar."""
    from thursec.core.target import parse_endpoint

    seen: list = []
    _patch(
        monkeypatch,
        tls=lambda host, port, verify, check_hostname: (_cert(), "TLSv1.3"),
        headers={},
        recorder=seen,
    )
    options = {"port": 8443}
    await TlsHeadersAudit().run(RunContext(target="alvo.com", options=options))

    _, _, porta_dos_outros = parse_endpoint("alvo.com", options)
    assert ("tls", "alvo.com", porta_dos_outros, True, True) in seen


@pytest.mark.parametrize("target", ["ws://alvo.com", "ftp://alvo.com", "gopher://alvo.com"])
async def test_qualquer_esquema_sem_tls_e_dito_e_nao_tentado(monkeypatch, target):
    """Testar só `== "http"` deixava ws:// cair no handshake contra a porta 80."""
    seen: list = []

    def nunca(host, port, verify=True, check_hostname=True):  # pragma: no cover
        seen.append(port)
        raise AssertionError("não deve haver handshake num alvo sem TLS")

    monkeypatch.setattr(mod, "_tls_info", nunca)
    findings = await TlsHeadersAudit().run(_ctx(target=target))

    assert seen == []
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
