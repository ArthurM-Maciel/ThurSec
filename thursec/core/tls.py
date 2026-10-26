"""Camada TLS compartilhada: contexto, e a leitura de uma falha de certificado.

Cada módulo montava seu próprio ``HTTPSConnection`` e engolia qualquer erro de
TLS no mesmo ``except`` genérico. O resultado era incoerente dentro de uma única
execução contra um único alvo: o ``tls_headers`` seguia a auditoria e o
``cookies`` parava, e um certificado que não cobre o domínio era descrito como
"verifique se o host oferece HTTP(S) nesta porta" — mandando o operador olhar
para a porta quando o defeito estava no certificado. A decisão mora aqui, uma
vez só, e os três módulos de rede a usam.
"""

from __future__ import annotations

import ssl

from .context import RunContext
from .finding import Finding, Severity
from .i18n import L, Lf


def tls_context(verify: bool = True, check_hostname: bool = True) -> ssl.SSLContext:
    """Contexto TLS padrão; com ``verify=False``, aceita qualquer certificado.

    Desligar a verificação é opt-in explícito do operador (``--opt
    insecure_tls=true``): serve para auditar um host cujo certificado é
    justamente o defeito, e quem usa precisa saber que o servidor do outro lado
    deixou de provar quem é.

    ``check_hostname=False`` com ``verify=True`` é o meio-termo útil: a cadeia e
    as datas continuam sendo validadas, só o nome deixa de ser exigido. Num
    certificado que simplesmente não cobre o domínio, é o que permite continuar
    lendo o certificado em vez de perdê-lo — ``CERT_NONE`` faz o stdlib devolver
    um ``getpeercert()`` vazio.
    """
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif not check_hostname:
        ctx.check_hostname = False
    return ctx


# Falhas de verificação do certificado, por código do OpenSSL.
#
# Um certificado que o cliente recusa é um defeito do alvo, não uma falha de
# conectividade: o handshake aconteceu, o servidor respondeu, e todo navegador
# que visitar o site vai parar numa tela de aviso. Tratar isso como "não foi
# possível conectar" (MÉDIO) escondia o achado mais visível que existe atrás
# da mesma frase usada para "essa porta não fala TLS".
#
# código -> (severidade, título PT, título EN, recomendação PT, recomendação EN)
_VERIFY_FAILURES: dict[int, tuple[Severity, str, str, str, str]] = {
    10: (
        Severity.CRITICAL,
        "Certificado TLS expirado",
        "TLS certificate is expired",
        "Renove o certificado; enquanto isso, todo visitante vê um aviso de segurança.",
        "Renew the certificate; until then every visitor sees a security warning.",
    ),
    23: (
        Severity.CRITICAL,
        "Certificado TLS revogado",
        "TLS certificate is revoked",
        "Emita um certificado novo imediatamente: um certificado revogado costuma "
        "indicar chave privada comprometida.",
        "Issue a new certificate immediately: a revoked certificate usually means "
        "the private key was compromised.",
    ),
    9: (
        Severity.HIGH,
        "Certificado TLS ainda não é válido",
        "TLS certificate is not yet valid",
        "Confira o relógio do servidor e a data de início do certificado.",
        "Check the server clock and the certificate's start date.",
    ),
    62: (
        Severity.HIGH,
        "Certificado TLS não cobre este domínio",
        "TLS certificate does not cover this domain",
        "Emita um certificado que inclua este nome no SAN, ou corrija o apontamento "
        "de DNS/host virtual para o destino que de fato tem o certificado.",
        "Issue a certificate whose SAN includes this name, or fix the DNS/virtual-host "
        "mapping to point at the destination that actually holds the certificate.",
    ),
    18: (
        Severity.HIGH,
        "Certificado TLS autoassinado",
        "TLS certificate is self-signed",
        "Use um certificado emitido por uma CA pública (ex.: Let's Encrypt) em "
        "qualquer host que receba tráfego de terceiros.",
        "Use a certificate from a public CA (e.g. Let's Encrypt) on any host that "
        "receives third-party traffic.",
    ),
    19: (
        Severity.HIGH,
        "Cadeia do certificado TLS termina em certificado autoassinado",
        "TLS certificate chain ends in a self-signed certificate",
        "Sirva a cadeia completa emitida pela CA pública.",
        "Serve the full chain issued by the public CA.",
    ),
    20: (
        Severity.HIGH,
        "Cadeia do certificado TLS incompleta",
        "Incomplete TLS certificate chain",
        "Inclua os certificados intermediários na configuração do servidor: sem "
        "eles o certificado funciona em alguns clientes e falha em outros.",
        "Include the intermediate certificates in the server configuration: without "
        "them the certificate works in some clients and fails in others.",
    ),
    21: (
        Severity.HIGH,
        "Cadeia do certificado TLS incompleta",
        "Incomplete TLS certificate chain",
        "Inclua os certificados intermediários na configuração do servidor: sem "
        "eles o certificado funciona em alguns clientes e falha em outros.",
        "Include the intermediate certificates in the server configuration: without "
        "them the certificate works in some clients and fails in others.",
    ),
    7: (
        Severity.HIGH,
        "Assinatura do certificado TLS inválida",
        "Invalid TLS certificate signature",
        "O certificado servido não confere com a chave da CA que diz tê-lo emitido; "
        "reemita-o.",
        "The served certificate does not match the key of the CA that claims to have "
        "issued it; reissue it.",
    ),
}

# Qualquer outro código de verificação ainda é um certificado que o cliente
# recusa — descer para MÉDIO por não estar na tabela seria subnotificar.
_VERIFY_FALLBACK: tuple[Severity, str, str, str, str] = (
    Severity.HIGH,
    "Certificado TLS não passa na verificação",
    "TLS certificate fails verification",
    "Clientes que verificam o certificado vão recusar a conexão; corrija o "
    "certificado ou a cadeia servida.",
    "Clients that verify the certificate will refuse the connection; fix the "
    "certificate or the served chain.",
)


def cert_verification_finding(
    ctx: RunContext,
    module_id: str,
    error: ssl.SSLCertVerificationError,
    host: str,
    port: int,
    *,
    insecure: bool = False,
) -> Finding:
    """Traduzir uma recusa de certificado no achado específico que ela é.

    A frase final descreve a *configuração da execução*, não o que aconteceu
    com este módulo em particular. Essa distinção custou duas idas e voltas:
    descrever o desfecho por módulo fazia o relatório afirmar uma continuação
    que não houve para quem sobreviveu ao colapso, e separar os desfechos na
    chave trazia de volta a contagem dupla do mesmo certificado. O que cada
    módulo conseguiu ou não fazer já é dito pelo achado dele ao lado; aqui vai
    só o defeito do alvo, igual para todos, e por isso colapsável.
    """
    code = getattr(error, "verify_code", None)
    sev, title_pt, title_en, rec_pt, rec_en = _VERIFY_FAILURES.get(code, _VERIFY_FALLBACK)
    detail = getattr(error, "verify_message", None) or str(error)

    if insecure:
        tail_pt = (
            " Com insecure_tls, o que for obtido sobre o canal não verificado "
            "vem marcado com tls_verified: false."
        )
        tail_en = (
            " With insecure_tls, anything obtained over the unverified channel "
            "is marked tls_verified: false."
        )
    else:
        tail_pt = (
            " A auditoria para aqui; para seguir mesmo assim, use "
            "--opt insecure_tls=true."
        )
        tail_en = (
            " The audit stops here; to continue anyway, use "
            "--opt insecure_tls=true."
        )

    return ctx.finding(
        module_id,
        L(title_pt, title_en),
        sev,
        description=Lf(
            "O certificado servido por {host}:{port} foi recusado na verificação: {detail}." + tail_pt,
            "The certificate served by {host}:{port} failed verification: {detail}." + tail_en,
            host=host, port=port, detail=detail,
        ),
        evidence=f"{type(error).__name__}: {error}",
        recommendation=L(rec_pt, rec_en),
        metadata={
            "verify_code": code,
            "verify_message": detail,
            # O certificado é defeito do alvo, não de quem o encontrou: os três
            # módulos de rede batem nele na mesma execução, e o resumo não deve
            # contar o mesmo problema três vezes.
            #
            # ``insecure`` entra na chave porque a frase fala dele, e ele pode
            # variar entre módulos — ``--opt config_audit.cookies.insecure_tls``
            # vale para um só. Sem isto, o colapso podia guardar o achado do
            # módulo que parou e negar a continuação que de fato houve no
            # outro, junto com a marca de canal não verificado. Numa execução
            # com a bandeira uniforme, que é o caso normal, a chave é a mesma
            # para todos e o colapso acontece como antes.
            "dedup_key": f"cert-verify:{host}:{port}:{code}:{'i' if insecure else 'v'}",
        },
    )


def mark_unverified(findings: list[Finding], verified: bool) -> list[Finding]:
    """Carimbar ``tls_verified`` em tudo que veio de um canal não verificado.

    Um consumidor que filtra por ``tls_verified is False`` — a skill, um
    relatório, o próximo módulo — precisa que *todo* achado traga a marca, não
    só os de cabeçalho. O banner do servidor é o caso que mais importa: ele
    alimenta o ``vuln.cve_lookup`` por produto e versão, e pode ter vindo de
    qualquer coisa que atendeu naquele IP.
    """
    if verified:
        return findings
    for finding in findings:
        finding.metadata.setdefault("tls_verified", False)
    return findings
