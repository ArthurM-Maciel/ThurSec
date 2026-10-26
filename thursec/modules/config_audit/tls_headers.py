"""TLS + HTTP security-header audit — pure stdlib, no external tools.

A good first module: genuinely useful for defending your own sites, works out
of the box, and because it talks to the target it exercises the scope gate.
It checks:

  * certificate verification (hostname mismatch, expiry, broken chain)
  * certificate expiry (days remaining)
  * negotiated TLS protocol version (flags TLS < 1.2)
  * presence of key HTTP security headers (HSTS, CSP, X-Content-Type-Options, …)
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone

from ... import __version__
from ...core.context import RunContext, coerce_bool
from ...core.finding import Finding, Severity
from ...core.i18n import L, Lf
from ...core.module import Category, Intensity, Module
from ...core.target import (
    TargetError,
    is_network_target,
    parse_endpoint,
    validate_target,
)
from ...core.tls import cert_verification_finding, mark_unverified, tls_context

_USER_AGENT = f"ThurSec/{__version__}"

# header -> (severity if missing, recommendation PT, recommendation EN)
_SECURITY_HEADERS: dict[str, tuple[Severity, str, str]] = {
    "strict-transport-security": (
        Severity.MEDIUM,
        "Adicione HSTS para forçar HTTPS e impedir downgrade de protocolo.",
        "Add HSTS to force HTTPS and prevent protocol downgrade.",
    ),
    "content-security-policy": (
        Severity.MEDIUM,
        "Adicione um Content-Security-Policy para mitigar XSS e injeção de dados.",
        "Add a Content-Security-Policy to mitigate XSS and data injection.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "Defina 'X-Content-Type-Options: nosniff' para impedir MIME sniffing.",
        "Set 'X-Content-Type-Options: nosniff' to stop MIME sniffing.",
    ),
    "x-frame-options": (
        Severity.LOW,
        "Defina X-Frame-Options (ou CSP frame-ancestors) para prevenir clickjacking.",
        "Set X-Frame-Options (or CSP frame-ancestors) to prevent clickjacking.",
    ),
    "referrer-policy": (
        Severity.INFO,
        "Defina um Referrer-Policy para limitar o vazamento do referrer.",
        "Set a Referrer-Policy to limit referrer leakage.",
    ),
}


class TlsHeadersAudit(Module):
    id = "config_audit.tls_headers"
    category = Category.CONFIG_AUDIT
    intensity = Intensity.ACTIVE

    @property
    def name(self) -> str:
        return L("Cabeçalhos de segurança TLS e HTTP", "TLS & HTTP security headers")

    @property
    def description(self) -> str:
        return L(
            "Verifica a validade do certificado, a versão do TLS e os cabeçalhos "
            "de segurança HTTP.",
            "Check certificate validity, TLS version, and HTTP security headers.",
        )

    async def run(self, ctx: RunContext) -> list[Finding]:
        # Mesma guarda que cookies e http_methods: rejeitar o alvo implausível
        # *antes* de abrir socket. Sem ela, ``thursec run ./relatorio.html``
        # entregava a string literal ao socket e virava um "não foi possível
        # estabelecer conexão TLS" — que culpa o alvo em vez da linha de comando.
        try:
            validate_target(ctx.target)
        except TargetError as e:
            return [
                ctx.finding(
                    self.id,
                    L(
                        "Recusando a varredura: alvo inseguro/inválido",
                        "Refusing to scan: unsafe/invalid target",
                    ),
                    Severity.LOW,
                    description=L(
                        "O alvo foi rejeitado antes de qualquer conexão porque "
                        "não é um host/URL válido e poderia ser interpretado "
                        "como uma opção de linha de comando.",
                        "The target was rejected before any connection because "
                        "it is not a valid host/URL and could be interpreted as "
                        "a command-line option.",
                    ),
                    evidence=str(e),
                    recommendation=L(
                        "Forneça um hostname, IP, CIDR ou URL simples.",
                        "Provide a plain hostname, IP, CIDR, or URL.",
                    ),
                )
            ]

        if is_network_target(ctx.target):
            # Uma faixa não é um host: auditar o endereço de rede e rotular o
            # achado com o CIDR daria um relatório sobre 254 hosts tirado de um.
            return [
                ctx.finding(
                    self.id,
                    L(
                        "Alvo é uma faixa de rede, não um host",
                        "Target is a network range, not a host",
                    ),
                    Severity.INFO,
                    description=Lf(
                        "{t} é uma faixa; este módulo audita um host por vez.",
                        "{t} is a range; this module audits one host at a time.",
                        t=ctx.target,
                    ),
                    recommendation=L(
                        "Rode o recon.nmap na faixa para descobrir os hosts, e "
                        "este módulo contra cada host de interesse.",
                        "Run recon.nmap over the range to discover hosts, then "
                        "this module against each host of interest.",
                    ),
                )
            ]

        # Mesma leitura de alvo que cookies e http_methods, para que uma porta
        # em ``https://alvo:8443`` valha aqui também — senão os três módulos
        # falam com portas diferentes do mesmo alvo.
        # Exatamente a mesma leitura dos outros módulos de rede, opções
        # incluídas. Tentei três regras especiais aqui — ignorar ``--opt
        # port=``, aceitar só a forma com escopo, cair para 443 num alvo
        # ``http`` — e cada uma fez este módulo varrer uma porta diferente da
        # dos outros no mesmo alvo, que é o defeito que a leitura única existe
        # para eliminar. O esquema é que diz se a porta é TLS, e ele vem do
        # alvo: num alvo nu ou ``https``, a porta é a porta TLS para todos.
        scheme, host, port = parse_endpoint(ctx.target, ctx.options)

        if scheme != "https":
            # Qualquer esquema que não seja ``https`` — ``http``, mas também
            # ``ws``, ``ftp``, o que o operador escrever — nomeia um serviço
            # em texto claro, e ``parse_endpoint`` dá a todos a porta 80.
            # Testar só ``== "http"`` deixava ``ws://alvo`` cair no handshake. Adivinhar a 443
            # trocaria em silêncio a porta que o operador escreveu e faria
            # este módulo relatar sobre um serviço que ninguém pediu; tentar
            # o handshake na porta em claro daria um erro de conexão falso.
            return [
                ctx.finding(
                    self.id,
                    L(
                        "Alvo em texto claro: nada de TLS para auditar",
                        "Cleartext target: no TLS to audit",
                    ),
                    Severity.INFO,
                    description=Lf(
                        "{t} não nomeia um serviço TLS ({s}://), e este "
                        "módulo audita TLS.",
                        "{t} does not name a TLS service ({s}://), and this "
                        "module audits TLS.",
                        t=ctx.target, s=scheme,
                    ),
                    recommendation=L(
                        "Aponte o alvo para o serviço TLS, ex.: "
                        "https://alvo ou https://alvo:9443.",
                        "Point the target at the TLS service, e.g. "
                        "https://alvo or https://alvo:9443.",
                    ),
                )
            ]

        findings: list[Finding] = []

        # Só desliga a verificação do certificado quem pedir: a auditoria segue,
        # mas sobre um canal que pode não ser o servidor legítimo.
        insecure = coerce_bool(ctx.options.get("insecure_tls"), False)

        # TLS layer (cert + protocol) runs in a thread: stdlib ssl is blocking.
        verified = True
        # Independente de `verified`: mesmo sem exigir o nome, a cadeia e as
        # datas podem seguir validadas, e a busca de cabeçalhos não deve se
        # enfraquecer mais do que o handshake que a precedeu.
        chain_checked = True
        try:
            cert, proto = await asyncio.to_thread(_tls_info, host, port, True)
        except ssl.SSLCertVerificationError as e:
            if not insecure:
                # Sem o opt-in, a auditoria de cabeçalhos para aqui: ela exigiria
                # falar com um servidor que não provou ser quem diz ser.
                return [
                    cert_verification_finding(
                        ctx, self.id, e, host, port, insecure=insecure
                    )
                ]
            verified = False
            try:
                cert, proto, chain_checked = await self._tls_info_unverified(host, port)
            except Exception as retry_error:
                # A repetição também falhou. O achado do certificado descreve
                # só o defeito do alvo; que esta auditoria não saiu do lugar é
                # o que diz o achado logo abaixo.
                return [
                    cert_verification_finding(
                        ctx, self.id, e, host, port, insecure=insecure
                    ),
                    self._tls_connection_finding(ctx, retry_error, host, port),
                ]
            findings.append(
                cert_verification_finding(
                    ctx, self.id, e, host, port, insecure=insecure
                )
            )
        except Exception as e:
            return [self._tls_connection_finding(ctx, e, host, port)]

        findings.extend(self._check_cert(ctx, cert, host, port, verified))
        findings.extend(self._check_protocol(ctx, proto, verified))
        findings.extend(await self._check_headers(ctx, host, port, verified, chain_checked))
        # Inclusive o próprio achado do certificado: ele e os homônimos dos
        # outros módulos compartilham dedup_key, e a visão colapsada guarda só
        # um deles — se a marca dependesse de qual módulo rodou primeiro, quem
        # filtra por `tls_verified is False` veria resultado diferente conforme
        # a seleção de módulos da execução.
        return mark_unverified(findings, verified)

    async def _tls_info_unverified(
        self, host: str, port: int
    ) -> tuple[dict, str | None, bool]:
        """Refaz o handshake sem verificar, preservando o máximo do certificado.

        Primeiro desliga só a checagem de nome: se o defeito era o domínio não
        coberto, cadeia e datas seguem válidas e ``getpeercert()`` devolve o
        certificado inteiro — então a checagem de validade sobrevive ao
        ``insecure_tls``. Só quando isso também falha é que se cai para
        ``CERT_NONE``, onde o stdlib devolve um dicionário vazio.

        O terceiro valor diz se a cadeia continuou sendo validada, para que o
        resto da auditoria não desça mais do que o necessário.
        """
        try:
            cert, proto = await asyncio.to_thread(_tls_info, host, port, True, False)
            return cert, proto, True
        except ssl.SSLError:
            cert, proto = await asyncio.to_thread(_tls_info, host, port, False, False)
            return cert, proto, False

    # --- falhas de TLS -----------------------------------------------------
    def _tls_connection_finding(
        self, ctx: RunContext, error: BaseException, host: str, port: int
    ) -> Finding:
        """Não houve handshake: porta fechada, timeout, host errado."""
        return ctx.finding(
            self.id,
            L("Não foi possível estabelecer conexão TLS", "Could not establish TLS connection"),
            Severity.MEDIUM,
            description=Lf(
                "Falha ao completar o handshake TLS com {host}:{port}.",
                "Failed to complete a TLS handshake with {host}:{port}.",
                host=host, port=port,
            ),
            evidence=f"{type(error).__name__}: {error}",
            recommendation=L("Verifique se o host oferece TLS nesta porta.", "Verify the host serves TLS on this port."),
        )

    # --- checks ------------------------------------------------------------
    def _check_cert(
        self, ctx: RunContext, cert: dict, host: str, port: int, verified: bool = True
    ) -> list[Finding]:
        not_after = cert.get("notAfter")
        if not not_after:
            # Com CERT_NONE o stdlib devolve getpeercert() vazio, então a
            # validade simplesmente não foi checada. Calar aqui era
            # indistinguível de "o certificado está em dia" — justamente no
            # caminho em que o certificado já é sabidamente defeituoso e pode
            # estar vencido por cima disso.
            return [
                ctx.finding(
                    self.id,
                    L(
                        "Validade do certificado TLS não foi verificada",
                        "TLS certificate validity was not checked",
                    ),
                    Severity.LOW,
                    description=Lf(
                        "O certificado de {host}:{port} não pôde ser lido, então "
                        "sua data de expiração não foi conferida.",
                        "The certificate for {host}:{port} could not be read, so "
                        "its expiry date was not checked.",
                        host=host, port=port,
                    ),
                    recommendation=L(
                        "Confira a validade manualmente, ex.: openssl s_client "
                        "-connect host:443 | openssl x509 -noout -dates",
                        "Check the expiry by hand, e.g.: openssl s_client "
                        "-connect host:443 | openssl x509 -noout -dates",
                    ),
                    metadata={"tls_verified": verified},
                )
            ]
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days = (expires - datetime.now(timezone.utc)).days
        if days < 0:
            sev = Severity.CRITICAL
            title = L("Certificado TLS expirado", "TLS certificate is expired")
        elif days <= 14:
            sev = Severity.HIGH
            title = Lf("Certificado TLS expira em {days} dia(s)", "TLS certificate expires in {days} day(s)", days=days)
        elif days <= 30:
            sev = Severity.MEDIUM
            title = Lf("Certificado TLS expira em {days} dia(s)", "TLS certificate expires in {days} day(s)", days=days)
        else:
            return [
                ctx.finding(
                    self.id,
                    L("Validade do certificado TLS OK", "TLS certificate validity OK"),
                    Severity.INFO,
                    description=Lf("Certificado válido por mais {days} dia(s).", "Certificate valid for {days} more day(s).", days=days),
                    evidence=f"notAfter={not_after}",
                    metadata={"tls_verified": verified},
                )
            ]
        return [
            ctx.finding(
                self.id, title, sev,
                description=Lf(
                    "O certificado de {host}:{port} precisa ser renovado.",
                    "Certificate for {host}:{port} needs renewal.",
                    host=host, port=port,
                ),
                evidence=f"notAfter={not_after}",
                recommendation=L("Renove/rotacione o certificado antes que ele expire.", "Renew/rotate the certificate before it lapses."),
                metadata={"tls_verified": verified},
            )
        ]

    def _check_protocol(
        self, ctx: RunContext, proto: str | None, verified: bool = True
    ) -> list[Finding]:
        if not proto:
            return []
        weak = proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2")
        if weak:
            return [
                ctx.finding(
                    self.id,
                    Lf("Protocolo TLS fraco negociado: {proto}", "Weak TLS protocol negotiated: {proto}", proto=proto),
                    Severity.HIGH,
                    description=L("O servidor negociou uma versão TLS/SSL desatualizada.", "The server negotiated an outdated TLS/SSL version."),
                    evidence=f"negotiated={proto}",
                    recommendation=L("Desative TLS < 1.2; prefira TLS 1.3.", "Disable TLS < 1.2; prefer TLS 1.3."),
                    references=["https://datatracker.ietf.org/doc/html/rfc8996"],
                    metadata={"tls_verified": verified},
                )
            ]
        return [
            ctx.finding(
                self.id, Lf("Protocolo TLS OK ({proto})", "TLS protocol OK ({proto})", proto=proto), Severity.INFO,
                evidence=f"negotiated={proto}",
                metadata={"tls_verified": verified},
            )
        ]

    async def _check_headers(
        self,
        ctx: RunContext,
        host: str,
        port: int,
        verified: bool = True,
        chain_checked: bool = True,
    ) -> list[Finding]:
        # ``verified`` é o que se *diz* ao leitor; ``chain_checked`` é o quanto
        # se exige do servidor. Separar os dois evita descer para CERT_NONE numa
        # conexão cuja cadeia continua válida.
        try:
            # ``chain_checked`` vira o *verify* e ``verified`` vira a exigência do
            # nome: trocar os dois religava a checagem de hostname que acabara
            # de falhar, e a busca de cabeçalhos morria com o mesmo erro.
            headers = await asyncio.to_thread(
                _fetch_headers, host, port, verify=chain_checked, check_hostname=verified
            )
        except Exception as e:
            return [
                ctx.finding(
                    self.id, L("Não foi possível obter os cabeçalhos HTTP", "Could not fetch HTTP headers"), Severity.LOW,
                    evidence=f"{type(e).__name__}: {e}",
                    metadata={"tls_verified": verified},
                )
            ]
        present = {k.lower() for k in headers}
        findings = []
        for header, (sev, rec_pt, rec_en) in _SECURITY_HEADERS.items():
            if header not in present:
                findings.append(
                    ctx.finding(
                        self.id,
                        Lf("Cabeçalho de segurança ausente: {header}", "Missing security header: {header}", header=header),
                        sev,
                        description=Lf(
                            "A resposta de {host} não define '{header}'.",
                            "Response from {host} does not set '{header}'.",
                            host=host, header=header,
                        ),
                        recommendation=L(rec_pt, rec_en),
                        metadata={"tls_verified": verified},
                    )
                )
        server = headers.get("Server")
        if server:
            findings.append(
                ctx.finding(
                    self.id, L("Banner do servidor divulgado", "Server banner disclosed"), Severity.INFO,
                    evidence=f"Server: {server}",
                    metadata={"tls_verified": verified},
                    recommendation=L(
                        "Considere suprimir o cabeçalho Server para reduzir o fingerprinting.",
                        "Consider suppressing the Server header to reduce fingerprinting.",
                    ),
                )
            )
        return findings


# --- low-level helpers -----------------------------------------------------
def _tls_info(
    host: str, port: int, verify: bool = True, check_hostname: bool = True
) -> tuple[dict, str | None]:
    ctx = tls_context(verify, check_hostname)
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert() or {}, ssock.version()


def _fetch_headers(
    host: str, port: int, verify: bool = True, check_hostname: bool = True
) -> dict[str, str]:
    import http.client

    conn = http.client.HTTPSConnection(
        host, port, timeout=10, context=tls_context(verify, check_hostname)
    )
    try:
        conn.request("HEAD", "/", headers={"User-Agent": _USER_AGENT})
        resp = conn.getresponse()
        return {k: v for k, v in resp.getheaders()}
    finally:
        conn.close()
