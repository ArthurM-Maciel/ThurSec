"""HTTP methods & information-exposure audit — pure stdlib, no external tools.

This module asks the server, via a single ``OPTIONS /`` request, which HTTP
methods it *declares* it supports (the ``Allow`` header) and inspects a handful
of response headers that leak implementation details (``Server``,
``X-Powered-By``, ``X-AspNet-Version``). It is deliberately **read-only**: it
never sends a state-changing verb (no real ``PUT`` / ``DELETE`` / ``POST`` /
``TRACE``). Detection is based solely on what the server advertises in ``Allow``
and on the headers it returns — so running it cannot alter the target.

This module is ACTIVE (it sends one request to the target), so the engine's
scope gate applies before it ever runs. As a second line of defense the target
is routed through :func:`validate_target` first: a value shaped like a flag,
containing whitespace, or that is otherwise not a plausible host/URL is rejected
*before* any socket is opened (argument-injection / bad-target guard), mirroring
the nmap and nuclei modules.
"""

from __future__ import annotations

import asyncio
import ssl

from ... import __version__
from ...core.context import RunContext, coerce_bool, coerce_timeout
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

# Methods that, when advertised in Allow, warrant a finding. Mapped to
# (severity, recommendation). TRACE/TRACK enable Cross-Site Tracing; the
# write/tunnel verbs widen the attack surface and are rarely meant to be public.
# The recommendation is wrapped in L() so it follows the active language.
_DANGEROUS_METHODS: dict[str, tuple[Severity, str]] = {
    "TRACE": (
        Severity.MEDIUM,
        L(
            "Desative o método TRACE; ele habilita Cross-Site Tracing (XST) e "
            "pode ecoar de volta cabeçalhos sensíveis.",
            "Disable the TRACE method; it enables Cross-Site Tracing (XST) and can "
            "echo back sensitive headers.",
        ),
    ),
    "TRACK": (
        Severity.MEDIUM,
        L(
            "Desative o método TRACK (equivalente ao TRACE no IIS); ele habilita "
            "Cross-Site Tracing (XST).",
            "Disable the TRACK method (IIS equivalent of TRACE); it enables "
            "Cross-Site Tracing (XST).",
        ),
    ),
    "CONNECT": (
        Severity.HIGH,
        L(
            "Desative o método CONNECT a menos que seja um proxy intencional; "
            "ele pode permitir que o servidor seja abusado como túnel aberto.",
            "Disable the CONNECT method unless this is an intentional proxy; it can "
            "let the server be abused as an open tunnel.",
        ),
    ),
    "PUT": (
        Severity.HIGH,
        L(
            "Desative o método PUT a menos que uploads sejam intencionais; ele "
            "pode permitir upload arbitrário de arquivos / adulteração de "
            "conteúdo.",
            "Disable the PUT method unless uploads are intended; it can allow "
            "arbitrary file upload / content tampering.",
        ),
    ),
    "DELETE": (
        Severity.MEDIUM,
        L(
            "Desative o método DELETE a menos que seja intencional; ele pode "
            "permitir a remoção remota de recursos.",
            "Disable the DELETE method unless intended; it can allow remote removal "
            "of resources.",
        ),
    ),
    "PATCH": (
        Severity.MEDIUM,
        L(
            "Restrinja o método PATCH a menos que atualizações parciais sejam "
            "intencionais.",
            "Restrict the PATCH method unless partial updates are intended.",
        ),
    ),
}

# Response headers that disclose implementation details -> (severity, reason).
# The reason is wrapped in L() so it follows the active language.
_INFO_LEAK_HEADERS: dict[str, tuple[Severity, str]] = {
    "server": (
        Severity.LOW,
        L(
            "Suprima ou torne genérico o cabeçalho Server para reduzir o "
            "fingerprinting.",
            "Suppress or genericize the Server header to reduce fingerprinting.",
        ),
    ),
    "x-powered-by": (
        Severity.LOW,
        L(
            "Remova o cabeçalho X-Powered-By; ele revela a tecnologia de backend.",
            "Remove the X-Powered-By header; it discloses the backend technology.",
        ),
    ),
    "x-aspnet-version": (
        Severity.LOW,
        L(
            "Remova o cabeçalho X-AspNet-Version; ele revela a versão do "
            "framework.",
            "Remove the X-AspNet-Version header; it discloses the framework version.",
        ),
    ),
    "x-aspnetmvc-version": (
        Severity.LOW,
        L(
            "Remova o cabeçalho X-AspNetMvc-Version; ele revela a versão do "
            "framework.",
            "Remove the X-AspNetMvc-Version header; it discloses the framework "
            "version.",
        ),
    ),
}

_DEFAULT_TIMEOUT = 10.0


class HttpMethods(Module):
    id = "vuln.http_methods"
    name = L("Métodos HTTP & exposição de informação", "HTTP methods & info exposure")
    category = Category.VULN
    intensity = Intensity.ACTIVE
    description = L(
        "Verifica quais métodos HTTP o servidor anuncia via OPTIONS (sinalizando "
        "verbos perigosos como TRACE/PUT/DELETE) e reporta cabeçalhos de "
        "exposição de informação. Somente leitura: nunca envia requisições que "
        "alteram estado.",
        "Check which HTTP methods the server advertises via OPTIONS (flagging "
        "dangerous verbs like TRACE/PUT/DELETE) and report information-exposure "
        "headers. Read-only: never sends state-changing requests.",
    )

    async def run(self, ctx: RunContext) -> list[Finding]:
        # Defense against argument injection / invalid targets: reject anything
        # that isn't a plausible host/URL *before* opening a socket. We only use
        # validate_target as a gate; the actual scheme/host/port come from the
        # original target so a full URL's path and scheme stay meaningful.
        try:
            validate_target(ctx.target)
        except TargetError as e:
            return [
                ctx.finding(
                    self.id,
                    L(
                        "Recusando varredura: alvo inseguro/inválido",
                        "Refusing to scan: unsafe/invalid target",
                    ),
                    Severity.LOW,
                    description=L(
                        "O alvo foi rejeitado antes de qualquer requisição porque "
                        "não é um host/URL válido e poderia ser interpretado como "
                        "uma opção de linha de comando.",
                        "The target was rejected before any request because it is "
                        "not a valid host/URL and could be interpreted as a "
                        "command-line option.",
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

        scheme, host, port = parse_endpoint(ctx.target, ctx.options)
        timeout = coerce_timeout(ctx.options.get("timeout"), _DEFAULT_TIMEOUT)
        insecure = coerce_bool(ctx.options.get("insecure_tls"), False)

        # A verificação só é dispensada na *repetição*, depois que o certificado
        # comprovadamente falhou: a bandeira não deve rebaixar uma conexão que
        # teria sido verificada sem problema.
        prefix: list[Finding] = []
        verified = True
        try:
            status, headers = await asyncio.to_thread(
                self._options, host, port, scheme, timeout, True
            )
        except ssl.SSLCertVerificationError as e:
            # Um certificado recusado é defeito do alvo, não "porta errada":
            # cair no except genérico mandava o operador conferir se o host
            # serve HTTP(S) nessa porta, quando o host serve e o problema é
            # o certificado. Mesma leitura que o tls_headers faz.
            if not insecure:
                return [
                    cert_verification_finding(
                        ctx, self.id, e, host, port, insecure=insecure
                    )
                ]
            verified = False
            try:
                # Mesmo degrau que o tls_headers: primeiro dispensa só o nome,
                # mantendo cadeia e datas validadas. Cair direto para CERT_NONE
                # faria a mesma bandeira valer dois níveis de confiança na
                # mesma execução — e aceitaria o certificado de qualquer um.
                try:
                    status, headers = await asyncio.to_thread(
                        self._options, host, port, scheme, timeout, True, False
                    )
                except ssl.SSLError:
                    status, headers = await asyncio.to_thread(
                        self._options, host, port, scheme, timeout, False, False
                    )
            except Exception as retry_error:
                # A repetição também falhou. O achado do certificado descreve
                # só o defeito do alvo; que esta auditoria não saiu do lugar é
                # o que diz o achado logo abaixo.
                return [
                    cert_verification_finding(
                        ctx, self.id, e, host, port, insecure=insecure
                    ),
                    self._request_failure(ctx, retry_error, host, port, scheme),
                ]
            prefix.append(
                cert_verification_finding(
                    ctx, self.id, e, host, port, insecure=insecure
                )
            )
        except Exception as e:
            # Connection refused, timeout, DNS failure, ... — surface as a
            # handled finding; never let it crash the run.
            return [self._request_failure(ctx, e, host, port, scheme)]

        findings: list[Finding] = list(prefix)
        findings.extend(self._check_methods(ctx, headers, status))
        findings.extend(self._check_info_leak(ctx, headers))
        return mark_unverified(findings, verified)

    def _request_failure(
        self, ctx: RunContext, error: BaseException, host: str, port: int, scheme: str
    ) -> Finding:
        return ctx.finding(
            self.id,
            L(
                "Não foi possível completar a requisição OPTIONS",
                "Could not complete OPTIONS request",
            ),
            Severity.LOW,
            description=L(
                f"Falha ao enviar OPTIONS / para {host}:{port} via {scheme}.",
                f"Failed to send OPTIONS / to {host}:{port} over {scheme}.",
            ),
            evidence=f"{type(error).__name__}: {error}",
            recommendation=L(
                "Verifique se o host serve HTTP(S) nesta porta.",
                "Verify the host serves HTTP(S) on this port.",
            ),
        )

    # --- checks ------------------------------------------------------------
    def _check_methods(
        self, ctx: RunContext, headers: dict[str, str], status: int
    ) -> list[Finding]:
        allow = _get_header(headers, "allow")
        if not allow:
            return [
                ctx.finding(
                    self.id,
                    L(
                        "Nenhum cabeçalho Allow anunciado pelo OPTIONS",
                        "No Allow header advertised by OPTIONS",
                    ),
                    Severity.INFO,
                    description=L(
                        "O servidor não retornou um cabeçalho Allow em resposta ao "
                        "OPTIONS /, então os métodos anunciados não puderam ser "
                        "enumerados.",
                        "The server did not return an Allow header in response to "
                        "OPTIONS /, so advertised methods could not be enumerated.",
                    ),
                    evidence=f"OPTIONS / -> HTTP {status}",
                    recommendation=L(
                        "Não necessariamente um problema; verifique os métodos "
                        "permitidos por outros meios se preciso.",
                        "Not necessarily a problem; verify allowed methods out of "
                        "band if needed.",
                    ),
                )
            ]

        methods = {
            m.strip().upper() for m in allow.split(",") if m.strip()
        }
        findings: list[Finding] = []
        for method in sorted(methods):
            if method in _DANGEROUS_METHODS:
                sev, rec = _DANGEROUS_METHODS[method]
                findings.append(
                    ctx.finding(
                        self.id,
                        L(
                            f"Método HTTP perigoso anunciado: {method}",
                            f"Dangerous HTTP method advertised: {method}",
                        ),
                        sev,
                        description=L(
                            f"O servidor anuncia o método {method} em seu "
                            "cabeçalho Allow.",
                            f"The server advertises the {method} method in its "
                            "Allow header.",
                        ),
                        evidence=f"Allow: {allow}",
                        recommendation=rec,
                        metadata={"method": method},
                    )
                )

        if not findings:
            # Methods advertised but none dangerous — record the clean result.
            findings.append(
                ctx.finding(
                    self.id,
                    L(
                        "Métodos HTTP anunciados (nenhum verbo perigoso)",
                        "HTTP methods advertised (no dangerous verbs)",
                    ),
                    Severity.INFO,
                    description=L(
                        "O cabeçalho Allow lista apenas métodos seguros padrão.",
                        "The Allow header lists only standard safe methods.",
                    ),
                    evidence=f"Allow: {allow}",
                )
            )
        return findings

    def _check_info_leak(
        self, ctx: RunContext, headers: dict[str, str]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for header, (sev, rec) in _INFO_LEAK_HEADERS.items():
            value = _get_header(headers, header)
            if value:
                # Normalize to the canonical header name for the title.
                canonical = "-".join(p.capitalize() for p in header.split("-"))
                findings.append(
                    ctx.finding(
                        self.id,
                        L(
                            f"Cabeçalho de exposição de informação: {canonical}",
                            f"Information exposure header: {canonical}",
                        ),
                        sev,
                        description=L(
                            f"A resposta revela o cabeçalho '{canonical}', "
                            "ajudando no fingerprinting da stack.",
                            f"The response discloses the '{canonical}' header, "
                            "aiding fingerprinting of the stack.",
                        ),
                        evidence=f"{canonical}: {value}",
                        recommendation=rec,
                        metadata={"header": header},
                    )
                )
        return findings

    # --- HTTP layer (isolated so tests can monkeypatch it) -----------------
    def _options(
        self,
        host: str,
        port: int,
        scheme: str,
        timeout: float = _DEFAULT_TIMEOUT,
        verify: bool = True,
        check_hostname: bool = True,
    ) -> tuple[int, dict[str, str]]:
        """Send a single ``OPTIONS /`` and return ``(status, headers)``.

        Blocking (stdlib ``http.client``); callers run it via
        ``asyncio.to_thread``. Deliberately the only place a socket is opened,
        which keeps the detection logic unit-testable without any network.
        """
        import http.client

        if scheme == "https":
            conn = http.client.HTTPSConnection(
                host, port, timeout=timeout, context=tls_context(verify, check_hostname)
            )
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request("OPTIONS", "/", headers={"User-Agent": _USER_AGENT})
            resp = conn.getresponse()
            # Drain the (usually empty) body so the connection closes cleanly.
            resp.read()
            return resp.status, {k: v for k, v in resp.getheaders()}
        finally:
            conn.close()


# --- helpers ---------------------------------------------------------------


def _get_header(headers: dict[str, str], name: str) -> str:
    """Case-insensitive header lookup (http.client preserves original casing)."""
    name = name.lower()
    for k, v in headers.items():
        if k.lower() == name:
            return v
    return ""
