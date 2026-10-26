"""Cookie security-flag audit — pure stdlib, no external tools.

This module sends a single ``GET /`` request to the target and inspects every
``Set-Cookie`` response header for the three flags that matter for defending a
session cookie:

  * ``Secure``   — keeps the cookie off cleartext HTTP (flagged on HTTPS).
  * ``HttpOnly`` — hides the cookie from JavaScript (``document.cookie``).
  * ``SameSite`` — mitigates CSRF; ``SameSite=None`` without ``Secure`` is
    rejected by modern browsers and is itself a misconfiguration.

It is deliberately **read-only**: it issues one idempotent ``GET`` and never a
state-changing verb, so running it cannot alter the target.

This module is ACTIVE (it sends one request to the target), so the engine's
scope gate applies before it ever runs. As a second line of defense the target
is routed through :func:`validate_target` first: a value shaped like a flag,
containing whitespace, or that is otherwise not a plausible host/URL is rejected
*before* any socket is opened (argument-injection / bad-target guard), mirroring
the nmap, nuclei and http_methods modules.

The cookie **value** is never logged: evidence carries only the cookie name and
the flags observed, so a captured session token can't leak into a findings
store or report.
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

_DEFAULT_TIMEOUT = 10.0


class CookieAudit(Module):
    id = "config_audit.cookies"
    category = Category.CONFIG_AUDIT
    intensity = Intensity.ACTIVE

    @property
    def name(self) -> str:
        return L("Flags de segurança de cookies", "Cookie security flags")

    @property
    def description(self) -> str:
        return L(
            "Audita as flags Set-Cookie (Secure, HttpOnly, SameSite) a partir de "
            "um único GET somente-leitura. Nunca registra os valores dos cookies.",
            "Audit Set-Cookie flags (Secure, HttpOnly, SameSite) from a single "
            "read-only GET. Never logs cookie values.",
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
                    L("Recusando a varredura: alvo inseguro/inválido", "Refusing to scan: unsafe/invalid target"),
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
                    recommendation=L("Forneça um hostname, IP, CIDR ou URL simples.", "Provide a plain hostname, IP, CIDR, or URL."),
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
            raw_cookies = await asyncio.to_thread(
                self._get_set_cookies, host, port, scheme, timeout, True
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
                    raw_cookies = await asyncio.to_thread(
                        self._get_set_cookies, host, port, scheme, timeout, True, False
                    )
                except ssl.SSLError:
                    raw_cookies = await asyncio.to_thread(
                        self._get_set_cookies, host, port, scheme, timeout, False, False
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

        if not raw_cookies:
            return mark_unverified(prefix + [
                ctx.finding(
                    self.id,
                    L("Nenhum cookie definido pela resposta", "No cookies set by the response"),
                    Severity.INFO,
                    description=Lf(
                        "GET / para {host}:{port} não retornou cabeçalhos Set-Cookie, "
                        "então não há flags de cookie para auditar.",
                        "GET / to {host}:{port} returned no Set-Cookie headers, "
                        "so there are no cookie flags to audit.",
                        host=host, port=port,
                    ),
                    recommendation=L(
                        "Não é necessariamente um problema; verifique por outros "
                        "meios se a aplicação deveria definir um cookie de sessão aqui.",
                        "Not necessarily a problem; verify out of band if the app "
                        "is expected to set a session cookie here.",
                    ),
                )
            ], verified)

        findings: list[Finding] = list(prefix)
        is_https = scheme == "https"
        for raw in raw_cookies:
            name, flags = _parse_cookie(raw)
            if not name:
                continue
            findings.extend(self._check_cookie(ctx, name, flags, is_https))
        return mark_unverified(findings, verified)

    def _request_failure(
        self, ctx: RunContext, error: BaseException, host: str, port: int, scheme: str
    ) -> Finding:
        return ctx.finding(
            self.id,
            L("Não foi possível completar a requisição GET", "Could not complete GET request"),
            Severity.LOW,
            description=Lf(
                "Falha ao enviar GET / para {host}:{port} via {scheme}.",
                "Failed to send GET / to {host}:{port} over {scheme}.",
                host=host, port=port, scheme=scheme,
            ),
            evidence=f"{type(error).__name__}: {error}",
            recommendation=L("Verifique se o host oferece HTTP(S) nesta porta.", "Verify the host serves HTTP(S) on this port."),
        )

    # --- checks ------------------------------------------------------------
    def _check_cookie(
        self, ctx: RunContext, name: str, flags: "_CookieFlags", is_https: bool
    ) -> list[Finding]:
        """Emit findings for one cookie's missing/weak flags.

        ``evidence`` deliberately names the cookie and the flags only — never
        the cookie value.
        """
        findings: list[Finding] = []
        # A compact, value-free description of what was observed.
        observed = _describe_flags(flags)

        # Secure — only meaningful / enforceable over HTTPS. A cookie set over
        # cleartext HTTP cannot be protected by Secure anyway.
        if is_https and not flags.secure:
            findings.append(
                ctx.finding(
                    self.id,
                    Lf("Cookie sem a flag Secure: {name}", "Cookie without Secure flag: {name}", name=name),
                    Severity.MEDIUM,
                    description=Lf(
                        "O cookie '{name}' é definido via HTTPS sem o atributo "
                        "Secure, então pode ser enviado por HTTP em texto claro.",
                        "Cookie '{name}' is set over HTTPS without the Secure "
                        "attribute, so it may be sent over cleartext HTTP.",
                        name=name,
                    ),
                    evidence=f"{name}: {observed}",
                    recommendation=L(
                        "Adicione o atributo Secure para que o cookie só seja "
                        "enviado por HTTPS.",
                        "Add the Secure attribute so the cookie is only sent over "
                        "HTTPS.",
                    ),
                    metadata={"cookie": name, "flag": "Secure"},
                )
            )

        # HttpOnly — always recommended for cookies not read by JS.
        if not flags.httponly:
            findings.append(
                ctx.finding(
                    self.id,
                    Lf("Cookie sem a flag HttpOnly: {name}", "Cookie without HttpOnly flag: {name}", name=name),
                    Severity.MEDIUM,
                    description=Lf(
                        "O cookie '{name}' não tem o atributo HttpOnly, então é "
                        "acessível ao JavaScript (document.cookie) e exposto a "
                        "roubo via XSS.",
                        "Cookie '{name}' lacks the HttpOnly attribute, so it is "
                        "accessible to JavaScript (document.cookie) and exposed to "
                        "theft via XSS.",
                        name=name,
                    ),
                    evidence=f"{name}: {observed}",
                    recommendation=L(
                        "Adicione o atributo HttpOnly a menos que o cookie precise "
                        "ser lido por scripts do lado do cliente.",
                        "Add the HttpOnly attribute unless the cookie must be read "
                        "by client-side scripts.",
                    ),
                    metadata={"cookie": name, "flag": "HttpOnly"},
                )
            )

        # SameSite — absent (browser default is now Lax, but being explicit is
        # safer) or SameSite=None without Secure (rejected by modern browsers).
        if flags.samesite is None:
            findings.append(
                ctx.finding(
                    self.id,
                    Lf("Cookie sem o atributo SameSite: {name}", "Cookie without SameSite attribute: {name}", name=name),
                    Severity.LOW,
                    description=Lf(
                        "O cookie '{name}' não define SameSite; depender do padrão "
                        "do navegador deixa o comportamento de CSRF implícito.",
                        "Cookie '{name}' does not set SameSite; relying on the "
                        "browser default leaves CSRF behavior implicit.",
                        name=name,
                    ),
                    evidence=f"{name}: {observed}",
                    recommendation=L(
                        "Defina SameSite explicitamente (Lax ou Strict) para mitigar CSRF.",
                        "Set SameSite explicitly (Lax or Strict) to mitigate CSRF.",
                    ),
                    metadata={"cookie": name, "flag": "SameSite"},
                )
            )
        elif flags.samesite == "none" and not flags.secure:
            findings.append(
                ctx.finding(
                    self.id,
                    Lf("Cookie com SameSite=None mas sem Secure: {name}", "Cookie with SameSite=None but no Secure: {name}", name=name),
                    Severity.MEDIUM,
                    description=Lf(
                        "O cookie '{name}' usa SameSite=None sem Secure; navegadores "
                        "modernos rejeitam esses cookies, e isso desativa a proteção "
                        "contra CSRF.",
                        "Cookie '{name}' uses SameSite=None without Secure; modern "
                        "browsers reject such cookies, and it disables CSRF "
                        "protection.",
                        name=name,
                    ),
                    evidence=f"{name}: {observed}",
                    recommendation=L(
                        "Adicione Secure ao usar SameSite=None, ou mude para "
                        "SameSite=Lax/Strict.",
                        "Add Secure when using SameSite=None, or switch to "
                        "SameSite=Lax/Strict.",
                    ),
                    metadata={"cookie": name, "flag": "SameSite=None"},
                )
            )

        if not findings:
            # Cookie carries all recommended flags — record the clean result.
            findings.append(
                ctx.finding(
                    self.id,
                    Lf("Flags do cookie OK: {name}", "Cookie flags OK: {name}", name=name),
                    Severity.INFO,
                    description=Lf("O cookie '{name}' define as flags recomendadas.", "Cookie '{name}' sets the recommended flags.", name=name),
                    evidence=f"{name}: {observed}",
                    metadata={"cookie": name},
                )
            )
        return findings

    # --- HTTP layer (isolated so tests can monkeypatch it) -----------------
    def _get_set_cookies(
        self,
        host: str,
        port: int,
        scheme: str,
        timeout: float = _DEFAULT_TIMEOUT,
        verify: bool = True,
        check_hostname: bool = True,
    ) -> list[str]:
        """Send a single ``GET /`` and return the raw ``Set-Cookie`` headers.

        Blocking (stdlib ``http.client``); callers run it via
        ``asyncio.to_thread``. Deliberately the only place a socket is opened,
        which keeps the detection logic unit-testable without any network. Each
        ``Set-Cookie`` header is returned as its own raw string (http.client
        preserves repeated headers), so multiple cookies are all audited.
        """
        import http.client

        if scheme == "https":
            conn = http.client.HTTPSConnection(
                host, port, timeout=timeout, context=tls_context(verify, check_hostname)
            )
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request("GET", "/", headers={"User-Agent": _USER_AGENT})
            resp = conn.getresponse()
            # Drain the body so the connection closes cleanly.
            resp.read()
            # get_all returns one entry per Set-Cookie header line.
            return list(resp.headers.get_all("Set-Cookie") or [])
        finally:
            conn.close()


# --- cookie parsing --------------------------------------------------------
class _CookieFlags:
    """The three audited attributes of one cookie (value never retained)."""

    __slots__ = ("secure", "httponly", "samesite")

    def __init__(self) -> None:
        self.secure: bool = False
        self.httponly: bool = False
        self.samesite: str | None = None  # lowercased value, or None if absent


def _parse_cookie(raw: str) -> tuple[str, _CookieFlags]:
    """Parse a raw ``Set-Cookie`` value into ``(name, flags)``.

    The cookie's **value** is parsed only to find the name and is then dropped
    on the floor — it is never stored or returned, so it cannot leak into a
    finding. Returns an empty name for an unparseable header.
    """
    flags = _CookieFlags()
    parts = raw.split(";")
    if not parts:
        return "", flags

    # First segment is "name=value"; keep only the name.
    name_value = parts[0].strip()
    name = name_value.split("=", 1)[0].strip()
    if not name:
        return "", flags

    for attr in parts[1:]:
        attr = attr.strip()
        if not attr:
            continue
        key, _, val = attr.partition("=")
        key = key.strip().lower()
        if key == "secure":
            flags.secure = True
        elif key == "httponly":
            flags.httponly = True
        elif key == "samesite":
            flags.samesite = val.strip().lower()
    return name, flags


def _describe_flags(flags: _CookieFlags) -> str:
    """A compact, value-free summary of the flags, for use as evidence."""
    parts = [
        f"Secure={'yes' if flags.secure else 'no'}",
        f"HttpOnly={'yes' if flags.httponly else 'no'}",
        f"SameSite={flags.samesite if flags.samesite is not None else 'absent'}",
    ]
    return ", ".join(parts)


# --- helpers ---------------------------------------------------------------
