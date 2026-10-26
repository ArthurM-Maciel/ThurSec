"""Subdomain discovery via Certificate Transparency logs — pure stdlib.

Public CT logs record every certificate a CA issues, including the hostnames in
them. Querying crt.sh for a domain therefore surfaces subdomains an organisation
may not realise are publicly discoverable — all without sending a single packet
to the target itself, which is why this module is PASSIVE and needs no scope.
"""

from __future__ import annotations

import asyncio
import json
import time
import urllib.error
import urllib.request

from ... import __version__
from ...core.context import RunContext, coerce_timeout
from ...core.finding import Finding, Severity
from ...core.i18n import L, Lf
from ...core.module import Category, Intensity, Module

_CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
_USER_AGENT = f"ThurSec/{__version__}"
# crt.sh agrega todos os logs públicos de CT e costuma levar dezenas de
# segundos em domínios grandes; um teto curto demais vira timeout rotineiro.
_DEFAULT_TIMEOUT = 45.0
# O crt.sh devolve 502/503 intermitentes mesmo quando está no ar — medido em
# ~2 de 3 requisições, e o 502 volta em menos de 1s. Sem repetir, isso vira
# um falso "não foi possível consultar" na maioria das execuções.
_MAX_ATTEMPTS = 3
_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
_RETRY_DELAY = 2.0
_MAX_RETRY_DELAY = 30.0
# Falhas que melhoram repetindo. gaierror (NXDOMAIN) e erro de TLS ficam de fora.
_TRANSIENT_ERRORS = (TimeoutError, ConnectionError)
# Above this many subdomains we nudge the operator about attack surface.
_LARGE_SURFACE = 50
# How many names to show inline in the finding's evidence.
_EVIDENCE_LIMIT = 20


class CtSubdomains(Module):
    id = "recon.ct_subdomains"
    category = Category.RECON
    intensity = Intensity.PASSIVE

    @property
    def name(self) -> str:
        return L(
            "Subdomínios via Certificate Transparency",
            "Certificate Transparency subdomains",
        )

    @property
    def description(self) -> str:
        return L(
            "Enumera subdomínios a partir de logs públicos de Certificate "
            "Transparency (crt.sh).",
            "Enumerate subdomains from public Certificate Transparency logs (crt.sh).",
        )

    async def run(self, ctx: RunContext) -> list[Finding]:
        domain = _normalize_domain(ctx.target)

        timeout = coerce_timeout(ctx.options.get("timeout"), _DEFAULT_TIMEOUT)

        try:
            raw = await asyncio.to_thread(self.fetch, domain, timeout)
            entries = json.loads(raw)
        except Exception as e:
            return [
                ctx.finding(
                    self.id,
                    L(
                        "Não foi possível consultar os logs de Certificate Transparency",
                        "Could not query Certificate Transparency logs",
                    ),
                    Severity.LOW,
                    description=Lf(
                        "A consulta aos logs de CT para {domain} via crt.sh não "
                        "foi concluída.",
                        "The CT log lookup for {domain} via crt.sh did not complete.",
                        domain=domain,
                    ),
                    evidence=f"{type(e).__name__}: {e}",
                    recommendation=L(
                        "Tente novamente mais tarde ou consulte outra fonte de CT; "
                        "o crt.sh pode estar lento ou com limite de requisições.",
                        "Retry later or query another CT source; crt.sh can be slow "
                        "or rate-limited.",
                    ),
                    references=["https://crt.sh/"],
                )
            ]

        subdomains = _extract_subdomains(entries, domain)
        count = len(subdomains)

        shown = subdomains[:_EVIDENCE_LIMIT]
        evidence = "\n".join(shown)
        if count > len(shown):
            evidence += f"\n... (+{count - len(shown)} more)"

        if count > _LARGE_SURFACE:
            severity = Severity.LOW
            recommendation = L(
                "Um grande número de subdomínios é publicamente descobrível via "
                "logs de CT. Revise se cada host exposto deve mesmo ser alcançável "
                "e reduza a superfície de ataque exposta externamente quando possível.",
                "A large number of subdomains are publicly discoverable via CT logs. "
                "Review whether every exposed host is intended to be reachable and "
                "reduce the externally exposed attack surface where possible.",
            )
        else:
            severity = Severity.INFO
            recommendation = ""

        return [
            ctx.finding(
                self.id,
                Lf(
                    "Descobertos {count} subdomínios via Certificate Transparency",
                    "Discovered {count} subdomains via Certificate Transparency",
                    count=count,
                ),
                severity,
                description=Lf(
                    "Encontrado(s) {count} subdomínio(s) único(s) de {domain} em "
                    "logs públicos de Certificate Transparency (crt.sh).",
                    "Found {count} unique subdomain(s) of {domain} in public "
                    "Certificate Transparency logs (crt.sh).",
                    count=count,
                    domain=domain,
                ),
                evidence=evidence,
                recommendation=recommendation,
                references=["https://crt.sh/"],
                metadata={"domain": domain, "count": count, "subdomains": subdomains},
            )
        ]

    # --- isolable fetch (monkeypatched in tests) ---------------------------
    def fetch(self, domain: str, timeout: float = _DEFAULT_TIMEOUT) -> str:
        """Fetch the raw crt.sh JSON response for ``domain``. Blocking on purpose."""
        url = _CRT_SH_URL.format(domain=domain)
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        # `timeout` é o orçamento TOTAL do operador, não por tentativa: com
        # repetição, um por-tentativa multiplicaria a espera por _MAX_ATTEMPTS
        # e travaria a execução inteira (os módulos rodam em sequência).
        deadline = time.monotonic() + timeout
        last: Exception | None = None

        for attempt in range(_MAX_ATTEMPTS):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                with urllib.request.urlopen(req, timeout=remaining) as resp:
                    return resp.read().decode("utf-8", errors="replace")
            except urllib.error.HTTPError as e:
                # HTTPError é file-like e segura um socket: fechar antes de dormir.
                e.close()
                last = e
                if e.code not in _RETRY_STATUSES:
                    raise
                delay = _retry_delay(e)
            except urllib.error.URLError as e:
                # urllib embrulha o erro de conexão: só repetir se o motivo for
                # transitório. NXDOMAIN (gaierror) e falha de TLS não melhoram
                # repetindo — repeti-las só atrasa o mesmo achado.
                if not isinstance(e.reason, _TRANSIENT_ERRORS):
                    raise
                last = e
                delay = _RETRY_DELAY
            except _TRANSIENT_ERRORS as e:
                # Timeout de leitura sobe direto, sem embrulho.
                last = e
                delay = _RETRY_DELAY

            if attempt + 1 >= _MAX_ATTEMPTS:
                break
            if deadline - time.monotonic() <= delay:
                break  # dormir estouraria o orçamento; desiste agora.
            time.sleep(delay)

        if last is None:  # orçamento esgotado antes da primeira tentativa
            raise TimeoutError(f"crt.sh lookup budget of {timeout}s exhausted")
        raise last


# --- helpers ---------------------------------------------------------------
def _retry_delay(error: urllib.error.HTTPError) -> float:
    """Pausa antes da segunda tentativa, respeitando Retry-After num 429."""
    try:
        after = float(error.headers.get("Retry-After", ""))
    except (AttributeError, TypeError, ValueError):
        return _RETRY_DELAY
    # Um Retry-After absurdo não deve travar a execução inteira.
    return max(_RETRY_DELAY, min(after, _MAX_RETRY_DELAY))



def _normalize_domain(target: str) -> str:
    """Reduce a target (possibly a URL) to a bare, lowercase domain."""
    t = target.strip().lower()
    if "://" in t:
        from urllib.parse import urlparse

        t = urlparse(t).hostname or t
    t = t.split("/", 1)[0]
    t = t.split(":", 1)[0]
    return t.strip(".")


def _extract_subdomains(entries: object, domain: str) -> list[str]:
    """Parse crt.sh JSON into a sorted, deduplicated list of in-scope subdomains."""
    suffix = "." + domain
    found: set[str] = set()

    if not isinstance(entries, list):
        return []

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name_value = entry.get("name_value", "")
        if not isinstance(name_value, str):
            continue
        for line in name_value.splitlines():
            name = line.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if not name:
                continue
            if name == domain or name.endswith(suffix):
                found.add(name)

    return sorted(found)
