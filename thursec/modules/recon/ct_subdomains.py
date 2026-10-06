"""Subdomain discovery via Certificate Transparency logs — pure stdlib.

Public CT logs record every certificate a CA issues, including the hostnames in
them. Querying crt.sh for a domain therefore surfaces subdomains an organisation
may not realise are publicly discoverable — all without sending a single packet
to the target itself, which is why this module is PASSIVE and needs no scope.
"""

from __future__ import annotations

import asyncio
import json
import urllib.request

from ...core.context import RunContext
from ...core.finding import Finding, Severity
from ...core.i18n import L, Lf
from ...core.module import Category, Intensity, Module

_CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
_USER_AGENT = "ThurSec/0.1"
_TIMEOUT = 15
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

        try:
            raw = await asyncio.to_thread(self.fetch, domain)
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
    def fetch(self, domain: str) -> str:
        """Fetch the raw crt.sh JSON response for ``domain``. Blocking on purpose."""
        url = _CRT_SH_URL.format(domain=domain)
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace")


# --- helpers ---------------------------------------------------------------
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
