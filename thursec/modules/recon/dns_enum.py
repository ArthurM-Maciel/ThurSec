"""Passive DNS enumeration via DNS-over-HTTPS (DoH) — pure stdlib.

Rather than query the target's authoritative servers directly, this module asks
a free, public DoH resolver (Cloudflare's ``cloudflare-dns.com``) for the
domain's records. The lookup travels to the resolver, never to the target, so
the module is PASSIVE and needs no scope: we learn the published A/AAAA/MX/NS/
TXT/CNAME records plus basic email-security hygiene (SPF, DMARC) without sending
a single packet to the organisation being assessed.
"""

from __future__ import annotations

import asyncio
import json
import urllib.parse
import urllib.request

from ...core.context import RunContext
from ...core.finding import Finding, Severity
from ...core.module import Category, Intensity, Module

_DOH_URL = "https://cloudflare-dns.com/dns-query"
_ACCEPT = "application/dns-json"
_USER_AGENT = "ThurSec/0.1"
_TIMEOUT = 10
# Record types we enumerate for the apex domain, in report order.
_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")
# How many records to show inline in a finding's evidence.
_EVIDENCE_LIMIT = 25


class DnsEnum(Module):
    id = "recon.dns"
    name = "DNS enumeration (DoH)"
    category = Category.RECON
    intensity = Intensity.PASSIVE
    description = (
        "Enumerate DNS records (A/AAAA/MX/NS/TXT/CNAME) and check SPF/DMARC "
        "hygiene via a public DNS-over-HTTPS resolver — no packets to the target."
    )

    async def run(self, ctx: RunContext) -> list[Finding]:
        domain = _normalize_domain(ctx.target)
        findings: list[Finding] = []
        # Track per-type success so hygiene checks never fire on a failed lookup.
        records_by_type: dict[str, list[str]] = {}

        for rtype in _RECORD_TYPES:
            try:
                raw = await asyncio.to_thread(self.fetch, domain, rtype)
                records = _parse_answer(json.loads(raw))
            except Exception as e:
                findings.append(self._error_finding(ctx, domain, rtype, e))
                continue

            records_by_type[rtype] = records
            if records:
                findings.append(
                    ctx.finding(
                        self.id,
                        f"{rtype} records for {domain}",
                        Severity.INFO,
                        description=(
                            f"Found {len(records)} {rtype} record(s) for {domain} "
                            "via DNS-over-HTTPS."
                        ),
                        evidence=_evidence(records),
                        references=["https://developers.cloudflare.com/1.1.1.1/"],
                        metadata={
                            "domain": domain,
                            "type": rtype,
                            "records": records,
                        },
                    )
                )

        # --- Email hygiene: SPF ------------------------------------------------
        # Only assess SPF if the TXT lookup actually succeeded.
        if "TXT" in records_by_type:
            txt = records_by_type["TXT"]
            if not any("v=spf1" in r.lower() for r in txt):
                findings.append(
                    ctx.finding(
                        self.id,
                        f"No SPF record published for {domain}",
                        Severity.LOW,
                        description=(
                            f"No TXT record containing an SPF policy (v=spf1) was "
                            f"found for {domain}. Without SPF, receivers cannot verify "
                            "which hosts are authorised to send mail for this domain, "
                            "making spoofing easier."
                        ),
                        evidence="\n".join(txt) or "(no TXT records)",
                        recommendation=(
                            "Publish an SPF record, e.g. a TXT record "
                            '"v=spf1 include:_spf.yourprovider.com -all" that lists '
                            "every authorised sender and ends in -all (or ~all)."
                        ),
                        references=["https://www.rfc-editor.org/rfc/rfc7208"],
                        metadata={"domain": domain, "type": "TXT", "check": "spf"},
                    )
                )

        # --- Email hygiene: DMARC ---------------------------------------------
        dmarc_name = f"_dmarc.{domain}"
        try:
            raw = await asyncio.to_thread(self.fetch, dmarc_name, "TXT")
            dmarc = _parse_answer(json.loads(raw))
        except Exception as e:
            findings.append(self._error_finding(ctx, dmarc_name, "TXT", e))
            dmarc = None

        if dmarc is not None and not any("v=DMARC1" in r for r in dmarc):
            findings.append(
                ctx.finding(
                    self.id,
                    f"No DMARC record published for {domain}",
                    Severity.LOW,
                    description=(
                        f"No TXT record containing a DMARC policy (v=DMARC1) was "
                        f"found at {dmarc_name}. Without DMARC, there is no published "
                        "policy telling receivers how to handle mail that fails SPF "
                        "or DKIM, nor any reporting of abuse."
                    ),
                    evidence="\n".join(dmarc) or "(no TXT records)",
                    recommendation=(
                        f"Publish a DMARC record as a TXT record at {dmarc_name}, "
                        'e.g. "v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain". Start '
                        "with p=none to monitor, then tighten to quarantine/reject."
                    ),
                    references=["https://www.rfc-editor.org/rfc/rfc7489"],
                    metadata={"domain": domain, "type": "TXT", "check": "dmarc"},
                )
            )

        return findings

    def _error_finding(
        self, ctx: RunContext, name: str, rtype: str, exc: Exception
    ) -> Finding:
        return ctx.finding(
            self.id,
            f"Could not resolve {rtype} record for {name}",
            Severity.LOW,
            description=(
                f"The DNS-over-HTTPS lookup of {name} ({rtype}) did not complete."
            ),
            evidence=f"{type(exc).__name__}: {exc}",
            recommendation=(
                "Retry later or try another DoH resolver; the resolver may be "
                "temporarily unreachable or rate-limited."
            ),
            references=["https://developers.cloudflare.com/1.1.1.1/"],
            metadata={"name": name, "type": rtype},
        )

    # --- isolable fetch (monkeypatched in tests) ---------------------------
    def fetch(self, name: str, rtype: str) -> str:
        """Fetch the raw DoH JSON answer for ``name``/``rtype``. Blocking on purpose."""
        query = urllib.parse.urlencode({"name": name, "type": rtype})
        req = urllib.request.Request(
            f"{_DOH_URL}?{query}",
            headers={"Accept": _ACCEPT, "User-Agent": _USER_AGENT},
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace")


# --- helpers ---------------------------------------------------------------
def _normalize_domain(target: str) -> str:
    """Reduce a target (possibly a URL) to a bare, lowercase domain."""
    t = target.strip().lower()
    if "://" in t:
        t = urllib.parse.urlparse(t).hostname or t
    t = t.split("/", 1)[0]
    t = t.split(":", 1)[0]
    return t.strip(".")


def _parse_answer(payload: object) -> list[str]:
    """Pull the ``data`` field out of each entry in a DoH JSON ``Answer`` list.

    TXT records come back as one or more quoted strings; we unquote and join
    them so callers see the human-readable value (e.g. ``v=spf1 ...``).
    """
    if not isinstance(payload, dict):
        return []
    answer = payload.get("Answer")
    if not isinstance(answer, list):
        return []

    records: list[str] = []
    for entry in answer:
        if not isinstance(entry, dict):
            continue
        data = entry.get("data")
        if not isinstance(data, str):
            continue
        records.append(_clean_txt(data))
    return records


def _clean_txt(data: str) -> str:
    """Unquote a DoH record value and stitch together split TXT chunks."""
    data = data.strip()
    # Long TXT values arrive as adjacent quoted chunks: "part1" "part2".
    if '" "' in data:
        data = data.replace('" "', "")
    return data.strip('"')


def _evidence(records: list[str]) -> str:
    shown = records[:_EVIDENCE_LIMIT]
    evidence = "\n".join(shown)
    if len(records) > len(shown):
        evidence += f"\n... (+{len(records) - len(shown)} more)"
    return evidence
