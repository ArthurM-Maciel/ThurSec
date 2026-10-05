"""Domain registration recon via RDAP — pure stdlib, fully passive.

RDAP (Registration Data Access Protocol, RFC 9083) is the modern, structured
replacement for legacy WHOIS: a public, free, JSON API that any CA/registry
exposes. Querying ``rdap.org`` bootstraps to the authoritative server for the
TLD and returns the domain's registrar, key dates, nameservers and EPP status
codes — all without sending a single packet to the target itself, which is why
this module is PASSIVE and needs no scope.

Beyond surfacing who owns a domain, the registration data carries a concrete
risk signal: a domain that is expired, or about to expire, can be hijacked or
silently dropped, so we escalate those.
"""

from __future__ import annotations

import asyncio
import json
import urllib.request
from datetime import datetime, timezone

from ...core.context import RunContext
from ...core.finding import Finding, Severity
from ...core.module import Category, Intensity, Module

_RDAP_URL = "https://rdap.org/domain/{domain}"
_USER_AGENT = "ThurSec/0.1"
_TIMEOUT = 15
# Warn when a domain is within this many days of expiring.
_EXPIRY_WARN_DAYS = 30

# RDAP eventAction values we care about, mapped to a friendly label.
_EVENT_LABELS = {
    "registration": "registration",
    "expiration": "expiration",
    "last changed": "last-changed",
}


class WhoisRdap(Module):
    id = "recon.whois"
    name = "Domain registration (RDAP/WHOIS)"
    category = Category.RECON
    intensity = Intensity.PASSIVE
    description = (
        "Passively look up domain registration data (registrar, dates, "
        "nameservers, status) via the public RDAP service."
    )

    async def run(self, ctx: RunContext) -> list[Finding]:
        domain = _normalize_domain(ctx.target)

        try:
            raw = await asyncio.to_thread(self.fetch, domain)
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("RDAP response was not a JSON object")
        except Exception as e:
            return [
                ctx.finding(
                    self.id,
                    "Could not retrieve RDAP data",
                    Severity.LOW,
                    description=(
                        f"The RDAP lookup for {domain} via rdap.org did not complete."
                    ),
                    evidence=f"{type(e).__name__}: {e}",
                    recommendation=(
                        "Retry later or query the TLD's RDAP/WHOIS server directly; "
                        "rdap.org can be slow, rate-limited, or lack a bootstrap "
                        "entry for some TLDs."
                    ),
                    references=["https://about.rdap.org/"],
                )
            ]

        info = _parse_rdap(data, domain)
        findings: list[Finding] = []

        # --- summary INFO finding -------------------------------------------
        summary_lines = []
        if info["registrar"]:
            summary_lines.append(f"registrar: {info['registrar']}")
        for label, value in info["events"].items():
            summary_lines.append(f"{label}: {value}")
        if info["nameservers"]:
            summary_lines.append("nameservers: " + ", ".join(info["nameservers"]))
        if info["status"]:
            summary_lines.append("status: " + ", ".join(info["status"]))

        findings.append(
            ctx.finding(
                self.id,
                f"Domain registration data for {domain}",
                Severity.INFO,
                description=(
                    f"Retrieved registration data for {domain} from public RDAP."
                ),
                evidence="\n".join(summary_lines) if summary_lines else "(no fields)",
                references=["https://about.rdap.org/"],
                metadata={
                    "domain": domain,
                    "registrar": info["registrar"],
                    "events": info["events"],
                    "nameservers": info["nameservers"],
                    "status": info["status"],
                },
            )
        )

        # --- expiry risk ----------------------------------------------------
        expiry_raw = info["events"].get("expiration")
        expiry_dt = _parse_date(expiry_raw) if expiry_raw else None
        if expiry_dt is not None:
            now = datetime.now(timezone.utc)
            days_left = (expiry_dt - now).total_seconds() / 86400
            if days_left < 0:
                findings.append(
                    ctx.finding(
                        self.id,
                        "Domain is expired",
                        Severity.HIGH,
                        description=(
                            f"The registration for {domain} expired on {expiry_raw} "
                            f"({abs(int(days_left))} day(s) ago)."
                        ),
                        evidence=f"expiration: {expiry_raw}",
                        recommendation=(
                            "Renew the domain immediately. An expired domain can be "
                            "re-registered by an attacker, enabling takeover of email, "
                            "sites and services that depend on it."
                        ),
                        references=["https://about.rdap.org/"],
                        metadata={"domain": domain, "expiration": expiry_raw},
                    )
                )
            elif days_left < _EXPIRY_WARN_DAYS:
                findings.append(
                    ctx.finding(
                        self.id,
                        "Domain expires soon",
                        Severity.MEDIUM,
                        description=(
                            f"The registration for {domain} expires on {expiry_raw} "
                            f"(in {int(days_left)} day(s))."
                        ),
                        evidence=f"expiration: {expiry_raw}",
                        recommendation=(
                            "Renew the domain well before expiry (ideally enable "
                            "auto-renew) to avoid an accidental lapse and possible "
                            "domain takeover."
                        ),
                        references=["https://about.rdap.org/"],
                        metadata={"domain": domain, "expiration": expiry_raw},
                    )
                )

        return findings

    # --- isolable fetch (monkeypatched in tests) ---------------------------
    def fetch(self, domain: str) -> str:
        """Fetch the raw RDAP JSON for ``domain``. Blocking on purpose."""
        url = _RDAP_URL.format(domain=domain)
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


def _parse_rdap(data: dict, domain: str) -> dict:
    """Pull the fields we report out of an RDAP domain object."""
    return {
        "registrar": _extract_registrar(data),
        "events": _extract_events(data),
        "nameservers": _extract_nameservers(data),
        "status": _extract_status(data),
    }


def _extract_events(data: dict) -> dict[str, str]:
    """Map RDAP events to {label: eventDate} for the actions we care about."""
    events: dict[str, str] = {}
    raw = data.get("events")
    if not isinstance(raw, list):
        return events
    for ev in raw:
        if not isinstance(ev, dict):
            continue
        action = str(ev.get("eventAction", "")).strip().lower()
        label = _EVENT_LABELS.get(action)
        date = ev.get("eventDate")
        if label and isinstance(date, str) and date:
            events.setdefault(label, date)
    return events


def _extract_nameservers(data: dict) -> list[str]:
    """Collect nameserver hostnames, lowercased, sorted and deduplicated."""
    found: set[str] = set()
    raw = data.get("nameservers")
    if isinstance(raw, list):
        for ns in raw:
            if isinstance(ns, dict):
                name = ns.get("ldhName")
                if isinstance(name, str) and name.strip():
                    found.add(name.strip().lower().rstrip("."))
    return sorted(found)


def _extract_status(data: dict) -> list[str]:
    """Return EPP status codes as a clean list of strings."""
    raw = data.get("status")
    if not isinstance(raw, list):
        return []
    return [str(s) for s in raw if isinstance(s, str) and s.strip()]


def _extract_registrar(data: dict) -> str:
    """Find the registrar name among the RDAP entities.

    The registrar is an entity whose ``roles`` include ``"registrar"``; its
    human name lives in the jCard (vCard) ``fn`` property. Fall back to the
    entity handle if the vCard is missing or malformed.
    """
    entities = data.get("entities")
    if not isinstance(entities, list):
        return ""
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        roles = ent.get("roles")
        if not isinstance(roles, list) or "registrar" not in roles:
            continue
        name = _vcard_fn(ent.get("vcardArray"))
        if name:
            return name
        handle = ent.get("handle")
        if isinstance(handle, str) and handle.strip():
            return handle.strip()
    return ""


def _vcard_fn(vcard: object) -> str:
    """Extract the ``fn`` (formatted name) value from a jCard array."""
    # jCard shape: ["vcard", [ ["fn", {}, "text", "Some Registrar, Inc."], ... ]]
    if not isinstance(vcard, list) or len(vcard) < 2:
        return ""
    props = vcard[1]
    if not isinstance(props, list):
        return ""
    for prop in props:
        if (
            isinstance(prop, list)
            and len(prop) >= 4
            and prop[0] == "fn"
            and isinstance(prop[3], str)
        ):
            return prop[3].strip()
    return ""


def _parse_date(value: str) -> datetime | None:
    """Parse an RDAP ISO-8601 eventDate into an aware UTC datetime."""
    s = value.strip()
    # Python's fromisoformat handles "Z" only from 3.11; normalize it.
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
