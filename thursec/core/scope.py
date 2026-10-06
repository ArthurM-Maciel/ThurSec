"""Scope gate — ThurSec never touches a target that isn't authorized.

This is the feature that makes ThurSec a professional tool rather than a
"point it at anything" script: active modules must declare their target, and
the engine refuses to run them unless that target matches an explicit,
operator-provided scope. Out-of-scope scanning is one of the fastest ways to
turn an authorized engagement into an illegal one — so we make authorization a
hard precondition, not a reminder in the docs.

Scope is loaded from a YAML file the operator writes, e.g.::

    engagement: "Acme Corp - Q4 external pentest"
    authorized_by: "jane@acme.example (CISO)"
    expires: 2026-12-31
    targets:
      - "*.acme.example"
      - "203.0.113.0/24"
      - "10.0.0.5"
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Iterable

from .i18n import L, Lf


class ScopeError(Exception):
    """Raised when an action is attempted outside the authorized scope."""


def _parse_date(value: object) -> date | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value).strip())


@dataclass(slots=True)
class Scope:
    """An authorization boundary for one engagement."""

    engagement: str
    authorized_by: str
    targets: list[str] = field(default_factory=list)
    expires: date | None = None

    # --- loading -----------------------------------------------------------
    @classmethod
    def from_file(cls, path: str | Path) -> "Scope":
        import yaml  # local import keeps PyYAML optional until scope is used

        p = Path(path)
        if not p.exists():
            raise ScopeError(Lf("Arquivo de escopo não encontrado: {p}", "Scope file not found: {p}", p=p))
        data = yaml.safe_load(p.read_text()) or {}

        missing = [k for k in ("engagement", "authorized_by", "targets") if not data.get(k)]
        if missing:
            raise ScopeError(
                Lf(
                    "Arquivo de escopo {p} está sem o(s) campo(s) obrigatório(s): {fields}",
                    "Scope file {p} is missing required field(s): {fields}",
                    p=p,
                    fields=", ".join(missing),
                )
            )

        scope = cls(
            engagement=str(data["engagement"]),
            authorized_by=str(data["authorized_by"]),
            targets=[str(t).strip() for t in data["targets"] if str(t).strip()],
            expires=_parse_date(data.get("expires")),
        )
        if not scope.targets:
            raise ScopeError(Lf("Arquivo de escopo {p} não lista alvos.", "Scope file {p} lists no targets.", p=p))
        return scope

    # --- checks ------------------------------------------------------------
    @property
    def is_expired(self) -> bool:
        return self.expires is not None and date.today() > self.expires

    def contains(self, target: str) -> bool:
        """True if ``target`` (host, ip, or url host) is in scope."""
        host = _host_of(target)
        for entry in self.targets:
            if _match(host, entry):
                return True
        return False

    def enforce(self, target: str) -> None:
        """Raise ScopeError unless ``target`` is authorized and scope is valid."""
        if self.is_expired:
            raise ScopeError(
                Lf(
                    "O escopo do engajamento {engagement!r} expirou em {expires}.",
                    "Scope for engagement {engagement!r} expired on {expires}.",
                    engagement=self.engagement,
                    expires=self.expires,
                )
            )
        if not self.contains(target):
            raise ScopeError(
                Lf(
                    "O alvo {target!r} NÃO está no escopo autorizado "
                    "({engagement!r}). Recusando a execução. "
                    "Adicione-o ao arquivo de escopo apenas se você estiver "
                    "autorizado a testá-lo.",
                    "Target {target!r} is NOT in the authorized scope "
                    "({engagement!r}). Refusing to run. "
                    "Add it to the scope file only if you are authorized to test it.",
                    target=target,
                    engagement=self.engagement,
                )
            )

    def summary(self) -> str:
        exp = f", expires {self.expires}" if self.expires else ""
        return (
            f"{self.engagement} — authorized by {self.authorized_by}{exp} "
            f"({len(self.targets)} target pattern(s))"
        )


def _host_of(target: str) -> str:
    """Extract the host from a bare host, host:port, or URL."""
    t = target.strip()
    if "://" in t:
        from urllib.parse import urlparse

        t = urlparse(t).hostname or t
    # strip a trailing :port only when it's not part of an IPv6 literal
    if t.count(":") == 1:
        t = t.split(":", 1)[0]
    return t


def _match(host: str, entry: str) -> bool:
    """Match a host against a scope entry (glob, exact, or CIDR/IP)."""
    # CIDR or single IP entry
    try:
        net = ipaddress.ip_network(entry, strict=False)
        try:
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False  # host isn't an IP, entry is a network => no match
    except ValueError:
        pass
    # hostname glob (case-insensitive). Unlike fnmatch, '*' matches a single
    # label only (it does not cross '.'), so '*.lab.example' authorizes
    # 'a.lab.example' but NOT 'deep.sub.lab.example' — a deliberately tight
    # authorization boundary. '?' matches one non-dot character.
    return _glob_to_regex(entry.lower()).fullmatch(host.lower()) is not None


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    out = []
    for ch in pattern:
        if ch == "*":
            out.append(r"[^.]*")
        elif ch == "?":
            out.append(r"[^.]")
        else:
            out.append(re.escape(ch))
    return re.compile("".join(out))


def check_all(scope: Scope, targets: Iterable[str]) -> list[str]:
    """Return the subset of ``targets`` that are out of scope (for pre-flight)."""
    return [t for t in targets if not scope.contains(t)]
