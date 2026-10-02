"""Target validation — the defense against *argument injection* into argv.

ThurSec runs external tools (nmap, and more to come) with the operator's target
value placed directly on the command line, e.g. ``["nmap", "-sT", target]``.
Running without a shell already stops classic shell-injection (``; rm -rf``),
but it does **not** stop a target that *looks like a flag*: if ``target`` is
``"-sS"``, ``"--script=http-shellshock,exploit"`` or ``"-oN/tmp/pwned"``, the
tool parses it as one of its own options — bypassing any in-module allowlist and
potentially running arbitrary NSE scripts or writing files.

Appending ``--`` ("end of options") is **not** a reliable fix for nmap, so the
only safe stance is to *reject* a dangerous target rather than try to escape it.
That is what :func:`validate_target` does, and every module that forwards a
target into a subprocess argv should route it through here first.

A valid target is normalized and returned; anything implausible or dangerous
raises :class:`TargetError`. This module is pure stdlib and imports nothing from
the rest of ThurSec, so it is safe to use anywhere (no circular imports).
"""

from __future__ import annotations

import ipaddress
import re

__all__ = ["TargetError", "validate_target"]


class TargetError(Exception):
    """Raised when a target is empty, malformed, or unsafe to pass to a tool."""


# A single DNS label: 1-63 chars of letters/digits/hyphen, not starting or
# ending with a hyphen. The negative look-arounds reject the ``-sS`` shape.
_LABEL = re.compile(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def validate_target(raw: str) -> str:
    """Validate and normalize ``raw`` into a safe target string for a tool argv.

    Accepts a bare hostname, IPv4/IPv6 address, CIDR network, ``host:port``,
    a bracketed IPv6 literal (``[::1]`` / ``[::1]:80``), or a full URL (whose
    host is extracted). Returns the normalized host / IP / network.

    Raises :class:`TargetError` when the target is empty, begins with ``-``
    (would be read as a command-line flag — the core argument-injection guard),
    contains whitespace or control characters, or does not resemble a plausible
    host / IP / CIDR. Callers MUST NOT invoke the external tool when this raises.
    """
    if raw is None:
        raise TargetError("target is empty")
    s = raw.strip()

    if not s:
        raise TargetError("target is empty")
    if s.startswith("-"):
        raise TargetError(
            f"target {s!r} starts with '-' and would be interpreted as a "
            f"command-line flag (argument injection); refusing."
        )
    for ch in s:
        if ch.isspace():
            raise TargetError(f"target {s!r} contains whitespace")
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise TargetError(f"target {s!r} contains a control character")

    host = _extract_host(s)
    if not host:
        raise TargetError(f"could not extract a host from target {s!r}")
    if host.startswith("-"):
        # e.g. a URL/authority whose host itself looks like a flag.
        raise TargetError(
            f"host {host!r} from target {s!r} starts with '-'; refusing."
        )

    # IP address or CIDR network (also covers full IPv6 literals).
    try:
        net = ipaddress.ip_network(host, strict=False)
    except ValueError:
        net = None
    if net is not None:
        if net.prefixlen == net.max_prefixlen and "/" not in host:
            return str(net.network_address)  # bare single address
        return str(net)

    if _is_hostname(host):
        return host.lower().rstrip(".")

    raise TargetError(
        f"target {s!r} is not a plausible host, IP address, CIDR or URL host"
    )


# --- host extraction -------------------------------------------------------
def _extract_host(s: str) -> str:
    """Pull the bare host out of a URL / host:port / bracketed IPv6 / CIDR.

    Mirrors the host parsing in ``core.scope`` but also understands bracketed
    IPv6 literals and CIDR, which matter when the result is handed to a tool.
    """
    # Full URL — let urllib pull out the (already unbracketed) host.
    if "://" in s:
        from urllib.parse import urlparse

        return (urlparse(s).hostname or "").strip()

    # Bracketed IPv6 literal, optionally with a :port — "[::1]" / "[::1]:80".
    if s.startswith("["):
        end = s.find("]")
        if end > 1:
            return s[1:end]
        return ""

    # Whole string is an IP or CIDR (covers IPv6 with its many colons).
    try:
        ipaddress.ip_network(s, strict=False)
        return s
    except ValueError:
        pass

    # host:port (a single colon, so not an IPv6 literal) — drop the port.
    host = s.split(":", 1)[0] if s.count(":") == 1 else s
    # Drop any path component left on a bare hostname ("example.com/admin").
    host = host.split("/", 1)[0]
    return host


def _is_hostname(host: str) -> bool:
    """True if ``host`` is a plausible DNS hostname (one or more valid labels)."""
    if not host or len(host) > 253:
        return False
    labels = host.rstrip(".").split(".")
    return all(_LABEL.match(label) for label in labels)
