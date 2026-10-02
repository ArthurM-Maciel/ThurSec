"""TLS + HTTP security-header audit — pure stdlib, no external tools.

A good first module: genuinely useful for defending your own sites, works out
of the box, and because it talks to the target it exercises the scope gate.
It checks:

  * certificate expiry (days remaining)
  * negotiated TLS protocol version (flags TLS < 1.2)
  * presence of key HTTP security headers (HSTS, CSP, X-Content-Type-Options, …)
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone

from ...core.context import RunContext
from ...core.finding import Finding, Severity
from ...core.module import Category, Intensity, Module

# header -> (severity if missing, human recommendation)
_SECURITY_HEADERS: dict[str, tuple[Severity, str]] = {
    "strict-transport-security": (
        Severity.MEDIUM,
        "Add HSTS to force HTTPS and prevent protocol downgrade.",
    ),
    "content-security-policy": (
        Severity.MEDIUM,
        "Add a Content-Security-Policy to mitigate XSS and data injection.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "Set 'X-Content-Type-Options: nosniff' to stop MIME sniffing.",
    ),
    "x-frame-options": (
        Severity.LOW,
        "Set X-Frame-Options (or CSP frame-ancestors) to prevent clickjacking.",
    ),
    "referrer-policy": (
        Severity.INFO,
        "Set a Referrer-Policy to limit referrer leakage.",
    ),
}


class TlsHeadersAudit(Module):
    id = "config_audit.tls_headers"
    name = "TLS & HTTP security headers"
    category = Category.CONFIG_AUDIT
    intensity = Intensity.ACTIVE
    description = "Check certificate validity, TLS version, and HTTP security headers."

    async def run(self, ctx: RunContext) -> list[Finding]:
        host = _hostname(ctx.target)
        port = int(ctx.options.get("port", 443))
        findings: list[Finding] = []

        # TLS layer (cert + protocol) runs in a thread: stdlib ssl is blocking.
        try:
            cert, proto = await asyncio.to_thread(_tls_info, host, port)
        except Exception as e:
            findings.append(
                ctx.finding(
                    self.id,
                    "Could not establish TLS connection",
                    Severity.MEDIUM,
                    description=f"Failed to complete a TLS handshake with {host}:{port}.",
                    evidence=f"{type(e).__name__}: {e}",
                    recommendation="Verify the host serves TLS on this port.",
                )
            )
            return findings

        findings.extend(self._check_cert(ctx, cert, host, port))
        findings.extend(self._check_protocol(ctx, proto))
        findings.extend(await self._check_headers(ctx, host, port))
        return findings

    # --- checks ------------------------------------------------------------
    def _check_cert(self, ctx: RunContext, cert: dict, host: str, port: int) -> list[Finding]:
        not_after = cert.get("notAfter")
        if not not_after:
            return []
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days = (expires - datetime.now(timezone.utc)).days
        if days < 0:
            sev, title = Severity.CRITICAL, "TLS certificate is expired"
        elif days <= 14:
            sev, title = Severity.HIGH, f"TLS certificate expires in {days} day(s)"
        elif days <= 30:
            sev, title = Severity.MEDIUM, f"TLS certificate expires in {days} day(s)"
        else:
            return [
                ctx.finding(
                    self.id,
                    "TLS certificate validity OK",
                    Severity.INFO,
                    description=f"Certificate valid for {days} more day(s).",
                    evidence=f"notAfter={not_after}",
                )
            ]
        return [
            ctx.finding(
                self.id, title, sev,
                description=f"Certificate for {host}:{port} needs renewal.",
                evidence=f"notAfter={not_after}",
                recommendation="Renew/rotate the certificate before it lapses.",
            )
        ]

    def _check_protocol(self, ctx: RunContext, proto: str | None) -> list[Finding]:
        if not proto:
            return []
        weak = proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2")
        if weak:
            return [
                ctx.finding(
                    self.id,
                    f"Weak TLS protocol negotiated: {proto}",
                    Severity.HIGH,
                    description="The server negotiated an outdated TLS/SSL version.",
                    evidence=f"negotiated={proto}",
                    recommendation="Disable TLS < 1.2; prefer TLS 1.3.",
                    references=["https://datatracker.ietf.org/doc/html/rfc8996"],
                )
            ]
        return [
            ctx.finding(
                self.id, f"TLS protocol OK ({proto})", Severity.INFO,
                evidence=f"negotiated={proto}",
            )
        ]

    async def _check_headers(self, ctx: RunContext, host: str, port: int) -> list[Finding]:
        try:
            headers = await asyncio.to_thread(_fetch_headers, host, port)
        except Exception as e:
            return [
                ctx.finding(
                    self.id, "Could not fetch HTTP headers", Severity.LOW,
                    evidence=f"{type(e).__name__}: {e}",
                )
            ]
        present = {k.lower() for k in headers}
        findings = []
        for header, (sev, rec) in _SECURITY_HEADERS.items():
            if header not in present:
                findings.append(
                    ctx.finding(
                        self.id,
                        f"Missing security header: {header}",
                        sev,
                        description=f"Response from {host} does not set '{header}'.",
                        recommendation=rec,
                    )
                )
        server = headers.get("Server")
        if server:
            findings.append(
                ctx.finding(
                    self.id, "Server banner disclosed", Severity.INFO,
                    evidence=f"Server: {server}",
                    recommendation="Consider suppressing the Server header to reduce fingerprinting.",
                )
            )
        return findings


# --- low-level helpers -----------------------------------------------------
def _hostname(target: str) -> str:
    t = target.strip()
    if "://" in t:
        from urllib.parse import urlparse

        return urlparse(t).hostname or t
    return t.split(":", 1)[0] if t.count(":") == 1 else t


def _tls_info(host: str, port: int) -> tuple[dict, str | None]:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert() or {}, ssock.version()


def _fetch_headers(host: str, port: int) -> dict[str, str]:
    import http.client

    conn = http.client.HTTPSConnection(host, port, timeout=10)
    try:
        conn.request("HEAD", "/", headers={"User-Agent": "ThurSec/0.1"})
        resp = conn.getresponse()
        return {k: v for k, v in resp.getheaders()}
    finally:
        conn.close()
