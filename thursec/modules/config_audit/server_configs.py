"""Local server-config linter — nginx & sshd hardening checks.

Passive by design: it only reads configuration files on disk, never touches a
network target, so it needs no scope gate. The goal is to catch the classic
"shipped with an insecure default" before it reaches production — an sshd that
still allows ``PermitRootLogin yes``, an nginx that leaks its version via
``server_tokens on`` or serves directory listings with ``autoindex on``.

Everything here is pure stdlib (re/pathlib/os) and failure-tolerant: an
unreadable, binary or oversized file is skipped, never fatal. Each finding
carries the offending ``file:line`` in both evidence and metadata so a human can
jump straight to it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ...core.context import RunContext
from ...core.finding import Finding, Severity
from ...core.module import Category, Intensity, Module

# Skip anything bigger than this — real config lives in modest text files, and
# reading multi-megabyte blobs just wastes time.
_MAX_FILE_BYTES = 1_000_000
# How much of a file we sniff to decide "is this binary?".
_SNIFF_BYTES = 1024

# Directories we never descend into when handed a directory target.
_SKIP_DIRS: frozenset[str] = frozenset(
    {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__"}
)


# --- config-type detection -------------------------------------------------
# Filenames / suffixes that strongly imply a given config type. Matching is done
# on the lower-cased file name.
def _detect_type(path: Path, text: str) -> str | None:
    """Return "nginx", "sshd", or None for *path* (name first, then content)."""
    name = path.name.lower()

    if name == "sshd_config" or name.startswith("sshd_config"):
        return "sshd"
    if name == "ssh_config" or name.startswith("ssh_config"):
        # Client config — not our target; skip to avoid false positives.
        return None
    if name == "nginx.conf" or name.endswith(".nginx") or name.endswith(".nginx.conf"):
        return "nginx"

    # Files that live inside an nginx tree (sites-available/enabled, conf.d) and
    # end in .conf are very likely nginx server blocks.
    parts = {p.lower() for p in path.parts}
    if name.endswith(".conf") and parts & {
        "sites-available",
        "sites-enabled",
        "conf.d",
        "nginx",
    }:
        return "nginx"

    # Fall back to sniffing the content for unambiguous directives.
    head = text[:4096]
    if re.search(r"(?mi)^\s*(server|http|location|upstream)\b", head) and re.search(
        r"(?mi)^\s*(listen|server_name|server_tokens|ssl_protocols)\b", head
    ):
        return "nginx"
    if re.search(
        r"(?mi)^\s*(PermitRootLogin|PasswordAuthentication|Subsystem|ChallengeResponseAuthentication)\b",
        head,
    ):
        return "sshd"
    return None


# --- rule model ------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class _Rule:
    config_type: str  # "nginx" or "sshd"
    name: str  # short, stable title fragment
    pattern: re.Pattern[str]  # matched per-line
    severity: Severity
    recommendation: str


def _nginx(value: str) -> str:
    """Build an nginx directive regex: ``<directive> ... <value> ...``.

    nginx directives are whitespace-separated and end in ``;``. We match the
    directive name followed anywhere before the terminating ``;`` by *value*
    (as a whole token), case-insensitively.
    """
    return value


# Each rule is matched against a single logical line. Deliberately a flat,
# ordered, extensible list: adding a check is a one-line change.
_RULES: list[_Rule] = [
    # ---- nginx -----------------------------------------------------------
    _Rule(
        "nginx",
        "server_tokens on (version disclosure)",
        re.compile(r"(?i)^\s*server_tokens\s+on\s*;"),
        Severity.LOW,
        "Set 'server_tokens off;' so nginx does not advertise its exact "
        "version in responses and error pages.",
    ),
    _Rule(
        "nginx",
        "autoindex on (directory listing)",
        re.compile(r"(?i)^\s*autoindex\s+on\s*;"),
        Severity.MEDIUM,
        "Set 'autoindex off;' (the default) to stop nginx from serving "
        "browsable directory listings that can expose sensitive files.",
    ),
    _Rule(
        "nginx",
        "ssl_protocols allows obsolete TLS",
        re.compile(r"(?i)^\s*ssl_protocols\b[^;]*\bTLSv1(?:\.1)?(?!\.\d)[^;]*;"),
        Severity.MEDIUM,
        "Remove TLSv1 and TLSv1.1 from ssl_protocols; allow only TLSv1.2 and "
        "TLSv1.3 (e.g. 'ssl_protocols TLSv1.2 TLSv1.3;').",
    ),
    _Rule(
        "nginx",
        "ssl_ciphers allows weak ciphers",
        re.compile(r"(?i)^\s*ssl_ciphers\b[^;]*\b(?:RC4|MD5|NULL|EXPORT|DES)\b[^;]*;"),
        Severity.MEDIUM,
        "Drop RC4/DES/MD5/NULL/EXPORT ciphers; use a modern cipher suite and "
        "'ssl_prefer_server_ciphers on;'.",
    ),
    # ---- sshd ------------------------------------------------------------
    _Rule(
        "sshd",
        "PermitRootLogin yes",
        re.compile(r"(?i)^\s*PermitRootLogin\s+yes\b"),
        Severity.HIGH,
        "Set 'PermitRootLogin no' (or 'prohibit-password'): never allow direct "
        "interactive root logins over SSH.",
    ),
    _Rule(
        "sshd",
        "PermitEmptyPasswords yes",
        re.compile(r"(?i)^\s*PermitEmptyPasswords\s+yes\b"),
        Severity.CRITICAL,
        "Set 'PermitEmptyPasswords no': accounts with empty passwords must "
        "never be reachable over SSH.",
    ),
    _Rule(
        "sshd",
        "PasswordAuthentication yes",
        re.compile(r"(?i)^\s*PasswordAuthentication\s+yes\b"),
        Severity.MEDIUM,
        "Prefer key-based auth: set 'PasswordAuthentication no' to eliminate "
        "password brute-force and credential-stuffing against SSH.",
    ),
    _Rule(
        "sshd",
        "Protocol 1 (legacy SSHv1)",
        re.compile(r"(?i)^\s*Protocol\s+(?:1\b|.*\b1\b)"),
        Severity.HIGH,
        "Remove 'Protocol 1': SSH protocol 1 is cryptographically broken. Use "
        "protocol 2 only (the modern default).",
    ),
    _Rule(
        "sshd",
        "X11Forwarding yes",
        re.compile(r"(?i)^\s*X11Forwarding\s+yes\b"),
        Severity.LOW,
        "Set 'X11Forwarding no' unless required: X11 forwarding widens the "
        "attack surface between client and server.",
    ),
]

# Security headers we like to see present in an nginx config. Their absence is
# only informational (they may legitimately live in an included file).
_NGINX_EXPECTED_HEADERS: tuple[tuple[str, str], ...] = (
    ("strict-transport-security", "Add HSTS to force HTTPS and prevent downgrade."),
    ("x-content-type-options", "Set 'X-Content-Type-Options: nosniff' to stop MIME sniffing."),
    ("x-frame-options", "Set X-Frame-Options (or CSP frame-ancestors) to prevent clickjacking."),
    ("content-security-policy", "Add a Content-Security-Policy to mitigate XSS."),
)


class ServerConfigAudit(Module):
    id = "config_audit.server_configs"
    name = "Server config linter (nginx/sshd)"
    category = Category.CONFIG_AUDIT
    intensity = Intensity.PASSIVE
    description = (
        "Lint local nginx and sshd configuration files for insecure directives "
        "(server_tokens, autoindex, weak TLS, PermitRootLogin, empty passwords, "
        "legacy protocols) using named regex rules."
    )

    async def run(self, ctx: RunContext) -> list[Finding]:
        root = Path((ctx.target or ".").strip() or ".").expanduser()
        findings: list[Finding] = []

        if not root.exists():
            return [
                ctx.finding(
                    self.id,
                    "Config target does not exist",
                    Severity.INFO,
                    description=f"Path {root!s} was not found; nothing to lint.",
                )
            ]

        base = root if root.is_dir() else root.parent
        files = [root] if root.is_file() else _walk(root)

        for path in files:
            text = _read_text(path)
            if text is None:
                continue
            ctype = _detect_type(path, text)
            if ctype is None:
                continue
            rel = _relpath(path, base)
            findings.extend(_lint(ctx, self.id, rel, ctype, text))

        return findings


# --- linting ---------------------------------------------------------------
def _lint(
    ctx: RunContext, module_id: str, rel: str, ctype: str, text: str
) -> list[Finding]:
    findings: list[Finding] = []
    rules = [r for r in _RULES if r.config_type == ctype]

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        for rule in rules:
            if not rule.pattern.search(line):
                continue
            findings.append(
                ctx.finding(
                    module_id,
                    f"{ctype}: {rule.name} in {rel}",
                    rule.severity,
                    description=(
                        f"Insecure {ctype} directive matching '{rule.name}' was "
                        f"found in {rel} at line {lineno}."
                    ),
                    evidence=f"{rel}:{lineno}: {line[:200]}",
                    recommendation=rule.recommendation,
                    metadata={
                        "file": rel,
                        "line": lineno,
                        "config_type": ctype,
                        "rule": rule.name,
                    },
                )
            )

    if ctype == "nginx":
        findings.extend(_missing_headers(ctx, module_id, rel, text))
    return findings


def _missing_headers(
    ctx: RunContext, module_id: str, rel: str, text: str
) -> list[Finding]:
    """INFO-level note for common security headers not declared anywhere.

    Only emitted when the config actually looks like it terminates TLS / serves
    responses (it has a ``listen`` directive), to avoid noise on pure upstream
    or helper snippets.
    """
    lowered = text.lower()
    if "listen" not in lowered:
        return []
    out: list[Finding] = []
    for header, rec in _NGINX_EXPECTED_HEADERS:
        if header in lowered:
            continue
        out.append(
            ctx.finding(
                module_id,
                f"nginx: missing security header '{header}' in {rel}",
                Severity.INFO,
                description=(
                    f"No 'add_header {header}' directive was found in {rel}. "
                    "It may be set in an included file; verify it is present."
                ),
                evidence=f"{rel}: '{header}' not declared",
                recommendation=rec,
                metadata={"file": rel, "config_type": "nginx", "missing_header": header},
            )
        )
    return out


# --- filesystem ------------------------------------------------------------
def _walk(root: Path):
    """Yield candidate files under *root*, pruning skip-dirs."""
    import os

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            yield Path(dirpath) / fname


def _relpath(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def _read_text(path: Path) -> str | None:
    """Return the text of *path*, or None if it should be skipped.

    Never raises: anything unreadable/odd/binary/oversized is skipped.
    """
    try:
        if not path.is_file() or path.is_symlink():
            return None
        size = path.stat().st_size
        if size == 0 or size > _MAX_FILE_BYTES:
            return None
        with path.open("rb") as fh:
            head = fh.read(_SNIFF_BYTES)
        if b"\x00" in head:  # binary heuristic: NUL byte in the first KB
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return None
