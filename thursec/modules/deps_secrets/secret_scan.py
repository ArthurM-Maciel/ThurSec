"""Local secret scanner — grep a repo/directory for leaked credentials.

Passive by design: it only reads files on disk, never touches a network target,
so it needs no scope gate. The goal is to catch the classic "oops, committed an
API key" before it ships — AWS keys, private keys, cloud/API tokens, JWTs, and
generic high-entropy ``secret = "..."`` assignments.

Everything here is pure stdlib (os/pathlib/re/math) and failure-tolerant: an
unreadable or binary file is skipped, never fatal. Evidence is always redacted
so running the scanner doesn't itself write the secret into a report.
"""

from __future__ import annotations

import math
import re
from pathlib import Path

from ...core.context import RunContext
from ...core.finding import Finding, Severity
from ...core.module import Category, Intensity, Module

# Directories we never descend into: VCS metadata, vendored deps, build output,
# virtualenvs, caches. Scanning them is slow and all noise.
_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "env",
        "dist",
        "build",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
        ".idea",
        ".gradle",
        "target",
        "vendor",
    }
)

# Skip anything bigger than this — real secrets live in config/source, not in
# multi-megabyte blobs, and reading them just wastes time.
_MAX_FILE_BYTES = 1_000_000
# How much of a file we sniff to decide "is this binary?".
_SNIFF_BYTES = 1024

# --- detection rules -------------------------------------------------------
# Each rule: (name, compiled regex, severity). Deliberately a flat, ordered list
# so adding a new credential type is a one-line change. Group 1 (when present)
# is the sensitive value used for redaction; otherwise the whole match is used.
_RULES: list[tuple[str, re.Pattern[str], Severity]] = [
    (
        "AWS Access Key ID",
        re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16})\b"),
        Severity.HIGH,
    ),
    (
        "AWS Secret Access Key",
        re.compile(
            r"(?i)aws(.{0,20})?(secret|private)(.{0,20})?['\"]([A-Za-z0-9/+=]{40})['\"]"
        ),
        Severity.CRITICAL,
    ),
    (
        "Private Key (PEM)",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
    (
        "Google API Key",
        re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        Severity.HIGH,
    ),
    (
        "Slack Token",
        re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b"),
        Severity.HIGH,
    ),
    (
        "GitHub Token",
        re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36})\b"),
        Severity.HIGH,
    ),
    (
        "Slack Webhook URL",
        re.compile(r"(https://hooks\.slack\.com/services/[A-Za-z0-9/]+)"),
        Severity.HIGH,
    ),
    (
        "JSON Web Token (JWT)",
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
        Severity.HIGH,
    ),
    (
        "Generic high-entropy secret",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|passwd|password|access[_-]?key|"
            r"client[_-]?secret|auth)\b\s*[:=]\s*['\"]([^'\"]{16,})['\"]"
        ),
        Severity.HIGH,
    ),
]

# For the generic rule we require real randomness to cut false positives such as
# ``password = "changeme-in-production"``.
_MIN_ENTROPY_BITS = 3.5
_GENERIC_RULE_NAME = "Generic high-entropy secret"


class SecretScan(Module):
    id = "deps_secrets.secret_scan"
    name = "Local secret scan"
    category = Category.DEPS_SECRETS
    intensity = Intensity.PASSIVE
    description = (
        "Recursively scan a local directory/repo for leaked credentials "
        "(API keys, tokens, private keys) using named regex rules."
    )

    async def run(self, ctx: RunContext) -> list[Finding]:
        root = Path(ctx.target.strip() or ".").expanduser()
        findings: list[Finding] = []

        if not root.exists():
            findings.append(
                ctx.finding(
                    self.id,
                    "Scan target does not exist",
                    Severity.INFO,
                    description=f"Path {root!s} was not found; nothing to scan.",
                )
            )
            return findings

        base = root if root.is_dir() else root.parent
        files = [root] if root.is_file() else _walk(root)

        for path in files:
            for lineno, line, name, value, sev in _scan_file(path):
                rel = _relpath(path, base)
                findings.append(
                    ctx.finding(
                        self.id,
                        f"Possible {name} in {rel}",
                        sev,
                        description=(
                            f"A string matching '{name}' was found in {rel} "
                            f"at line {lineno}."
                        ),
                        evidence=_redact_line(line, value),
                        recommendation=(
                            "Revoke/rotate the credential immediately, remove it "
                            "from the file, and purge it from version-control "
                            "history (e.g. git filter-repo / BFG). Store secrets "
                            "in a secrets manager or environment, never in code."
                        ),
                        metadata={"file": rel, "line": lineno, "rule": name},
                    )
                )
        return findings


# --- filesystem walk -------------------------------------------------------
def _walk(root: Path):
    """Yield candidate files under *root*, pruning skip-dirs and junk."""
    import os

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune in place so os.walk never descends into skipped trees.
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            yield Path(dirpath) / fname


def _relpath(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


# --- per-file scanning -----------------------------------------------------
def _scan_file(path: Path):
    """Yield (lineno, line, rule_name, value, severity) for each match.

    Never raises: anything unreadable/odd about the file ends the generator.
    """
    try:
        if not path.is_file() or path.is_symlink():
            return
        size = path.stat().st_size
        if size == 0 or size > _MAX_FILE_BYTES:
            return
        with path.open("rb") as fh:
            head = fh.read(_SNIFF_BYTES)
        if b"\x00" in head:  # binary heuristic: NUL byte in the first KB
            return
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return

    for lineno, line in enumerate(text.splitlines(), start=1):
        for name, pattern, sev in _RULES:
            m = pattern.search(line)
            if not m:
                continue
            value = m.group(m.lastindex) if m.lastindex else m.group(0)
            if name == _GENERIC_RULE_NAME and _entropy(value) < _MIN_ENTROPY_BITS:
                continue
            yield lineno, line, name, value, sev


# --- helpers ---------------------------------------------------------------
def _entropy(s: str) -> float:
    """Shannon entropy (bits/char). Random tokens score high, words low."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _redact_line(line: str, value: str) -> str:
    """Return *line* with *value* masked, keeping only a short head/tail.

    e.g. ``AKIAIOSFODNN7EXAMPLE`` -> ``AKIA************MPLE`` — enough to locate
    the secret, never enough to use it.
    """
    line = line.strip()
    if not value:
        return line[:200]
    redacted = _mask(value)
    return line.replace(value, redacted)[:200]


def _mask(value: str) -> str:
    n = len(value)
    if n <= 8:
        # Too short to safely show any of it.
        return "*" * n
    head = value[:4]
    tail = value[-4:]
    return f"{head}{'*' * (n - 8)}{tail}"
