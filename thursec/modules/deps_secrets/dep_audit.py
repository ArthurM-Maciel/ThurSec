"""Dependency audit — check a project's pinned Python deps against OSV.

Passive by design: it reads dependency manifests on disk (``requirements*.txt``
and ``pyproject.toml``) and queries the public, free, no-auth OSV database
(https://osv.dev) for known vulnerabilities. It never touches the audited
project's own infrastructure and needs no scope gate — the only network call is
to osv.dev, a public vulnerability index.

Everything is pure stdlib (os/pathlib/re/json/urllib, plus ``tomllib`` on 3.11+)
and failure-tolerant: an unreadable manifest, a malformed line, or a network
error becomes a handled finding, never an unhandled exception.

The OSV HTTP layer lives in :meth:`DepAudit._query_osv`, isolated so tests can
replace it with canned responses — no network needed in CI.
"""

from __future__ import annotations

import asyncio
import json
import re
import urllib.error
import urllib.request
from pathlib import Path

from ...core.context import RunContext
from ...core.finding import Finding, Severity
from ...core.module import Category, Intensity, Module

try:  # stdlib on 3.11+; requires-python is >=3.11 so this is expected to exist.
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - defensive for <3.11.
    tomllib = None  # type: ignore[assignment]

_OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_OSV_ECOSYSTEM = "PyPI"
_OSV_VULN_URL = "https://osv.dev/vulnerability/"
_USER_AGENT = "ThurSec/0.1"
_TIMEOUT = 20
# Cap how many distinct packages we query so a huge lockfile can't blow up a run.
_MAX_PACKAGES = 200

# A requirement line with an exact pin: ``name==1.2.3`` (extras/markers stripped).
# Only ``==`` is resolvable to a single version; ``>=``, ``~=`` etc. are not.
_PINNED_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;#,]+)"
)
# Any requirement that names a package but is NOT an exact pin -> reported INFO.
_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
# Ordered map from OSV textual severity labels to our Severity scale.
_SEVERITY_WORDS: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class DepAudit(Module):
    id = "deps_secrets.dep_audit"
    name = "Dependency audit (OSV)"
    category = Category.DEPS_SECRETS
    intensity = Intensity.PASSIVE
    description = (
        "Parse a project's Python dependency manifests (requirements*.txt, "
        "pyproject.toml) and check each pinned package against the public OSV "
        "vulnerability database. Flags known-vulnerable versions and unpinned "
        "dependencies. Passive: reads files locally and queries osv.dev only."
    )

    async def run(self, ctx: RunContext) -> list[Finding]:
        root = Path(str(ctx.target).strip() or ".").expanduser()
        findings: list[Finding] = []

        if not root.exists():
            return [
                ctx.finding(
                    self.id,
                    "Audit target does not exist",
                    Severity.INFO,
                    description=f"Path {root!s} was not found; nothing to audit.",
                )
            ]

        base = root if root.is_dir() else root.parent
        manifests = _find_manifests(root)
        if not manifests:
            return [
                ctx.finding(
                    self.id,
                    "No Python dependency manifests found",
                    Severity.INFO,
                    description=(
                        "No requirements*.txt or pyproject.toml was found under "
                        f"{base!s}; there are no Python dependencies to audit."
                    ),
                )
            ]

        # Keyed by (canonical name, version) for dedup; value keeps the manifest
        # it came from and the name as the user actually wrote it.
        pinned: dict[tuple[str, str], tuple[str, str]] = {}
        for manifest in manifests:
            rel = _relpath(manifest, base)
            try:
                deps, unpinned = _parse_manifest(manifest)
            except Exception as e:  # defensive: parsing never aborts the module.
                findings.append(
                    ctx.finding(
                        self.id,
                        f"Could not parse manifest {rel}",
                        Severity.LOW,
                        description=(
                            "The dependency manifest could not be parsed; its "
                            "packages were not audited."
                        ),
                        evidence=f"{type(e).__name__}: {e}",
                        metadata={"manifest": rel},
                    )
                )
                continue
            for name, version in deps:
                # First manifest that pins a (name, version) wins the attribution.
                pinned.setdefault((_canon(name), version), (rel, name))
            for name in unpinned:
                findings.append(
                    ctx.finding(
                        self.id,
                        f"Unpinned dependency '{name}' in {rel}",
                        Severity.INFO,
                        description=(
                            f"'{name}' is declared without an exact version (=="
                            "), so it cannot be resolved to a single version and "
                            "was not checked against OSV."
                        ),
                        recommendation=(
                            "Pin dependencies to exact versions (e.g. in a lock "
                            "file) so they can be audited and builds are "
                            "reproducible."
                        ),
                        metadata={"manifest": rel, "package": name},
                    )
                )

        if not pinned:
            findings.append(
                ctx.finding(
                    self.id,
                    "No pinned dependencies to audit",
                    Severity.INFO,
                    description=(
                        "Manifests were found but none pinned a package to an "
                        "exact version, so nothing was queried against OSV."
                    ),
                )
            )
            return findings

        audited = 0
        vulnerable = 0
        for (_canon_name, version), (rel, name) in list(pinned.items())[:_MAX_PACKAGES]:
            audited += 1
            try:
                vulns = await asyncio.to_thread(self._query_osv, name, version)
            except Exception as e:
                findings.append(
                    ctx.finding(
                        self.id,
                        f"OSV query failed for {name} {version}",
                        Severity.LOW,
                        description=(
                            "The OSV lookup did not complete, so this package "
                            "could not be checked for known vulnerabilities."
                        ),
                        evidence=f"{type(e).__name__}: {e}",
                        recommendation="Retry with network access to osv.dev.",
                        metadata={"manifest": rel, "package": name, "version": version},
                    )
                )
                continue
            for vuln in vulns:
                vulnerable += 1
                findings.append(_vuln_finding(ctx, self.id, name, version, rel, vuln))

        if vulnerable == 0:
            findings.append(
                ctx.finding(
                    self.id,
                    "No known-vulnerable dependencies found",
                    Severity.INFO,
                    description=(
                        f"Audited {audited} pinned package(s) against OSV; none "
                        "match a known vulnerability."
                    ),
                    metadata={"packages_audited": audited},
                )
            )
        return findings

    # --- isolable OSV HTTP layer (monkeypatched in tests) ------------------
    def _query_osv(self, name: str, version: str) -> list[dict]:
        """Query OSV for one (package, version). Return a list of vuln dicts.

        Isolated so tests replace it with canned data — no network. Blocking;
        callers wrap it in ``asyncio.to_thread``.
        """
        payload = json.dumps(
            {
                "version": version,
                "package": {"name": name, "ecosystem": _OSV_ECOSYSTEM},
            }
        ).encode()
        req = urllib.request.Request(
            _OSV_QUERY_URL,
            method="POST",
            data=payload,
            headers={
                "User-Agent": _USER_AGENT,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        doc = json.loads(raw) if raw else {}
        vulns = doc.get("vulns") if isinstance(doc, dict) else None
        return [v for v in vulns if isinstance(v, dict)] if isinstance(vulns, list) else []


# --- manifest discovery & parsing ------------------------------------------
def _find_manifests(root: Path) -> list[Path]:
    """Return the dependency manifests to parse.

    If *root* is a file, audit just that file. If it's a directory, pick up
    ``requirements*.txt`` and ``pyproject.toml`` at its top level.
    """
    if root.is_file():
        return [root]
    found: list[Path] = []
    try:
        for entry in sorted(root.iterdir()):
            if not entry.is_file():
                continue
            n = entry.name
            if n == "pyproject.toml" or (
                n.startswith("requirements") and n.endswith(".txt")
            ):
                found.append(entry)
    except OSError:
        return []
    return found


def _parse_manifest(path: Path) -> tuple[list[tuple[str, str]], list[str]]:
    """Return (pinned, unpinned) for one manifest.

    ``pinned`` is a list of (name, version); ``unpinned`` a list of package
    names declared without an exact ``==`` pin.
    """
    if path.name == "pyproject.toml":
        return _parse_pyproject(path)
    return _parse_requirements(path)


def _parse_requirements(path: Path) -> tuple[list[tuple[str, str]], list[str]]:
    pinned: list[tuple[str, str]] = []
    unpinned: list[str] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            # Skip blanks, comments, and pip options (-r, -e, --hash, ...).
            continue
        _classify(line, pinned, unpinned)
    return pinned, unpinned


def _parse_pyproject(path: Path) -> tuple[list[tuple[str, str]], list[str]]:
    pinned: list[tuple[str, str]] = []
    unpinned: list[str] = []
    if tomllib is None:  # pragma: no cover - 3.11+ guaranteed by requires-python.
        return pinned, unpinned
    with path.open("rb") as fh:
        doc = tomllib.load(fh)

    specs: list[str] = []
    project = doc.get("project")
    if isinstance(project, dict):
        deps = project.get("dependencies")
        if isinstance(deps, list):
            specs.extend(d for d in deps if isinstance(d, str))
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group in optional.values():
                if isinstance(group, list):
                    specs.extend(d for d in group if isinstance(d, str))

    for spec in specs:
        _classify(spec, pinned, unpinned)
    return pinned, unpinned


def _classify(
    spec: str, pinned: list[tuple[str, str]], unpinned: list[str]
) -> None:
    """Sort one requirement spec into the pinned or unpinned bucket."""
    m = _PINNED_RE.match(spec)
    if m:
        pinned.append((m.group(1), m.group(2).strip()))
        return
    name_m = _NAME_RE.match(spec)
    if name_m:
        unpinned.append(name_m.group(1))


def _canon(name: str) -> str:
    """PEP 503 normalisation so 'Flask' and 'flask' hit the same OSV record."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _relpath(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


# --- finding construction --------------------------------------------------
def _vuln_finding(
    ctx: RunContext,
    module_id: str,
    name: str,
    version: str,
    manifest: str,
    vuln: dict,
) -> Finding:
    osv_id = str(vuln.get("id") or "UNKNOWN")
    summary = str(vuln.get("summary") or vuln.get("details") or "").strip()
    severity = _derive_severity(vuln)
    aliases = [a for a in vuln.get("aliases", []) if isinstance(a, str)]
    references = _references(vuln, osv_id)

    evidence_parts = [f"{name}=={version} is affected by {osv_id}"]
    if aliases:
        evidence_parts.append("aliases: " + ", ".join(aliases))
    if summary:
        evidence_parts.append(_truncate(summary, 300))

    return ctx.finding(
        module_id,
        f"Vulnerable dependency {name} {version} ({osv_id})",
        severity,
        description=(
            summary
            or f"OSV lists {osv_id} as affecting {name} {version}. See the "
            "referenced advisory for details."
        ),
        evidence="\n".join(evidence_parts),
        recommendation=(
            "Upgrade to a fixed version listed in the OSV advisory, or apply the "
            "vendor's mitigation. Re-run the audit to confirm the fix."
        ),
        references=references,
        metadata={
            "manifest": manifest,
            "package": name,
            "version": version,
            "osv_id": osv_id,
            "aliases": aliases,
        },
    )


def _derive_severity(vuln: dict) -> Severity:
    """Best-effort severity from OSV data; defaults to HIGH when unknown.

    Order of preference: a textual label in ``database_specific.severity``, then
    a CVSS score, then a conservative HIGH default (a published advisory match
    is never merely informational).
    """
    dbs = vuln.get("database_specific")
    if isinstance(dbs, dict):
        word = str(dbs.get("severity") or "").strip().upper()
        if word in _SEVERITY_WORDS:
            return _SEVERITY_WORDS[word]

    score = _cvss_score(vuln.get("severity"))
    if score is not None:
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score > 0.0:
            return Severity.LOW
    return Severity.HIGH


def _cvss_score(severity: object) -> float | None:
    """Pull a numeric base score out of an OSV ``severity`` list if present."""
    if not isinstance(severity, list):
        return None
    for entry in severity:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("score")
        if raw is None:
            continue
        try:
            return float(raw)
        except (TypeError, ValueError):
            # CVSS vector strings (not a plain number) are ignored here.
            continue
    return None


def _references(vuln: dict, osv_id: str) -> list[str]:
    urls: list[str] = []
    refs = vuln.get("references")
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, dict) and isinstance(ref.get("url"), str):
                urls.append(ref["url"])
    link = f"{_OSV_VULN_URL}{osv_id}"
    if link not in urls:
        urls.insert(0, link)
    return urls


def _truncate(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
