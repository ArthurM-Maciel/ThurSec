"""Dependency audit — check a project's pinned deps against OSV.

Covers two ecosystems, because a real project is rarely only one: Python
(``requirements*.txt``, ``pyproject.toml``) and npm (``package-lock.json``,
with ``package.json`` reported as unpinned since its ranges cannot be resolved
to a single version). OSV indexes both behind the same API — only the
``ecosystem`` field changes — so adding npm is a parser plus a constant.

Passive by design: it reads dependency manifests on disk and queries the
public, free, no-auth OSV database
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

from ... import __version__
from ...core.context import RunContext
from ...core.finding import Finding, Severity
from ...core.i18n import L, Lf
from ...core.module import Category, Intensity, Module

try:  # stdlib on 3.11+; requires-python is >=3.11 so this is expected to exist.
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - defensive for <3.11.
    tomllib = None  # type: ignore[assignment]

_OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_ECOSYSTEM_PYPI = "PyPI"
_ECOSYSTEM_NPM = "npm"
_OSV_ECOSYSTEM = _ECOSYSTEM_PYPI  # padrão, mantido para compatibilidade
_OSV_VULN_URL = "https://osv.dev/vulnerability/"
_USER_AGENT = f"ThurSec/{__version__}"
_TIMEOUT = 20
# Cap how many distinct packages we query so a huge lockfile can't blow up a run.
_MAX_PACKAGES = 200
# Consultas simultâneas à OSV. Pública e gratuita: paralelizar sim, martelar não.
_CONCURRENCY = 8
# Lockfiles do npm e equivalentes. Só o do npm é parseado hoje, mas a presença
# de qualquer um deles significa que o projeto FIXA versões — então as faixas do
# package.json não são "dependência não fixada" e avisar seria conselho errado.
_NPM_LOCKFILES = frozenset({"package-lock.json", "yarn.lock", "pnpm-lock.yaml"})

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
    name = L("Auditoria de dependências (OSV)", "Dependency audit (OSV)")
    category = Category.DEPS_SECRETS
    intensity = Intensity.PASSIVE
    description = L(
        "Analisa os manifestos de dependências de um projeto — Python "
        "(requirements*.txt, pyproject.toml) e npm (package-lock.json, "
        "package.json) — e verifica cada pacote fixado contra a base pública "
        "de vulnerabilidades OSV. Sinaliza versões sabidamente vulneráveis e "
        "dependências não fixadas. Passivo: lê arquivos localmente e consulta "
        "apenas osv.dev.",
        "Parse a project's dependency manifests — Python (requirements*.txt, "
        "pyproject.toml) and npm (package-lock.json, package.json) — and check "
        "each pinned package against the public OSV vulnerability database. "
        "Flags known-vulnerable versions and unpinned dependencies. Passive: "
        "reads files locally and queries osv.dev only.",
    )

    async def run(self, ctx: RunContext) -> list[Finding]:
        root = Path(str(ctx.target).strip() or ".").expanduser()
        findings: list[Finding] = []

        if not root.exists():
            return [
                ctx.finding(
                    self.id,
                    L("Alvo de auditoria não existe", "Audit target does not exist"),
                    Severity.INFO,
                    description=Lf(
                        "O caminho {root} não foi encontrado; nada a auditar.",
                        "Path {root} was not found; nothing to audit.",
                        root=str(root),
                    ),
                )
            ]

        base = root if root.is_dir() else root.parent
        manifests = _find_manifests(root)
        if not manifests:
            return [
                ctx.finding(
                    self.id,
                    L(
                        "Nenhum manifesto de dependências encontrado",
                        "No dependency manifests found",
                    ),
                    Severity.INFO,
                    description=Lf(
                        "Nenhum requirements*.txt, pyproject.toml, "
                        "package-lock.json ou package.json foi encontrado em "
                        "{base}; não há dependências a auditar.",
                        "No requirements*.txt, pyproject.toml, package-lock.json or "
                        "package.json was found under {base}; there are no "
                        "dependencies to audit.",
                        base=str(base),
                    ),
                )
            ]

        # Keyed by (ecosystem, canonical name, version) for dedup; the value
        # keeps the manifest it came from and the name as the user wrote it.
        pinned: dict[tuple[str, str, str], tuple[str, str]] = {}
        # Um package.json ao lado de um package-lock.json não tem dependência
        # "não fixada": faixas no manifesto mais um lock é a prática correta do
        # npm, e o lock já resolve cada uma para uma versão exata. Avisar ali
        # seria conselho errado — e eram 27 achados num projeto pequeno.
        locked_dirs = {
            m.parent for m in manifests if m.name in _NPM_LOCKFILES
        }

        for manifest in manifests:
            rel = _relpath(manifest, base)
            ecosystem = _ecosystem_for(manifest)
            if manifest.name == "package.json" and manifest.parent in locked_dirs:
                continue
            try:
                deps, unpinned = _parse_manifest(manifest)
            except Exception as e:  # defensive: parsing never aborts the module.
                findings.append(
                    ctx.finding(
                        self.id,
                        L(
                            f"Não foi possível analisar o manifesto {rel}",
                            f"Could not parse manifest {rel}",
                        ),
                        Severity.LOW,
                        description=L(
                            "O manifesto de dependências não pôde ser analisado; "
                            "seus pacotes não foram auditados.",
                            "The dependency manifest could not be parsed; its "
                            "packages were not audited.",
                        ),
                        evidence=f"{type(e).__name__}: {e}",
                        metadata={"manifest": rel},
                    )
                )
                continue
            for name, version in deps:
                # First manifest that pins a (name, version) wins the attribution.
                key = (ecosystem, _canon(name, ecosystem), version)
                pinned.setdefault(key, (rel, name))
            for name in unpinned:
                findings.append(
                    ctx.finding(
                        self.id,
                        L(
                            f"Dependência não fixada '{name}' em {rel}",
                            f"Unpinned dependency '{name}' in {rel}",
                        ),
                        Severity.INFO,
                        description=L(
                            f"'{name}' é declarada sem uma versão exata (==), "
                            "então não pode ser resolvida para uma única versão e "
                            "não foi verificada contra a OSV.",
                            f"'{name}' is declared without an exact version (=="
                            "), so it cannot be resolved to a single version and "
                            "was not checked against OSV.",
                        ),
                        recommendation=L(
                            "Fixe as dependências em versões exatas (ex.: em um "
                            "lock file) para que possam ser auditadas e os builds "
                            "sejam reproduzíveis.",
                            "Pin dependencies to exact versions (e.g. in a lock "
                            "file) so they can be audited and builds are "
                            "reproducible.",
                        ),
                        metadata={"manifest": rel, "package": name},
                    )
                )

        if not pinned:
            findings.append(
                ctx.finding(
                    self.id,
                    L(
                        "Nenhuma dependência fixada para auditar",
                        "No pinned dependencies to audit",
                    ),
                    Severity.INFO,
                    description=L(
                        "Manifestos foram encontrados, mas nenhum fixou um pacote "
                        "em uma versão exata, então nada foi consultado contra a "
                        "OSV.",
                        "Manifests were found but none pinned a package to an "
                        "exact version, so nothing was queried against OSV.",
                    ),
                )
            )
            return findings

        cap = _coerce_cap(ctx.options.get("max_packages"))
        if len(pinned) > cap:
            findings.append(
                ctx.finding(
                    self.id,
                    Lf(
                        "Auditoria parcial: {n} de {total} pacotes verificados",
                        "Partial audit: {n} of {total} packages checked",
                        n=cap,
                        total=len(pinned),
                    ),
                    Severity.LOW,
                    description=Lf(
                        "O projeto fixa {total} pacotes e o teto desta execução "
                        "é {n}, então {resto} não foram consultados. Uma "
                        "auditoria incompleta apresentada como completa é pior "
                        "que nenhuma.",
                        "The project pins {total} packages and this run is "
                        "capped at {n}, so {resto} were not queried. An "
                        "incomplete audit presented as complete is worse than "
                        "none.",
                        total=len(pinned),
                        n=cap,
                        resto=len(pinned) - cap,
                    ),
                    recommendation=L(
                        "Aumente o teto com "
                        "--opt deps_secrets.dep_audit.max_packages=<n>.",
                        "Raise the cap with "
                        "--opt deps_secrets.dep_audit.max_packages=<n>.",
                    ),
                    metadata={"pinned": len(pinned), "cap": cap},
                )
            )

        # As consultas são independentes entre si, então vão em paralelo com um
        # teto de concorrência: um lockfile tem centenas de pacotes e, em série,
        # uma landing page levava mais de dois minutos. O teto existe para não
        # martelar uma API pública e gratuita.
        alvos = [
            (rel, name, version, ecosystem)
            for (ecosystem, _c, version), (rel, name) in list(pinned.items())[:cap]
        ]
        gate = asyncio.Semaphore(_CONCURRENCY)

        async def consultar(name: str, version: str, ecosystem: str):
            async with gate:
                return await asyncio.to_thread(
                    self._query_osv, name, version, ecosystem
                )

        resultados = await asyncio.gather(
            *(consultar(n, v, e) for _rel, n, v, e in alvos),
            return_exceptions=True,
        )

        audited = 0
        vulnerable = 0
        for (rel, name, version, _eco), vulns in zip(alvos, resultados):
            audited += 1
            if isinstance(vulns, BaseException):
                findings.append(
                    ctx.finding(
                        self.id,
                        L(
                            f"Consulta OSV falhou para {name} {version}",
                            f"OSV query failed for {name} {version}",
                        ),
                        Severity.LOW,
                        description=L(
                            "A consulta à OSV não foi concluída, então este pacote "
                            "não pôde ser verificado quanto a vulnerabilidades "
                            "conhecidas.",
                            "The OSV lookup did not complete, so this package "
                            "could not be checked for known vulnerabilities.",
                        ),
                        evidence=f"{type(vulns).__name__}: {vulns}",
                        recommendation=L(
                            "Tente novamente com acesso de rede ao osv.dev.",
                            "Retry with network access to osv.dev.",
                        ),
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
                    L(
                        "Nenhuma dependência sabidamente vulnerável encontrada",
                        "No known-vulnerable dependencies found",
                    ),
                    Severity.INFO,
                    description=Lf(
                        "Auditou {audited} pacote(s) fixado(s) contra a OSV; "
                        "nenhum corresponde a uma vulnerabilidade conhecida.",
                        "Audited {audited} pinned package(s) against OSV; none "
                        "match a known vulnerability.",
                        audited=audited,
                    ),
                    metadata={"packages_audited": audited},
                )
            )
        return findings

    # --- isolable OSV HTTP layer (monkeypatched in tests) ------------------
    def _query_osv(
        self, name: str, version: str, ecosystem: str = _OSV_ECOSYSTEM
    ) -> list[dict]:
        """Query OSV for one (package, version). Return a list of vuln dicts.

        Isolated so tests replace it with canned data — no network. Blocking;
        callers wrap it in ``asyncio.to_thread``.
        """
        payload = json.dumps(
            {
                "version": version,
                "package": {"name": name, "ecosystem": ecosystem},
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
    ``requirements*.txt``, ``pyproject.toml``, ``package-lock.json`` and
    ``package.json`` at its top level.

    ``package.json`` is collected even when a lock file is present, but the
    caller skips parsing it in that case: the lock already carries the exact
    versions, and the ranges in ``package.json`` are not "unpinned" when a lock
    sits beside them.
    """
    if root.is_file():
        return [root]
    found: list[Path] = []
    try:
        for entry in sorted(root.iterdir()):
            if not entry.is_file():
                continue
            n = entry.name
            if (
                n in ("pyproject.toml", "package.json")
                or n in _NPM_LOCKFILES
                or (n.startswith("requirements") and n.endswith(".txt"))
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
    if path.name == "package-lock.json":
        return _parse_package_lock(path)
    if path.name in _NPM_LOCKFILES:
        # yarn.lock e pnpm-lock.yaml não são JSON e ainda não têm parser. São
        # coletados só como sinal de que o projeto fixa versões; parseá-los como
        # requirements.txt produziria lixo.
        return [], []
    if path.name == "package.json":
        return _parse_package_json(path)
    return _parse_requirements(path)


def _coerce_cap(value: object) -> int:
    """Teto de pacotes a consultar, a partir de --opt max_packages."""
    if isinstance(value, bool):
        return _MAX_PACKAGES
    try:
        n = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return _MAX_PACKAGES
    return n if n > 0 else _MAX_PACKAGES


def _ecosystem_for(path: Path) -> str:
    """Which OSV ecosystem a manifest belongs to."""
    if path.name == "package.json" or path.name in _NPM_LOCKFILES:
        return _ECOSYSTEM_NPM
    return _ECOSYSTEM_PYPI


def _parse_package_lock(path: Path) -> tuple[list[tuple[str, str]], list[str]]:
    """Exact versions from an npm lock file (lockfileVersion 1, 2 and 3)."""
    doc = json.loads(path.read_text(encoding="utf-8", errors="replace") or "{}")
    pinned: list[tuple[str, str]] = []

    # v2/v3: a flat "packages" map keyed by install path.
    packages = doc.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not key or not isinstance(meta, dict):
                continue  # "" is the project itself
            if "node_modules/" not in key:
                # Um membro de workspace num monorepo é indexado pelo próprio
                # diretório ("packages/api"). Não é release pública: consultar
                # a OSV por esse nome dá falso positivo por colisão, manda um
                # caminho como nome de pacote, e gasta vaga sob o teto.
                continue
            if meta.get("link") is True:  # workspace symlink, not a release
                continue
            name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
            version = meta.get("version")
            if isinstance(name, str) and isinstance(version, str) and version:
                pinned.append((name, version))

    # v1: a nested "dependencies" tree.
    def walk(tree: object) -> None:
        if not isinstance(tree, dict):
            return
        for name, meta in tree.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if isinstance(version, str) and version:
                pinned.append((name, version))
            walk(meta.get("dependencies"))

    if not packages:
        walk(doc.get("dependencies"))

    return pinned, []


def _parse_package_json(path: Path) -> tuple[list[tuple[str, str]], list[str]]:
    """npm ranges cannot resolve to one version, so everything is 'unpinned'.

    Reported rather than guessed: '^4.4.1' installs whatever is newest in the
    range, so auditing the literal string would check a version that may not be
    the one deployed. The lock file is what carries the truth.
    """
    doc = json.loads(path.read_text(encoding="utf-8", errors="replace") or "{}")
    unpinned: list[str] = []
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        block = doc.get(field)
        if isinstance(block, dict):
            unpinned.extend(str(n) for n in block)
    return [], unpinned


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


def _canon(name: str, ecosystem: str = _ECOSYSTEM_PYPI) -> str:
    """Normalise a package name for dedup, per ecosystem.

    PEP 503 folds ``-``, ``_`` and ``.`` together so 'Flask' and 'flask' hit the
    same OSV record. npm must **not** be folded that way: ``-`` and ``_`` are
    distinct characters in a package name there, and scoped names carry a ``/``.
    """
    if ecosystem == _ECOSYSTEM_NPM:
        return name
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
        L(
            f"Dependência vulnerável {name} {version} ({osv_id})",
            f"Vulnerable dependency {name} {version} ({osv_id})",
        ),
        severity,
        description=(
            summary
            or L(
                f"A OSV lista {osv_id} como afetando {name} {version}. Veja o "
                "aviso referenciado para detalhes.",
                f"OSV lists {osv_id} as affecting {name} {version}. See the "
                "referenced advisory for details.",
            )
        ),
        evidence="\n".join(evidence_parts),
        recommendation=L(
            "Atualize para uma versão corrigida listada no aviso da OSV, ou "
            "aplique a mitigação do fornecedor. Rode a auditoria de novo para "
            "confirmar a correção.",
            "Upgrade to a fixed version listed in the OSV advisory, or apply the "
            "vendor's mitigation. Re-run the audit to confirm the fix.",
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
