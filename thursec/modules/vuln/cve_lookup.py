"""CVE lookup by product/version fingerprint against the public NVD database.

Passive by design: given a product name (and optionally a version) it asks the
National Vulnerability Database REST API 2.0 which published CVEs mention that
product. It sends **nothing** to the target itself — the only network call is to
services.nvd.nist.gov, NIST's free, public, no-auth vulnerability index (rate
limited without an API key, which is fine for our purposes). That is why this
module is PASSIVE and needs no scope gate.

Input comes from ``ctx.options`` (``product``/``version``) or, failing that, is
parsed out of ``ctx.target`` as ``"product"`` or ``"product:version"`` (e.g.
``"nginx:1.18.0"``). With no product we emit a single INFO finding explaining
how to use the module.

When a version is supplied we do a best-effort match against each CVE's CPE
version ranges: a CVE whose range covers the version is reported with
``confidence=confirmed``; one with no usable range data is reported as a
``potential`` exposure at a reduced confidence; and a CVE whose ranges exist but
exclude the version is dropped. We never claim exploitation — only *potential*
exposure worth investigating.

Everything is pure stdlib (urllib/json) and failure-tolerant: a network or parse
error becomes a handled finding, never an unhandled exception. The NVD HTTP
layer lives in :meth:`CveLookup._query_nvd`, isolated so tests swap in canned
responses — no network needed in CI.
"""

from __future__ import annotations

import asyncio
import json
import urllib.parse
import urllib.request

from ...core.context import RunContext
from ...core.finding import Finding, Severity
from ...core.i18n import L
from ...core.module import Category, Intensity, Module

_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/"
_USER_AGENT = "ThurSec/0.1"
_TIMEOUT = 20
# Cap how many CVE findings we emit so a broad keyword can't flood a run.
_MAX_FINDINGS = 50


class CveLookup(Module):
    id = "vuln.cve_lookup"
    name = L("Consulta de CVE (NVD)", "CVE lookup (NVD)")
    category = Category.VULN
    intensity = Intensity.PASSIVE
    description = L(
        "Consulta CVEs conhecidos de um produto (e versão opcional) na base "
        "pública NVD. Informe o produto via options['product'] ou um alvo como "
        "'nginx:1.18.0'. Passivo: consulta apenas services.nvd.nist.gov, nunca o "
        "alvo. Reporta exposição potencial, nunca exploração confirmada.",
        "Look up known CVEs for a product (and optional version) in the public "
        "NVD database. Give it a product via options['product'] or a target like "
        "'nginx:1.18.0'. Passive: queries services.nvd.nist.gov only, never the "
        "target. Reports potential exposure, never confirmed exploitation.",
    )

    async def run(self, ctx: RunContext) -> list[Finding]:
        product, version = _resolve_product_version(ctx)

        if not product:
            return [
                ctx.finding(
                    self.id,
                    L(
                        "Nenhum produto informado para consulta de CVE",
                        "No product given for CVE lookup",
                    ),
                    Severity.INFO,
                    description=L(
                        "Este módulo precisa de um nome de produto para buscar "
                        "CVEs conhecidos na NVD. Informe via options['product'] "
                        "(com um options['version'] opcional), ou defina o alvo "
                        "como 'product' ou 'product:version' (ex.: 'nginx:1.18.0').",
                        "This module needs a product name to search the NVD for "
                        "known CVEs. Provide it via options['product'] (with an "
                        "optional options['version']), or set the target to "
                        "'product' or 'product:version' (e.g. 'nginx:1.18.0').",
                    ),
                    recommendation=L(
                        "Rode de novo com um fingerprint de produto, por exemplo "
                        "target='openssl:1.1.1' ou options={'product': 'openssl', "
                        "'version': '1.1.1'}.",
                        "Re-run with a product fingerprint, for example "
                        "target='openssl:1.1.1' or options={'product': 'openssl', "
                        "'version': '1.1.1'}.",
                    ),
                    references=[_NVD_API_URL],
                )
            ]

        try:
            doc = await asyncio.to_thread(self._query_nvd, product)
        except Exception as e:
            return [
                ctx.finding(
                    self.id,
                    L(
                        f"Não foi possível consultar a NVD para '{product}'",
                        f"Could not query NVD for '{product}'",
                    ),
                    Severity.LOW,
                    description=L(
                        f"A consulta à NVD para '{product}' não foi concluída, "
                        "então nenhum CVE conhecido pôde ser obtido.",
                        f"The NVD lookup for '{product}' did not complete, so no "
                        "known CVEs could be retrieved.",
                    ),
                    evidence=f"{type(e).__name__}: {e}",
                    recommendation=L(
                        "Tente novamente mais tarde; a API pública da NVD é "
                        "limitada por taxa sem uma API key e pode ser lenta.",
                        "Retry later; the public NVD API is rate-limited without "
                        "an API key and can be slow.",
                    ),
                    references=[_NVD_API_URL],
                    metadata={"product": product, "version": version},
                )
            ]

        try:
            vulnerabilities = _extract_vulnerabilities(doc)
        except Exception as e:
            return [
                ctx.finding(
                    self.id,
                    L(
                        f"Não foi possível analisar a resposta da NVD para "
                        f"'{product}'",
                        f"Could not parse NVD response for '{product}'",
                    ),
                    Severity.LOW,
                    description=L(
                        "A resposta da NVD não pôde ser analisada, então nenhum "
                        "CVE conhecido pôde ser extraído.",
                        "The NVD response could not be parsed, so no known CVEs "
                        "could be extracted.",
                    ),
                    evidence=f"{type(e).__name__}: {e}",
                    references=[_NVD_API_URL],
                    metadata={"product": product, "version": version},
                )
            ]

        findings: list[Finding] = []
        matched = 0
        for item in vulnerabilities:
            cve = item.get("cve") if isinstance(item, dict) else None
            if not isinstance(cve, dict):
                continue

            confidence = _confidence_for(cve, version)
            if confidence is None:
                # Version supplied and the CVE's ranges exclude it -> not relevant.
                continue

            findings.append(_cve_finding(ctx, self.id, product, version, cve, confidence))
            matched += 1
            if matched >= _MAX_FINDINGS:
                break

        if not findings:
            label = product if not version else f"{product} {version}"
            findings.append(
                ctx.finding(
                    self.id,
                    L(
                        f"Nenhum CVE conhecido encontrado para '{label}'",
                        f"No known CVEs found for '{label}'",
                    ),
                    Severity.INFO,
                    description=L(
                        f"A NVD não retornou CVEs correspondentes a '{label}'. "
                        "Isso não é prova de que o produto esteja livre de "
                        "vulnerabilidades — apenas que nenhuma surgiu para esta "
                        "palavra-chave/versão.",
                        f"The NVD returned no CVEs matching '{label}'. This is not "
                        "proof the product is free of vulnerabilities — only that "
                        "none surfaced for this keyword/version.",
                    ),
                    references=[_NVD_API_URL],
                    metadata={"product": product, "version": version},
                )
            )
        return findings

    # --- isolable NVD HTTP layer (monkeypatched in tests) ------------------
    def _query_nvd(self, product: str) -> dict:
        """Query NVD 2.0 by keyword and return the parsed JSON document.

        Isolated so tests replace it with canned data — no network. Blocking;
        callers wrap it in ``asyncio.to_thread``.
        """
        query = urllib.parse.urlencode({"keywordSearch": product})
        url = f"{_NVD_API_URL}?{query}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        return json.loads(raw) if raw else {}


# --- input resolution ------------------------------------------------------
def _resolve_product_version(ctx: RunContext) -> tuple[str, str]:
    """Work out (product, version) from options first, then the target string."""
    opts = ctx.options or {}
    product = str(opts.get("product") or "").strip()
    version = str(opts.get("version") or "").strip()

    if not product:
        product, parsed_version = _parse_target(ctx.target)
        if not version:
            version = parsed_version
    return product, version


def _parse_target(target: object) -> tuple[str, str]:
    """Parse a bare target into (product, version).

    Accepts ``"product"`` or ``"product:version"``. A value that is only a
    version-looking suffix is still treated as the version half.
    """
    text = str(target or "").strip()
    if not text:
        return "", ""
    if ":" in text:
        product, _, version = text.partition(":")
        return product.strip(), version.strip()
    return text, ""


# --- NVD response parsing --------------------------------------------------
def _extract_vulnerabilities(doc: object) -> list[dict]:
    if not isinstance(doc, dict):
        return []
    vulns = doc.get("vulnerabilities")
    if not isinstance(vulns, list):
        return []
    return [v for v in vulns if isinstance(v, dict)]


def _english_description(cve: dict) -> str:
    descriptions = cve.get("descriptions")
    if isinstance(descriptions, list):
        for desc in descriptions:
            if isinstance(desc, dict) and desc.get("lang") == "en":
                value = desc.get("value")
                if isinstance(value, str) and value.strip():
                    return value.strip()
        # Fall back to the first available description regardless of language.
        for desc in descriptions:
            if isinstance(desc, dict):
                value = desc.get("value")
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return ""


def _base_score(cve: dict) -> float | None:
    """Pull a CVSS base score, preferring v3.1 > v3.0 > v2."""
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            cvss_data = entry.get("cvssData")
            if isinstance(cvss_data, dict) and cvss_data.get("baseScore") is not None:
                try:
                    return float(cvss_data["baseScore"])
                except (TypeError, ValueError):
                    continue
    return None


def _severity_from_score(score: float | None) -> Severity:
    """Map a CVSS base score to our scale; unknown score -> MEDIUM (conservative)."""
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


# --- version matching ------------------------------------------------------
def _iter_cpe_matches(cve: dict):
    """Yield every ``cpeMatch`` dict across the CVE's configuration nodes."""
    configs = cve.get("configurations")
    if not isinstance(configs, list):
        return
    for config in configs:
        if not isinstance(config, dict):
            continue
        nodes = config.get("nodes")
        if not isinstance(nodes, list):
            continue
        for node in nodes:
            if not isinstance(node, dict):
                continue
            matches = node.get("cpeMatch")
            if not isinstance(matches, list):
                continue
            for match in matches:
                if isinstance(match, dict):
                    yield match


def _version_key(version: str) -> tuple:
    """A sortable key for a dotted version; non-numeric parts compare as text.

    Numbers sort as integers and always rank below trailing text so that, e.g.,
    ``1.2`` < ``1.2.0`` holds loosely without pretending to be full semver.
    """
    key: list[tuple[int, object]] = []
    for part in str(version).replace("-", ".").split("."):
        if part.isdigit():
            key.append((0, int(part)))
        elif part:
            key.append((1, part))
    return tuple(key)


def _cpe_version(match: dict) -> str:
    """Extract an exact version baked into a CPE 2.3 criteria string, if any."""
    criteria = match.get("criteria")
    if not isinstance(criteria, str):
        return ""
    parts = criteria.split(":")
    # cpe:2.3:a:vendor:product:version:...  -> index 5 is the version field.
    if len(parts) > 5:
        ver = parts[5]
        if ver and ver not in ("*", "-"):
            return ver
    return ""


def _match_covers_version(match: dict, version: str) -> bool | None:
    """Does one cpeMatch cover ``version``? True/False, or None if undetermined."""
    if match.get("vulnerable") is False:
        return None

    target = _version_key(version)
    start_incl = match.get("versionStartIncluding")
    start_excl = match.get("versionStartExcluding")
    end_incl = match.get("versionEndIncluding")
    end_excl = match.get("versionEndExcluding")

    has_range = any(
        isinstance(b, str) and b
        for b in (start_incl, start_excl, end_incl, end_excl)
    )
    if has_range:
        if isinstance(start_incl, str) and start_incl and target < _version_key(start_incl):
            return False
        if isinstance(start_excl, str) and start_excl and target <= _version_key(start_excl):
            return False
        if isinstance(end_incl, str) and end_incl and target > _version_key(end_incl):
            return False
        if isinstance(end_excl, str) and end_excl and target >= _version_key(end_excl):
            return False
        return True

    exact = _cpe_version(match)
    if exact:
        return _version_key(exact) == target
    return None


def _confidence_for(cve: dict, version: str) -> str | None:
    """Decide how a CVE relates to ``version``.

    Returns ``"confirmed"`` (a range/exact CPE covers the version),
    ``"potential"`` (no version given, or no usable version data to decide), or
    ``None`` (version given and every usable range excludes it -> drop it).
    """
    if not version:
        return "potential"

    saw_decision = False
    for match in _iter_cpe_matches(cve):
        covered = _match_covers_version(match, version)
        if covered is True:
            return "confirmed"
        if covered is False:
            saw_decision = True

    # Some matches were decisive and none covered the version -> not relevant.
    if saw_decision:
        return None
    # No usable version data at all -> best-effort potential exposure.
    return "potential"


# --- finding construction --------------------------------------------------
def _cve_finding(
    ctx: RunContext,
    module_id: str,
    product: str,
    version: str,
    cve: dict,
    confidence: str,
) -> Finding:
    cve_id = str(cve.get("id") or "UNKNOWN")
    summary = _english_description(cve)
    score = _base_score(cve)
    severity = _severity_from_score(score)

    detail_url = f"{_NVD_DETAIL_URL}{cve_id}"
    references = [detail_url]
    for ref in _references(cve):
        if ref not in references:
            references.append(ref)

    affected = product if not version else f"{product} {version}"
    evidence_parts = [f"{cve_id} is listed in NVD as mentioning {affected}."]
    if score is not None:
        evidence_parts.append(f"CVSS base score: {score}")
    if confidence == "potential" and version:
        evidence_parts.append(
            "Version match could not be confirmed from NVD CPE data; reported as "
            "a potential exposure."
        )

    description = summary or L(
        f"A NVD lista {cve_id} como relacionado a {product}. Veja o aviso "
        "referenciado para detalhes.",
        f"NVD lists {cve_id} as relating to {product}. See the referenced "
        "advisory for details.",
    )
    if confidence == "potential" and version:
        description = (
            L(
                "Exposição potencial (não confirmada para esta versão exata). ",
                "Potential exposure (not confirmed for this exact version). ",
            )
            + description
        )

    return ctx.finding(
        module_id,
        L(
            f"CVE conhecido: {cve_id} afeta {product}",
            f"Known CVE: {cve_id} affects {product}",
        ),
        severity,
        description=description,
        evidence="\n".join(evidence_parts),
        recommendation=L(
            "Confirme se a versão implantada é de fato afetada usando o aviso da "
            "NVD, depois atualize para uma release corrigida ou aplique a "
            "mitigação do fornecedor. Isto indica exposição potencial, não "
            "exploração.",
            "Confirm whether the deployed version is actually affected using the "
            "NVD advisory, then upgrade to a fixed release or apply the vendor's "
            "mitigation. This indicates potential exposure, not exploitation.",
        ),
        references=references,
        metadata={
            "product": product,
            "version": version,
            "cve_id": cve_id,
            "cvss_base_score": score,
            "confidence": confidence,
        },
    )


def _references(cve: dict) -> list[str]:
    urls: list[str] = []
    refs = cve.get("references")
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, dict) and isinstance(ref.get("url"), str):
                urls.append(ref["url"])
    return urls
