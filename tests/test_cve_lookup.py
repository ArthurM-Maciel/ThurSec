"""Tests for the NVD CVE lookup — fully offline (no network).

The NVD HTTP layer (``CveLookup._query_nvd``) is isolated so each test swaps in
a fake returning a canned NVD 2.0 document. This exercises the real parsing,
severity derivation and version-matching logic without ever opening a socket.
"""

import pytest

from thursec.core.context import RunContext
from thursec.core.finding import Severity
from thursec.modules.vuln.cve_lookup import (
    CveLookup,
    _base_score,
    _confidence_for,
    _severity_from_score,
)

# Two canned NVD CVE records with different CVSS metrics and version ranges.
# CVE-CRIT: CVSS v3.1 = 9.8 (CRITICAL), affects nginx < 1.20.1.
# CVE-MED : CVSS v2 only = 5.0 (MEDIUM), affects nginx <= 1.18.0.
_NVD_DOC = {
    "totalResults": 2,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-23017",
                "descriptions": [
                    {"lang": "es", "value": "resolucion DNS off-by-one"},
                    {"lang": "en", "value": "nginx DNS resolver off-by-one heap write"},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                    ],
                    "cvssMetricV2": [{"cvssData": {"baseScore": 6.8}}],
                },
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "0.6.18",
                                        "versionEndExcluding": "1.20.1",
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {"url": "https://nginx.org/download/patch.txt"},
                ],
            }
        },
        {
            "cve": {
                "id": "CVE-2018-16845",
                "descriptions": [
                    {"lang": "en", "value": "nginx mp4 module memory disclosure"},
                ],
                "metrics": {
                    "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}],
                },
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "1.18.0",
                                    }
                                ]
                            }
                        ]
                    }
                ],
            }
        },
    ],
}


def _fake_nvd(doc):
    def fake(self, product):
        return doc

    return fake


async def _run(target="", options=None, monkeypatch=None, doc=_NVD_DOC):
    monkeypatch.setattr(CveLookup, "_query_nvd", _fake_nvd(doc))
    return await CveLookup().run(RunContext(target=target, options=options or {}))


# --- parsing + severity, no version -> both CVEs reported -------------------
@pytest.mark.asyncio
async def test_parses_both_cves_with_severity(monkeypatch):
    findings = await _run(target="nginx", monkeypatch=monkeypatch)

    by_id = {f.metadata["cve_id"]: f for f in findings}
    assert set(by_id) == {"CVE-2021-23017", "CVE-2018-16845"}

    crit = by_id["CVE-2021-23017"]
    assert crit.severity == Severity.CRITICAL  # v3.1 9.8
    assert crit.title == "CVE conhecido: CVE-2021-23017 afeta nginx"
    assert crit.description.startswith("nginx DNS resolver")  # english summary
    assert any("nvd.nist.gov/vuln/detail/CVE-2021-23017" in r for r in crit.references)
    assert "https://nginx.org/download/patch.txt" in crit.references
    # No version given -> potential exposure, not confirmed.
    assert crit.metadata["confidence"] == "potential"

    med = by_id["CVE-2018-16845"]
    assert med.severity == Severity.MEDIUM  # v2 5.0


# --- version filtering: 1.18.0 is covered by both ranges -------------------
@pytest.mark.asyncio
async def test_version_in_range_is_confirmed(monkeypatch):
    findings = await _run(
        options={"product": "nginx", "version": "1.18.0"}, monkeypatch=monkeypatch
    )
    ids = {f.metadata["cve_id"]: f.metadata["confidence"] for f in findings}
    assert ids == {"CVE-2021-23017": "confirmed", "CVE-2018-16845": "confirmed"}


# --- version filtering: 1.21.0 is out of both ranges -> dropped ------------
@pytest.mark.asyncio
async def test_version_out_of_range_is_dropped(monkeypatch):
    findings = await _run(target="nginx:1.21.0", monkeypatch=monkeypatch)

    cve_findings = [f for f in findings if f.title.startswith("CVE conhecido")]
    assert cve_findings == []
    # A reassuring INFO stands in instead.
    assert any("No known CVEs found" in f.title for f in findings)
    assert all(f.severity <= Severity.INFO for f in findings)


# --- target parsing: product:version split --------------------------------
@pytest.mark.asyncio
async def test_target_product_version_split(monkeypatch):
    findings = await _run(target="nginx:1.18.0", monkeypatch=monkeypatch)
    assert all(f.metadata["version"] == "1.18.0" for f in findings)
    assert all(f.metadata["product"] == "nginx" for f in findings)


# --- no product -> help finding -------------------------------------------
@pytest.mark.asyncio
async def test_no_product_emits_help(monkeypatch):
    findings = await _run(target="", monkeypatch=monkeypatch)

    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "No product given" in findings[0].title
    assert "product:version" in findings[0].description


# --- error path (network/parse failure handled, never raised) --------------
@pytest.mark.asyncio
async def test_nvd_error_is_handled(monkeypatch):
    def boom(self, product):
        raise ConnectionError("nvd unreachable")

    monkeypatch.setattr(CveLookup, "_query_nvd", boom)
    findings = await CveLookup().run(RunContext(target="nginx"))

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert "Could not query NVD" in findings[0].title
    assert "nvd unreachable" in findings[0].evidence


# --- empty NVD result -> reassuring INFO -----------------------------------
@pytest.mark.asyncio
async def test_no_cves_found(monkeypatch):
    findings = await _run(
        target="obscureproduct", monkeypatch=monkeypatch, doc={"vulnerabilities": []}
    )
    assert len(findings) == 1
    assert "No known CVEs found" in findings[0].title
    assert findings[0].severity == Severity.INFO


# --- unit: CVSS preference + severity mapping ------------------------------
def test_base_score_prefers_v31_over_v2():
    cve = {
        "metrics": {
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
            "cvssMetricV2": [{"cvssData": {"baseScore": 6.8}}],
        }
    }
    assert _base_score(cve) == 9.8


def test_severity_from_score_bands():
    assert _severity_from_score(9.8) == Severity.CRITICAL
    assert _severity_from_score(7.5) == Severity.HIGH
    assert _severity_from_score(5.0) == Severity.MEDIUM
    assert _severity_from_score(2.0) == Severity.LOW
    # Unknown score -> conservative MEDIUM default.
    assert _severity_from_score(None) == Severity.MEDIUM


# --- unit: confidence when a CVE carries no version data -------------------
def test_confidence_potential_without_version_data():
    cve = {"configurations": []}
    assert _confidence_for(cve, "1.0.0") == "potential"
    assert _confidence_for(cve, "") == "potential"
