"""Tests for the OSV dependency audit — fully offline (no network).

The OSV HTTP layer (``DepAudit._query_osv``) is isolated so each test swaps in a
fake keyed by package name, returning canned OSV vuln dicts. This exercises the
real manifest parsing and finding logic without ever opening a socket.
"""

import pytest

from thursec.core.context import RunContext
from thursec.core.finding import Severity
from thursec.core.i18n import get_lang, set_lang
from thursec.modules.deps_secrets.dep_audit import (
    DepAudit,
    _canon,
    _derive_severity,
    _parse_manifest,
)


@pytest.fixture(autouse=True)
def _force_english():
    """These tests assert the English finding text; pin the language to en."""
    prev = get_lang()
    set_lang("en")
    try:
        yield
    finally:
        set_lang(prev)

# A canned OSV advisory for a known-vulnerable package/version.
_JINJA_VULN = {
    "id": "GHSA-h5c8-rqwp-cp95",
    "summary": "Jinja2 sandbox escape via str.format",
    "aliases": ["CVE-2024-22195"],
    "database_specific": {"severity": "MODERATE"},
    "references": [
        {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-h5c8-rqwp-cp95"}
    ],
}


def _osv_router(table):
    """Build a fake _query_osv returning table[name] (default: no vulns)."""

    def fake(self, name, version):
        return list(table.get(_canon(name), []))

    return fake


async def _run(target, monkeypatch, table):
    monkeypatch.setattr(DepAudit, "_query_osv", _osv_router(table))
    return await DepAudit().run(RunContext(target=str(target)))


# --- manifest parsing ------------------------------------------------------
def test_parse_requirements_pinned_and_unpinned(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text(
        "# a comment\n"
        "-r other.txt\n"
        "Jinja2==2.11.2\n"
        "requests[security]==2.25.0\n"
        "flask>=1.0\n"
        "\n"
        "numpy==1.26.4 ; python_version >= '3.9'\n"
    )
    pinned, unpinned = _parse_manifest(req)

    assert ("Jinja2", "2.11.2") in pinned
    assert ("requests", "2.25.0") in pinned  # extras stripped
    assert ("numpy", "1.26.4") in pinned  # env marker stripped
    assert "flask" in unpinned  # >= is not an exact pin


def test_parse_pyproject_dependencies(tmp_path):
    pp = tmp_path / "pyproject.toml"
    pp.write_text(
        "[project]\n"
        'name = "demo"\n'
        'dependencies = ["Jinja2==2.11.2", "click>=8.0"]\n'
        "\n"
        "[project.optional-dependencies]\n"
        'dev = ["pytest==8.0.0"]\n'
    )
    pinned, unpinned = _parse_manifest(pp)

    assert ("Jinja2", "2.11.2") in pinned
    assert ("pytest", "8.0.0") in pinned  # from optional-dependencies
    assert "click" in unpinned


# --- vulnerable dependency -------------------------------------------------
@pytest.mark.asyncio
async def test_vulnerable_dependency_reported(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("Jinja2==2.11.2\n")

    findings = await _run(tmp_path, monkeypatch, {"jinja2": [_JINJA_VULN]})

    vulns = [f for f in findings if f.title.startswith("Vulnerable dependency")]
    assert len(vulns) == 1
    f = vulns[0]
    assert "Jinja2" in f.title and "2.11.2" in f.title
    assert "GHSA-h5c8-rqwp-cp95" in f.title
    # MODERATE in OSV maps to MEDIUM on our scale.
    assert f.severity == Severity.MEDIUM
    # OSV id + alias surface in metadata/evidence; OSV link is referenced.
    assert f.metadata["osv_id"] == "GHSA-h5c8-rqwp-cp95"
    assert "CVE-2024-22195" in f.metadata["aliases"]
    assert any("osv.dev/vulnerability/GHSA-h5c8-rqwp-cp95" in r for r in f.references)


# --- clean project ---------------------------------------------------------
@pytest.mark.asyncio
async def test_clean_project_has_no_vuln_finding(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("Jinja2==3.1.4\nrequests==2.32.0\n")

    findings = await _run(tmp_path, monkeypatch, {})  # OSV returns nothing

    assert not [f for f in findings if f.title.startswith("Vulnerable dependency")]
    # A reassuring INFO is still emitted.
    assert any("No known-vulnerable dependencies" in f.title for f in findings)
    assert all(f.severity <= Severity.INFO for f in findings)


# --- unpinned dependency reported as INFO ----------------------------------
@pytest.mark.asyncio
async def test_unpinned_dependency_reported(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("flask>=1.0\n")

    findings = await _run(tmp_path, monkeypatch, {})

    unpinned = [f for f in findings if "Unpinned dependency" in f.title]
    assert len(unpinned) == 1
    assert unpinned[0].severity == Severity.INFO
    assert unpinned[0].metadata["package"] == "flask"


# --- error path (network/parse failure is handled, never raised) -----------
@pytest.mark.asyncio
async def test_osv_error_is_handled(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("Jinja2==2.11.2\n")

    def boom(self, name, version):
        raise ConnectionError("osv.dev unreachable")

    monkeypatch.setattr(DepAudit, "_query_osv", boom)
    findings = await DepAudit().run(RunContext(target=str(tmp_path)))

    errs = [f for f in findings if f.title.startswith("OSV query failed")]
    assert len(errs) == 1
    assert errs[0].severity == Severity.LOW
    assert "osv.dev unreachable" in errs[0].evidence


# --- no manifests ----------------------------------------------------------
@pytest.mark.asyncio
async def test_no_manifests_found(tmp_path, monkeypatch):
    (tmp_path / "README.md").write_text("# nothing to audit\n")

    findings = await _run(tmp_path, monkeypatch, {})

    assert len(findings) == 1
    assert "No Python dependency manifests" in findings[0].title


# --- severity derivation unit ----------------------------------------------
def test_derive_severity_from_cvss_and_default():
    assert _derive_severity({"severity": [{"type": "CVSS_V3", "score": 9.8}]}) == (
        Severity.CRITICAL
    )
    assert _derive_severity({"severity": [{"type": "CVSS_V3", "score": 5.0}]}) == (
        Severity.MEDIUM
    )
    # No severity info at all -> conservative HIGH default.
    assert _derive_severity({}) == Severity.HIGH
