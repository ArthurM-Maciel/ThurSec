"""Tests for the OSV dependency audit — fully offline (no network).

The OSV HTTP layer (``DepAudit._query_osv``) is isolated so each test swaps in a
fake keyed by package name, returning canned OSV vuln dicts. This exercises the
real manifest parsing and finding logic without ever opening a socket.
"""

import json

import pytest

from thursec.core.context import RunContext
from thursec.core.finding import Severity
from thursec.core.i18n import get_lang, set_lang
from thursec.modules.deps_secrets.dep_audit import (
    DepAudit,
    _canon,
    _derive_severity,
    _parse_manifest,
    _parse_package_json,
    _parse_package_lock,
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

    def fake(self, name, version, *_a, **_kw):
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

    def boom(self, name, version, *_a, **_kw):
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
    assert "No dependency manifests" in findings[0].title


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


# --- npm -------------------------------------------------------------------
_LOCK_V3 = {
    "name": "app",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "app", "version": "1.0.0"},
        "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/@scope/pkg": {"version": "2.1.0"},
        "node_modules/a/node_modules/nested": {"version": "0.1.0"},
        "node_modules/link-me": {"version": "1.0.0", "link": True},
    },
}

_LOCK_V1 = {
    "lockfileVersion": 1,
    "dependencies": {
        "lodash": {"version": "4.17.20", "dependencies": {"sub": {"version": "1.2.3"}}}
    },
}


def test_parse_lock_v3_pega_versoes_exatas_e_ignora_link(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps(_LOCK_V3))

    pinned, unpinned = _parse_package_lock(lock)

    assert ("lodash", "4.17.20") in pinned
    assert ("@scope/pkg", "2.1.0") in pinned      # nome com escopo preservado
    assert ("nested", "0.1.0") in pinned          # dependência aninhada
    assert all(n != "link-me" for n, _ in pinned)  # symlink de workspace
    assert all(n != "app" for n, _ in pinned)      # o próprio projeto
    assert unpinned == []


def test_parse_lock_v1_percorre_a_arvore(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps(_LOCK_V1))

    pinned, _ = _parse_package_lock(lock)

    assert ("lodash", "4.17.20") in pinned
    assert ("sub", "1.2.3") in pinned


def test_package_json_vira_nao_fixado(tmp_path):
    """'^4.4.1' instala o que for mais novo na faixa — auditar a string mentiria."""
    pj = tmp_path / "package.json"
    pj.write_text(json.dumps({
        "dependencies": {"react": "^18.2.0"},
        "devDependencies": {"vite": "~5.0.0"},
    }))

    pinned, unpinned = _parse_package_json(pj)

    assert pinned == []
    assert set(unpinned) == {"react", "vite"}


async def test_o_ecossistema_certo_chega_na_consulta_osv(tmp_path, monkeypatch):
    """npm e PyPI são bases distintas na OSV: trocar isso audita o pacote errado."""
    (tmp_path / "package-lock.json").write_text(json.dumps(_LOCK_V3))
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n")

    vistos = []

    def spy(self, name, version, ecosystem=None):
        vistos.append((name, version, ecosystem))
        return []

    monkeypatch.setattr(DepAudit, "_query_osv", spy)
    await DepAudit().run(RunContext(target=str(tmp_path)))

    por_nome = {n: eco for n, _, eco in vistos}
    assert por_nome["lodash"] == "npm"
    assert por_nome["@scope/pkg"] == "npm"
    assert por_nome["requests"] == "PyPI"


def test_coerce_cap_rejeita_lixo_e_booleano():
    from thursec.modules.deps_secrets.dep_audit import _MAX_PACKAGES, _coerce_cap

    assert _coerce_cap(50) == 50
    assert _coerce_cap("50") == 50
    for ruim in (None, 0, -1, True, False, "muitos", []):
        assert _coerce_cap(ruim) == _MAX_PACKAGES


async def test_package_json_ao_lado_de_lock_nao_vira_nao_fixado(tmp_path, monkeypatch):
    """Faixa + lockfile é a prática correta do npm; avisar seria conselho errado."""
    (tmp_path / "package-lock.json").write_text(json.dumps(_LOCK_V3))
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "^4.17.20", "react": "^18.0.0"}})
    )
    monkeypatch.setattr(DepAudit, "_query_osv", lambda self, n, v, *a, **k: [])

    findings = await DepAudit().run(RunContext(target=str(tmp_path)))

    assert [f for f in findings if "npinned" in f.title or "ão fixada" in f.title] == []


async def test_package_json_sozinho_ainda_avisa(tmp_path, monkeypatch):
    """Sem lock, a faixa é mesmo irresolvível — aí o aviso vale."""
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "^4.17.20"}})
    )
    monkeypatch.setattr(DepAudit, "_query_osv", lambda self, n, v, *a, **k: [])

    findings = await DepAudit().run(RunContext(target=str(tmp_path)))

    assert any("lodash" in f.title for f in findings)


async def test_truncamento_vira_achado_em_vez_de_silencio(tmp_path, monkeypatch):
    """Auditoria incompleta apresentada como completa é pior que nenhuma."""
    pacotes = {f"node_modules/p{i}": {"version": "1.0.0"} for i in range(10)}
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": pacotes})
    )
    monkeypatch.setattr(DepAudit, "_query_osv", lambda self, n, v, *a, **k: [])

    findings = await DepAudit().run(
        RunContext(target=str(tmp_path), options={"max_packages": 3})
    )

    parcial = [f for f in findings if "Partial audit" in f.title]
    assert len(parcial) == 1
    assert parcial[0].severity == Severity.LOW
    assert parcial[0].metadata == {"pinned": 10, "cap": 3}
    # A frase que o operador lê também precisa bater: 10 - 3 = 7, não -190.
    assert "7 were not queried" in parcial[0].description


_LOCK_MONOREPO = {
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "raiz", "version": "1.0.0"},
        "packages/ui": {"name": "@app/ui", "version": "0.0.0"},
        "packages/api": {"version": "0.0.0"},
        "node_modules/@app/ui": {"resolved": "packages/ui", "link": True},
        "node_modules/lodash": {"version": "4.17.20"},
    },
}


def test_monorepo_nao_consulta_membro_de_workspace(tmp_path):
    """'packages/api' é diretório, não release pública: consultar dá falso positivo."""
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps(_LOCK_MONOREPO))

    pinned, _ = _parse_package_lock(lock)
    nomes = {n for n, _ in pinned}

    assert nomes == {"lodash"}
    assert "@app/ui" not in nomes      # membro do workspace
    assert "packages/api" not in nomes  # caminho, não nome de pacote


@pytest.mark.parametrize("lockfile", ["yarn.lock", "pnpm-lock.yaml"])
async def test_yarn_e_pnpm_contam_como_projeto_fixado(tmp_path, monkeypatch, lockfile):
    """Sem parser ainda, mas a presença já impede o conselho errado de 'fixe'."""
    (tmp_path / lockfile).write_text("lodash@^4:\n  version \"4.17.20\"\n")
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "^4.17.20", "react": "^18.0.0"}})
    )
    monkeypatch.setattr(DepAudit, "_query_osv", lambda self, n, v, *a, **k: [])

    findings = await DepAudit().run(RunContext(target=str(tmp_path)))

    assert [f for f in findings if "Unpinned" in f.title] == []
