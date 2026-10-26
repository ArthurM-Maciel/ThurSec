"""Tests for the posture dashboard (PLAT2). All local — no network."""

from __future__ import annotations

import pytest

from thursec.core.dashboard import render_dashboard
from thursec.core.finding import Finding, Severity
from thursec.core.i18n import set_lang
from thursec.core.store import FindingStore


@pytest.fixture(autouse=True)
def _english_ui():
    """Most assertions below check the English UI; pin the language and reset.

    The default language is Portuguese, so without this the labels would come
    out in PT. A dedicated test (``test_dashboard_renders_in_portuguese``)
    exercises the PT default explicitly.
    """
    set_lang("en")
    yield
    set_lang("pt")


def _store(tmp_path):
    return FindingStore(tmp_path / "thursec.db")


def _two_run_store(tmp_path):
    """Build a store with two runs: a NEW, a RESOLVED and an ESCALATED finding."""
    store = _store(tmp_path)
    store.save_run(
        "e",
        "t.example",
        [
            Finding("m", "t.example", "stays", Severity.LOW),
            Finding("m", "t.example", "goes away", Severity.MEDIUM),
            Finding("m", "t.example", "escalates", Severity.LOW),
        ],
    )
    store.save_run(
        "e",
        "t.example",
        [
            Finding("m", "t.example", "stays", Severity.LOW),
            Finding("m", "t.example", "appears", Severity.HIGH),
            Finding("m", "t.example", "escalates", Severity.CRITICAL),
        ],
    )
    return store


def test_dashboard_is_self_contained_html(tmp_path):
    store = _two_run_store(tmp_path)
    html = render_dashboard(store, "t.example")
    assert html.startswith("<!doctype html>")
    assert html.rstrip().endswith("</html>")
    # Self-contained: inline CSS/SVG, no external assets or scripts.
    assert "<style>" in html
    assert "<script" not in html
    assert "http://" not in html and "https://" not in html
    assert "cdn" not in html.lower()


def test_dashboard_has_all_sections(tmp_path):
    store = _two_run_store(tmp_path)
    html = render_dashboard(store, "t.example")
    assert "Current posture" in html
    assert "Trend across runs" in html
    assert "Latest diff" in html
    assert "Findings" in html
    # Trend chart is inline SVG.
    assert "<svg" in html


def test_dashboard_summary_counts_latest_run(tmp_path):
    store = _two_run_store(tmp_path)
    html = render_dashboard(store, "t.example")
    # Latest run: stays(LOW), appears(HIGH), escalates(CRITICAL) => total 3.
    assert "<div class='tile-num'>3</div>" in html  # total tile
    # Each severity present in the latest run appears in the findings table.
    assert "appears" in html
    assert "escalates" in html


def test_dashboard_diff_section_no_double_count(tmp_path):
    """The escalated finding must appear only under Changed severity."""
    store = _two_run_store(tmp_path)
    html = render_dashboard(store, "t.example")
    diff_section = html.split("Latest diff", 1)[1].split("Findings", 1)[0]
    # 'appears' is genuinely new, 'goes away' resolved; both shown once.
    assert "appears" in diff_section
    assert "goes away" in diff_section
    # 'escalates' shows in the changed list with its transition badges.
    assert "escalates" in diff_section
    assert "Low" in diff_section and "Critical" in diff_section


def test_diff_does_not_duplicate_changed_in_new_or_resolved(tmp_path):
    """Store-level guarantee the dashboard relies on."""
    store = _two_run_store(tmp_path)
    diff = store.diff_latest("t.example")
    new_titles = {f["title"] for f in diff["new"]}
    resolved_titles = {f["title"] for f in diff["resolved"]}
    changed_titles = {c["title"] for c in diff["changed_severity"]}

    assert new_titles == {"appears"}
    assert resolved_titles == {"goes away"}
    assert changed_titles == {"escalates"}
    # The crux: no overlap between the buckets.
    assert "escalates" not in new_titles
    assert "escalates" not in resolved_titles


def test_dashboard_defaults_to_latest_target(tmp_path):
    store = _two_run_store(tmp_path)
    # No target passed => most recently run target is used.
    html = render_dashboard(store)
    assert "t.example" in html


def test_dashboard_empty_store_no_crash(tmp_path):
    store = _store(tmp_path)
    html = render_dashboard(store)
    assert html.startswith("<!doctype html>")
    assert "no runs" in html.lower()


def test_dashboard_single_run_diff_message(tmp_path):
    store = _store(tmp_path)
    store.save_run("e", "t", [Finding("m", "t", "only", Severity.LOW)])
    html = render_dashboard(store, "t")
    assert "need at least two runs" in html
    assert "<svg" in html  # trend still renders for one run


def test_dashboard_renders_in_portuguese(tmp_path):
    """With the default (PT) language, labels come out in Portuguese."""
    set_lang("pt")
    store = _two_run_store(tmp_path)
    html = render_dashboard(store, "t.example")
    assert 'lang="pt-BR"' in html
    assert "Painel de postura ThurSec" in html
    assert "Postura atual — última execução" in html
    assert "Tendência entre execuções" in html
    assert "Última comparação" in html
    assert "Achados — última execução" in html
    # Section headers and severity labels are translated.
    assert "Severidade" in html and "Recomendação" in html
    assert "Crítico" in html  # escalated finding's new severity
    # Still self-contained and script-free (anti-XSS / no-asset guarantee).
    assert "<script" not in html
    assert "http://" not in html and "https://" not in html


# --- o painel conta o que a execução imprimiu ------------------------------
def test_painel_colapsa_como_o_resumo_da_execucao(tmp_path):
    """Antes: a execução imprimia ALTO 1 e o painel mostrava ALTO 3."""
    from thursec.core.finding import Finding
    from thursec.core.report import Report
    from thursec.core.store import FindingStore

    def cert(module):
        return Finding(
            module=module,
            target="https://alvo",
            title="Certificado TLS não cobre este domínio",
            severity=Severity.HIGH,
            metadata={"dedup_key": "cert-verify:alvo:443:62"},
        )

    report = Report(engagement="x")
    report.add([cert(m) for m in ("config_audit.tls_headers", "config_audit.cookies", "vuln.http_methods")])

    store = FindingStore(str(tmp_path / "h.db"))
    # O store recebe os três, como a CLI faz — é o que mantém o diff estável.
    store.save_run("x", "https://alvo", report.findings)

    html = render_dashboard(store, "https://alvo")

    # O resumo da execução diz ALTO 1; o painel não pode dizer outra coisa.
    assert report.counts()["HIGH"] == 1
    assert ">1<" in html
    assert html.count("Certificado TLS não cobre este domínio") == 1


def test_o_diff_do_painel_colapsa_como_os_blocos(tmp_path):
    """A mesma página mostrava ALTO 1 em cima e o certificado 3x logo abaixo."""
    from thursec.core.finding import Finding
    from thursec.core.report import Report
    from thursec.core.store import FindingStore

    def cert(module):
        return Finding(
            module=module,
            target="https://alvo",
            title="Certificado TLS não cobre este domínio",
            severity=Severity.HIGH,
            metadata={"dedup_key": "cert-verify:alvo:443:62"},
        )

    store = FindingStore(str(tmp_path / "h.db"))
    # Primeira execução: só um achado, para a segunda ter o que comparar.
    base = Report(engagement="x")
    base.add([Finding(module="m", target="https://alvo", title="base", severity=Severity.LOW)])
    store.save_run("x", "https://alvo", base.findings)

    segunda = Report(engagement="x")
    segunda.add(
        [cert(m) for m in ("config_audit.tls_headers", "config_audit.cookies", "vuln.http_methods")]
    )
    store.save_run("x", "https://alvo", segunda.findings)

    html = render_dashboard(store, "https://alvo")
    assert html.count("Certificado TLS não cobre este domínio") == 2  # bloco + diff


def test_collapse_nao_funde_linhas_sem_identidade():
    """As entradas de changed_severity não têm fingerprint nem metadata.

    Agrupá-las pela chave vazia exibia três mudanças de severidade como uma,
    e as outras duas — possivelmente a CRITICAL — sumiam da página.
    """
    from thursec.core.report import collapse_rows

    entradas = [
        {"module": "a.m", "target": "t", "title": "x", "from": "LOW", "to": "HIGH"},
        {"module": "b.m", "target": "t", "title": "y", "from": "MEDIUM", "to": "HIGH"},
        {"module": "c.m", "target": "t", "title": "z", "from": "INFO", "to": "CRITICAL"},
    ]

    assert [e["module"] for e in collapse_rows(entradas)] == ["a.m", "b.m", "c.m"]


def test_mudancas_de_severidade_aparecem_todas_no_painel(tmp_path):
    from thursec.core.finding import Finding
    from thursec.core.store import FindingStore

    def f(titulo, sev):
        return Finding(module="m.um", target="https://alvo", title=titulo, severity=sev)

    store = FindingStore(str(tmp_path / "h.db"))
    store.save_run("x", "https://alvo", [
        f("alfa", Severity.LOW), f("beta", Severity.MEDIUM), f("gama", Severity.INFO),
    ])
    store.save_run("x", "https://alvo", [
        f("alfa", Severity.HIGH), f("beta", Severity.HIGH), f("gama", Severity.CRITICAL),
    ])

    html = render_dashboard(store, "https://alvo")
    for titulo in ("alfa", "beta", "gama"):
        assert titulo in html


def test_mudancas_de_severidade_iguais_sao_agrupadas():
    """Mesmo defeito, mesma transição: uma linha, não três."""
    from thursec.core.report import collapse_changes

    mudancas = [
        {"module": "vuln.http_methods", "target": "t", "title": "cert", "from": "LOW", "to": "HIGH"},
        {"module": "config_audit.cookies", "target": "t", "title": "cert", "from": "LOW", "to": "HIGH"},
        {"module": "config_audit.tls_headers", "target": "t", "title": "cert", "from": "LOW", "to": "HIGH"},
        # Transição diferente continua sendo outra linha.
        {"module": "m.outro", "target": "t", "title": "cert", "from": "INFO", "to": "HIGH"},
    ]
    r = collapse_changes(mudancas)

    assert len(r) == 2
    assert r[0]["module"] == "config_audit.cookies"  # menor id de módulo


def test_o_painel_mostra_quem_mais_viu_o_achado(tmp_path):
    """O colapso calculava essa lista e a página não a mostrava."""
    from thursec.core.finding import Finding
    from thursec.core.report import Report
    from thursec.core.store import FindingStore

    def cert(module):
        return Finding(
            module=module,
            target="https://alvo",
            title="Certificado TLS não cobre este domínio",
            severity=Severity.HIGH,
            metadata={"dedup_key": "cert-verify:alvo:443:62:v"},
        )

    report = Report(engagement="x")
    report.add([cert(m) for m in ("config_audit.tls_headers", "config_audit.cookies", "vuln.http_methods")])

    store = FindingStore(str(tmp_path / "h.db"))
    store.save_run("x", "https://alvo", report.findings)

    html = render_dashboard(store, "https://alvo")
    assert "config_audit.tls_headers" in html
    assert "vuln.http_methods" in html
    assert "módulo(s)" in html or "module(s)" in html
