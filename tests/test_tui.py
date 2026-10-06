"""Tests for the Textual TUI.

Two layers, both fast and deterministic:
  * pure helpers (grouping, tallies, cell rendering) — no UI at all;
  * a smoke test driving the app with Textual's headless pilot.
"""

from __future__ import annotations

import pytest

from thursec.core.engine import Registry
from thursec.core.finding import Finding, Severity
from thursec.core.i18n import get_lang, set_lang
from thursec.core.module import Category, Intensity
from thursec.tui.app import (
    SeverityTally,
    ThurSecApp,
    counts_line,
    group_modules,
    intensity_badge,
    module_prompt,
    severity_cell,
)


@pytest.fixture(autouse=True)
def _english_ui():
    """Pin the UI language to English for assertions on visible text.

    The project default is ``pt`` (PT-BR-first), so without this the labels
    would render in Portuguese. Tests that care about the Portuguese rendering
    set the language explicitly and are isolated by the restore below.
    """
    previous = get_lang()
    set_lang("en")
    try:
        yield
    finally:
        set_lang(previous)


@pytest.fixture(scope="module")
def registry() -> Registry:
    return Registry().discover()


# --- pure helpers ----------------------------------------------------------


def test_group_modules_groups_by_category_in_order(registry: Registry) -> None:
    grouped = group_modules(registry.all())
    assert grouped, "discovery should find at least one module"
    # categories appear in Category declaration order and none are empty
    seen = [cat for cat, _ in grouped]
    assert seen == sorted(seen, key=list(Category).index)
    for _, mods in grouped:
        assert mods
    # every discovered module lands in exactly one group
    flat = [m.id for _, mods in grouped for m in mods]
    assert sorted(flat) == sorted(m.id for m in registry.all())


def test_group_modules_omits_empty_categories() -> None:
    class _M:  # minimal stand-in; group_modules only touches .category
        def __init__(self, category: Category) -> None:
            self.category = category

    only_recon = [_M(Category.RECON)]
    grouped = group_modules(only_recon)  # type: ignore[arg-type]
    assert [cat for cat, _ in grouped] == [Category.RECON]


def test_severity_tally_counts_and_total() -> None:
    findings = [
        _finding(Severity.CRITICAL),
        _finding(Severity.HIGH),
        _finding(Severity.HIGH),
        _finding(Severity.INFO),
    ]
    tally = SeverityTally.from_findings(findings)
    assert tally.counts[Severity.CRITICAL] == 1
    assert tally.counts[Severity.HIGH] == 2
    assert tally.counts[Severity.INFO] == 1
    assert tally.counts[Severity.LOW] == 0
    assert tally.total() == 4


def test_empty_tally_is_zero() -> None:
    tally = SeverityTally.from_findings([])
    assert tally.total() == 0
    assert set(tally.counts.values()) == {0}


def test_severity_cell_is_coloured_and_labelled() -> None:
    cell = severity_cell(Severity.CRITICAL)
    assert cell.plain == "CRITICAL"
    assert "ff4d6d" in str(cell.style).lower()


def test_counts_line_mentions_each_severity_when_present() -> None:
    line = counts_line(SeverityTally.from_findings([_finding(Severity.HIGH)])).plain
    for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        assert name in line


def test_counts_line_empty_state() -> None:
    assert "none yet" in counts_line(SeverityTally.from_findings([])).plain


def test_intensity_badge_and_module_prompt(registry: Registry) -> None:
    badge = intensity_badge(Intensity.ACTIVE)
    assert "active" in badge.plain
    module = registry.all()[0]
    prompt = module_prompt(module).plain
    assert module.id in prompt
    assert module.name in prompt


# --- PT-BR rendering (default language) ------------------------------------


def test_severity_cell_renders_portuguese_by_default() -> None:
    set_lang("pt")
    cell = severity_cell(Severity.CRITICAL)
    assert cell.plain == "CRÍTICO"
    assert "ff4d6d" in str(cell.style).lower()


def test_counts_line_portuguese_labels_and_empty_state() -> None:
    set_lang("pt")
    line = counts_line(SeverityTally.from_findings([_finding(Severity.HIGH)])).plain
    for name in ("CRÍTICO", "ALTO", "MÉDIO", "BAIXO", "INFORMATIVO"):
        assert name in line
    assert "nenhum ainda" in counts_line(SeverityTally.from_findings([])).plain


def test_intensity_badge_portuguese(registry: Registry) -> None:
    set_lang("pt")
    assert "passivo" in intensity_badge(Intensity.PASSIVE).plain
    assert "ativo" in intensity_badge(Intensity.ACTIVE).plain
    assert "intrusivo" in intensity_badge(Intensity.INTRUSIVE).plain


def _finding(sev: Severity) -> Finding:
    return Finding(module="m", target="t", title="x", severity=sev)


# --- pilot smoke test ------------------------------------------------------


@pytest.mark.asyncio
async def test_app_mounts_with_modules() -> None:
    app = ThurSecApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        # the sidebar actually rendered module selections
        from textual.widgets import SelectionList

        lists = list(app.query(SelectionList))
        assert lists, "expected at least one SelectionList in the sidebar"
        total_options = sum(sel.option_count for sel in lists)
        assert total_options == len(app.registry.all()) > 0
        # passive modules are pre-selected; active ones gated off by default
        selected = app.selected_module_ids()
        assert all(
            app.registry.get(mid).requires_scope is False for mid in selected
        )


@pytest.mark.asyncio
async def test_run_without_target_notifies_and_adds_no_rows() -> None:
    app = ThurSecApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.action_run()  # no target entered
        await pilot.pause()
        from textual.widgets import DataTable

        table = app.query_one("#findings", DataTable)
        assert table.row_count == 0
