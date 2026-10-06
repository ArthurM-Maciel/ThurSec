"""ThurSec Textual TUI.

A beautiful, dark terminal UI that sits on top of the *exact same* engine the
CLI uses: discover modules, pick a target + authorized scope, run the selected
modules asynchronously, and watch findings land in a colour-coded table.

Run it with ``thursec-tui`` (installs via the ``tui`` extra) or
``python -m thursec.tui.app``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    SelectionList,
    Static,
)
from textual.widgets.selection_list import Selection

from ..core.engine import Engine, Registry
from ..core.finding import Finding, Severity
from ..core.i18n import L, init_lang_from_env
from ..core.module import Category, Intensity, Module
from ..core.scope import Scope, ScopeError

# Honour THURSEC_LANG when the TUI is launched standalone (``thursec-tui``),
# so class-level text (bindings, subtitle) reflects the operator's language.
init_lang_from_env()

# --- presentation constants ------------------------------------------------


def category_label(category: Category) -> str:
    """Localized label for each category section in the sidebar."""
    labels: dict[Category, str] = {
        Category.RECON: L("Reconhecimento", "Recon"),
        Category.VULN: L("Vulnerabilidades", "Vulnerabilities"),
        Category.DEPS_SECRETS: L("Deps e Segredos", "Deps & Secrets"),
        Category.CONFIG_AUDIT: L("Auditoria de Config", "Config Audit"),
    }
    return labels.get(category, category.value)


def severity_label(severity: Severity) -> str:
    """Localized name for a severity level."""
    labels: dict[Severity, str] = {
        Severity.CRITICAL: L("Crítico", "Critical"),
        Severity.HIGH: L("Alto", "High"),
        Severity.MEDIUM: L("Médio", "Medium"),
        Severity.LOW: L("Baixo", "Low"),
        Severity.INFO: L("Informativo", "Info"),
    }
    return labels[severity]


def intensity_label(intensity: Intensity) -> str:
    """Localized name for a module's intensity selo."""
    labels: dict[Intensity, str] = {
        Intensity.PASSIVE: L("passivo", "passive"),
        Intensity.ACTIVE: L("ativo", "active"),
        Intensity.INTRUSIVE: L("intrusivo", "intrusive"),
    }
    return labels[intensity]

#: Colour token per severity (matches the CSS variables / Rich styles).
SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "#ff4d6d",
    Severity.HIGH: "#ff8c42",
    Severity.MEDIUM: "#ffd23f",
    Severity.LOW: "#4ea8de",
    Severity.INFO: "#8d99ae",
}

#: Colour token per intensity badge.
INTENSITY_COLORS: dict[Intensity, str] = {
    Intensity.PASSIVE: "#5ad1a0",
    Intensity.ACTIVE: "#ffd23f",
    Intensity.INTRUSIVE: "#ff4d6d",
}


# --- pure helpers (unit-tested, no UI needed) ------------------------------


@dataclass(frozen=True)
class SeverityTally:
    """Immutable count of findings per severity, highest first."""

    counts: dict[Severity, int]

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> "SeverityTally":
        counts = {s: 0 for s in reversed(Severity)}  # CRITICAL -> INFO
        for f in findings:
            counts[f.severity] += 1
        return cls(counts)

    def total(self) -> int:
        return sum(self.counts.values())


def group_modules(modules: list[Module]) -> list[tuple[Category, list[Module]]]:
    """Group modules by category, preserving ``Category`` declaration order.

    Only categories that actually have modules are returned, so the sidebar
    never shows empty sections. This is the data the TUI renders — kept pure so
    it can be tested without spinning up the app.
    """
    grouped: list[tuple[Category, list[Module]]] = []
    for category in Category:
        mods = [m for m in modules if m.category == category]
        if mods:
            grouped.append((category, mods))
    return grouped


def intensity_badge(intensity: Intensity) -> Text:
    """A small coloured selo for a module's intensity."""
    color = INTENSITY_COLORS[intensity]
    return Text(f" {intensity_label(intensity)} ", style=f"bold {color}")


def module_prompt(module: Module) -> Text:
    """Rich label for a module inside the SelectionList."""
    text = Text()
    text.append(module.name, style="bold #e8ecf4")
    text.append("  ")
    text.append(intensity_badge(module.intensity))
    text.append("\n")
    text.append(module.id, style="#7d8597")
    return text


def severity_cell(severity: Severity) -> Text:
    """Colour-coded severity label for the findings table."""
    return Text(
        severity_label(severity).upper(), style=f"bold {SEVERITY_COLORS[severity]}"
    )


def counts_line(tally: SeverityTally) -> Text:
    """One-line severity breakdown shown above the table."""
    text = Text()
    text.append(L("Achados  ", "Findings  "), style="bold #e8ecf4")
    total = tally.total()
    if total == 0:
        text.append(L("nenhum ainda", "none yet"), style="italic #7d8597")
        return text
    parts = []
    for sev in reversed(Severity):  # CRITICAL -> INFO
        n = tally.counts[sev]
        chip = Text()
        chip.append(
            f" {severity_label(sev).upper()} ", style=f"bold {SEVERITY_COLORS[sev]}"
        )
        chip.append(f"{n} ", style=f"{SEVERITY_COLORS[sev]}")
        parts.append(chip)
    for i, chip in enumerate(parts):
        if i:
            text.append("  ")
        text.append(chip)
    return text


# --- the app ---------------------------------------------------------------


class ThurSecApp(App):
    """The ThurSec terminal UI."""

    CSS_PATH = "app.tcss"
    TITLE = "ThurSec"
    SUB_TITLE = L(
        "avaliação de segurança modular · apenas uso autorizado",
        "modular security assessment · authorized use only",
    )

    BINDINGS = [
        ("r", "run", L("Rodar selecionados", "Run selected")),
        ("l", "load_scope", L("Carregar escopo", "Load scope")),
        ("a", "select_all", L("Selecionar tudo", "Select all")),
        ("n", "select_none", L("Desmarcar tudo", "Deselect all")),
        ("c", "clear_results", L("Limpar resultados", "Clear results")),
        ("d", "toggle_dark", L("Escuro/Claro", "Dark/Light")),
        ("q", "quit", L("Sair", "Quit")),
    ]

    def __init__(self, registry: Registry | None = None) -> None:
        super().__init__()
        self.registry = registry if registry is not None else Registry().discover()
        self.grouped = group_modules(self.registry.all())
        self.scope: Scope | None = None
        self._findings: list[Finding] = []

    # --- composition -------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            with Vertical(id="sidebar"):
                yield Label(L("MÓDULOS", "MODULES"), id="sidebar-title")
                with VerticalScroll(id="module-list"):
                    if not self.grouped:
                        yield Static(
                            L("Nenhum módulo descoberto.", "No modules discovered."),
                            classes="empty-hint",
                        )
                    for category, mods in self.grouped:
                        yield Label(
                            category_label(category),
                            classes="category-label",
                        )
                        selections = [
                            Selection(
                                module_prompt(m),
                                m.id,
                                initial_state=not m.requires_scope,
                            )
                            for m in mods
                        ]
                        yield SelectionList(
                            *selections,
                            id=f"sel-{category.value}",
                            classes="module-group",
                        )
            with Vertical(id="main"):
                with Horizontal(id="controls"):
                    yield Input(
                        placeholder=L(
                            "alvo  (host · ip · url)", "target  (host · ip · url)"
                        ),
                        id="target-input",
                    )
                    yield Input(
                        placeholder=L(
                            "scope.yaml  (autoriza módulos ativos)",
                            "scope.yaml  (authorizes active modules)",
                        ),
                        id="scope-input",
                    )
                    yield Button(
                        L("Carregar escopo", "Load scope"),
                        id="load-scope",
                        variant="primary",
                    )
                    yield Button(L("Rodar ▸", "Run ▸"), id="run", variant="success")
                yield Static(self._scope_text(), id="scope-summary")
                yield Static(counts_line(SeverityTally.from_findings([])), id="counts")
                yield DataTable(id="findings", zebra_stripes=True, cursor_type="row")
                yield Label(L("ATIVIDADE", "ACTIVITY"), id="activity-title")
                yield RichLog(id="activity", highlight=False, markup=True, wrap=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#findings", DataTable)
        table.add_column(L("Severidade", "Severity"), width=12)
        table.add_column(L("Achado", "Finding"), width=46)
        table.add_column(L("Módulo", "Module"), width=26)
        table.add_column(L("Alvo", "Target"), width=22)
        log = self.query_one("#activity", RichLog)
        log.write(
            L(
                "[#5ad1a0]ThurSec pronto.[/] Módulos passivos já vêm selecionados. "
                "Módulos ativos/intrusivos precisam de um alvo no escopo.",
                "[#5ad1a0]ThurSec ready.[/] Passive modules are pre-selected. "
                "Active/intrusive modules need an in-scope target.",
            )
        )

    # --- scope -------------------------------------------------------------
    def _scope_text(self) -> Text:
        if self.scope is None:
            t = Text()
            t.append(L("⚠ Nenhum escopo carregado. ", "⚠ No scope loaded. "),
                     style="bold #ffd23f")
            t.append(
                L(
                    "Só módulos passivos vão rodar; os ativos ficam bloqueados.",
                    "Only passive modules will run; active ones are gated.",
                ),
                style="#7d8597",
            )
            return t
        t = Text()
        t.append(L("✓ Escopo: ", "✓ Scope: "), style="bold #5ad1a0")
        t.append(self.scope.summary(), style="#e8ecf4")
        if self.scope.is_expired:
            t.append(L("  [EXPIRADO]", "  [EXPIRED]"), style="bold #ff4d6d")
        return t

    def _refresh_scope_summary(self) -> None:
        self.query_one("#scope-summary", Static).update(self._scope_text())

    def action_load_scope(self) -> None:
        path = self.query_one("#scope-input", Input).value.strip()
        log = self.query_one("#activity", RichLog)
        if not path:
            self.notify(
                L("Informe o caminho de um scope.yaml primeiro.",
                  "Enter a path to a scope.yaml first."),
                severity="warning",
            )
            return
        try:
            self.scope = Scope.from_file(Path(path))
        except ScopeError as e:
            self.scope = None
            self._refresh_scope_summary()
            self.notify(
                str(e), title=L("Erro de escopo", "Scope error"), severity="error"
            )
            log.write(f"[#ff4d6d]{L('erro de escopo:', 'scope error:')}[/] {e}")
            return
        self._refresh_scope_summary()
        log.write(
            f"[#5ad1a0]{L('escopo carregado:', 'scope loaded:')}[/] "
            f"{self.scope.summary()}"
        )
        self.notify(
            L("Escopo carregado — módulos ativos agora autorizados no escopo.",
              "Scope loaded — active modules now authorized in-scope.")
        )

    # --- selection helpers -------------------------------------------------
    def _selection_lists(self) -> list[SelectionList]:
        return list(self.query(SelectionList))

    def selected_module_ids(self) -> list[str]:
        ids: list[str] = []
        for sel in self._selection_lists():
            ids.extend(sel.selected)
        return ids

    def action_select_all(self) -> None:
        for sel in self._selection_lists():
            sel.select_all()

    def action_select_none(self) -> None:
        for sel in self._selection_lists():
            sel.deselect_all()

    def action_clear_results(self) -> None:
        self._findings = []
        self.query_one("#findings", DataTable).clear()
        self._refresh_counts()
        self.query_one("#activity", RichLog).write(
            f"[#7d8597]{L('resultados limpos.', 'results cleared.')}[/]"
        )

    # --- running -----------------------------------------------------------
    def action_run(self) -> None:
        target = self.query_one("#target-input", Input).value.strip()
        if not target:
            self.notify(
                L("Informe um alvo antes de rodar.", "Enter a target before running."),
                severity="warning",
            )
            return
        module_ids = self.selected_module_ids()
        if not module_ids:
            self.notify(
                L("Selecione ao menos um módulo.", "Select at least one module."),
                severity="warning",
            )
            return
        modules = [m for mid in module_ids if (m := self.registry.get(mid))]
        self._run_modules(target, modules)

    @work(exclusive=True)
    async def _run_modules(self, target: str, modules: list[Module]) -> None:
        log = self.query_one("#activity", RichLog)
        run_btn = self.query_one("#run", Button)
        run_btn.disabled = True
        run_btn.label = L("Rodando…", "Running…")
        engine = Engine(self.registry, scope=self.scope)
        log.write(
            L(
                f"[bold #e8ecf4]▶ rodando {len(modules)} módulo(s) contra "
                f"[/][#4ea8de]{target}[/]",
                f"[bold #e8ecf4]▶ running {len(modules)} module(s) against "
                f"[/][#4ea8de]{target}[/]",
            )
        )
        try:
            for module in modules:
                result = await engine.run_module(module, target)
                if result.skipped:
                    log.write(
                        f"  [#ffd23f]~ {module.id} "
                        f"{L('PULADO', 'SKIPPED')}[/] "
                        f"[#7d8597]({L('trava de escopo', 'scope gate')})[/] — "
                        f"{result.skip_reason}"
                    )
                    continue
                if not result.ok:
                    log.write(
                        f"  [#ff4d6d]! {module.id} "
                        f"{L('ERRO', 'ERROR')}[/] — {result.error}"
                    )
                    continue
                self._add_findings(result.findings)
                notable = sum(1 for f in result.findings if f.severity > Severity.INFO)
                log.write(
                    L(
                        f"  [#5ad1a0]✓ {module.id}[/] — "
                        f"{len(result.findings)} achado(s), {notable} notável(is)",
                        f"  [#5ad1a0]✓ {module.id}[/] — "
                        f"{len(result.findings)} finding(s), {notable} notable",
                    )
                )
            log.write(L("[bold #5ad1a0]✔ execução concluída.[/]",
                        "[bold #5ad1a0]✔ run complete.[/]"))
        finally:
            run_btn.disabled = False
            run_btn.label = L("Rodar ▸", "Run ▸")

    def _add_findings(self, findings: list[Finding]) -> None:
        table = self.query_one("#findings", DataTable)
        for f in sorted(findings, key=lambda x: -int(x.severity)):
            self._findings.append(f)
            table.add_row(
                severity_cell(f.severity),
                Text(f.title, style="#e8ecf4"),
                Text(f.module, style="#7d8597"),
                Text(f.target, style="#4ea8de"),
            )
        self._refresh_counts()

    def _refresh_counts(self) -> None:
        tally = SeverityTally.from_findings(self._findings)
        self.query_one("#counts", Static).update(counts_line(tally))

    # --- button wiring -----------------------------------------------------
    @on(Button.Pressed, "#run")
    def _on_run(self) -> None:
        self.action_run()

    @on(Button.Pressed, "#load-scope")
    def _on_load_scope(self) -> None:
        self.action_load_scope()

    @on(Input.Submitted, "#scope-input")
    def _on_scope_submit(self) -> None:
        self.action_load_scope()

    @on(Input.Submitted, "#target-input")
    def _on_target_submit(self) -> None:
        self.action_run()


def main() -> None:
    ThurSecApp().run()


if __name__ == "__main__":
    main()
