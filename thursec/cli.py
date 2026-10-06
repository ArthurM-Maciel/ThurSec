"""ThurSec command-line entry point.

A thin layer over the engine: discover modules, optionally load a scope, run a
selection against a target, and write a report. A Textual TUI can sit on top of
these same primitives later — the CLI keeps the toolkit scriptable for CI.
"""

from __future__ import annotations

import argparse
import asyncio
import re
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .core.engine import Engine, Registry
from .core.i18n import L, Lf, SUPPORTED_LANGS, init_lang_from_env, set_lang
from .core.module import Category, Intensity
from .core.dashboard import render_dashboard
from .core.report import Report
from .core.scope import Scope, ScopeError
from .core.store import FindingStore, StoreError

_BANNER_ART = r"""
  _____ _                 ____
 |_   _| |__  _   _ _ __ / ___|  ___  ___
   | | | '_ \| | | | '__|\___ \ / _ \/ __|
   | | | | | | |_| | |    ___) |  __/ (__
   |_| |_| |_|\__,_|_|   |____/ \___|\___|"""


def _banner() -> str:
    tagline = L(
        "avaliação modular de segurança · uso autorizado apenas",
        "modular security assessment · authorized use only",
    )
    return f"{_BANNER_ART}\n {tagline}\n"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="thursec",
        description=L(
            "ThurSec — kit modular de avaliação de segurança.",
            "ThurSec — modular security assessment toolkit.",
        ),
    )
    p.add_argument("--version", action="version", version=f"ThurSec {__version__}")
    p.add_argument(
        "--lang", choices=list(SUPPORTED_LANGS),
        help=L(
            "Idioma da interface (pt/en). Padrão: THURSEC_LANG ou pt.",
            "Interface language (pt/en). Default: THURSEC_LANG or pt.",
        ),
    )
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help=L("Lista os módulos disponíveis.",
                                   "List available modules."))

    run = sub.add_parser("run", help=L("Executa módulos contra um alvo.",
                                        "Run modules against a target."))
    run.add_argument("target", help=L(
        "Host, IP ou URL a avaliar (deve estar no escopo).",
        "Host, IP, or URL to assess (must be in scope).",
    ))
    run.add_argument(
        "-m", "--module", action="append", default=[],
        help=L(
            "Id do módulo a executar (repetível). Padrão: todos os passivos.",
            "Module id to run (repeatable). Default: all passive modules.",
        ),
    )
    run.add_argument(
        "-c", "--category", choices=[c.value for c in Category],
        help=L("Executa todos os módulos de uma categoria.",
                "Run every module in a category."),
    )
    run.add_argument("--scope", type=Path, help=L(
        "Caminho para um arquivo de escopo autorizado (YAML).",
        "Path to an authorized scope YAML file.",
    ))
    run.add_argument(
        "--confirm-intrusive", action="store_true",
        help=L(
            "Confirma de antemão que os módulos INTRUSIVE (que podem alterar "
            "ou perturbar o alvo) estão autorizados. Sem esta flag, uma "
            "execução interativa pede confirmação; uma não-interativa os pula.",
            "Confirm up front that INTRUSIVE modules (which may alter or disrupt "
            "the target) are authorized. Without this flag an interactive run "
            "prompts for confirmation; a non-interactive run skips them.",
        ),
    )
    run.add_argument(
        "-O", "--opt", action="append", default=[], metavar="KEY=VALUE",
        dest="opt",
        help=L(
            "Passa uma opção de módulo como KEY=VALUE (repetível; a última "
            "vence para uma chave repetida). Exposta aos módulos como "
            "ctx.options. O valor é convertido: 'true'/'false' -> bool, "
            "inteiro -> int, decimal -> float, senão string. Ex.: --opt "
            "max_rps=50 --opt allow_intrusive=true --opt product=nginx.",
            "Pass a module option as KEY=VALUE (repeatable; last wins for a "
            "repeated key). Surfaced to modules as ctx.options. The value is "
            "coerced: 'true'/'false' -> bool, an integer -> int, a decimal -> "
            "float, otherwise a string. E.g. --opt max_rps=50 --opt "
            "allow_intrusive=true --opt product=nginx.",
        ),
    )
    run.add_argument(
        "-o", "--output", type=Path,
        help=L(
            "Escreve um relatório. Formato inferido da extensão (.json/.md/.html).",
            "Write a report. Format inferred from extension (.json/.md/.html).",
        ),
    )
    run.add_argument(
        "--store", type=Path,
        help=L(
            "Persiste esta execução em um histórico SQLite de findings (opt-in).",
            "Persist this run to a historical SQLite findings store (opt-in).",
        ),
    )

    diff = sub.add_parser(
        "diff", help=L(
            "Compara as duas execuções mais recentes de um alvo em um store.",
            "Diff the two most recent runs of a target in a store.",
        )
    )
    diff.add_argument(
        "--store", type=Path, required=True,
        help=L("Caminho do store SQLite de findings a ler.",
                "Path to the SQLite findings store to read from."),
    )
    diff.add_argument("target", help=L(
        "Alvo cujas duas últimas execuções comparar.",
        "Target whose last two runs to compare.",
    ))

    dash = sub.add_parser(
        "dashboard",
        help=L(
            "Gera um dashboard HTML de postura sobre um store de findings.",
            "Generate an HTML posture dashboard over a findings store.",
        ),
    )
    dash.add_argument(
        "--store", type=Path, required=True,
        help=L("Caminho do store SQLite de findings a ler.",
                "Path to the SQLite findings store to read from."),
    )
    dash.add_argument(
        "target", nargs="?",
        help=L(
            "Alvo a reportar. Padrão: o alvo executado mais recentemente.",
            "Target to report on. Default: the most recently run target.",
        ),
    )
    dash.add_argument(
        "-o", "--output", type=Path,
        help=L("Escreve o dashboard aqui (padrão: dashboard.html).",
                "Write the dashboard here (default: dashboard.html)."),
    )

    _add_awareness_parser(sub)
    return p


def _add_awareness_parser(sub) -> None:
    aw = sub.add_parser(
        "awareness",
        help=L(
            "Ferramentas autorizadas de conscientização (treino anti-phishing).",
            "Authorized security-awareness (anti-phishing training) tooling.",
        ),
    )
    aw_sub = aw.add_subparsers(dest="action", required=True)

    gen = aw_sub.add_parser(
        "generate",
        help=L(
            "Gera uma página EDUCATIVA, um modelo de e-mail de treino e tokens "
            "de rastreio por destinatário para uma campanha autorizada.",
            "Generate an EDUCATIONAL landing page, training e-mail template, "
            "and per-recipient tracking tokens for an authorized campaign.",
        ),
    )
    gen.add_argument("--name", default="Security Awareness Exercise",
                     help=L("Nome da campanha (usado nos artefatos gerados).",
                             "Campaign name (used in generated artifacts)."))
    gen.add_argument("--authorized-by", dest="authorized_by",
                     help=L("Nome de quem aprovou este exercício (obrigatório).",
                             "Name of the person who approved this exercise (required)."))
    gen.add_argument("--authorized-on", dest="authorized_on",
                     help=L("Data de aprovação, formato ISO YYYY-MM-DD (obrigatório).",
                             "Approval date, ISO format YYYY-MM-DD (required)."))
    gen.add_argument("--allow", action="append", default=[], metavar="DOMAIN|EMAIL",
                     help=L("Entrada da allowlist: um domínio ou e-mail (repetível).",
                             "Allowlist entry: a domain or e-mail (repeatable)."))
    gen.add_argument("--allowlist-file", type=Path,
                     help=L(
                         "Arquivo com uma entrada da allowlist (domínio ou e-mail) por linha.",
                         "File with one allowlist entry (domain or e-mail) per line."))
    gen.add_argument("--recipient", action="append", default=[], metavar="EMAIL",
                     help=L("E-mail de destinatário (repetível).",
                             "Recipient e-mail (repeatable)."))
    gen.add_argument("--recipients-file", type=Path,
                     help=L("Arquivo com um e-mail de destinatário por linha.",
                             "File with one recipient e-mail per line."))
    gen.add_argument("--base-url", dest="base_url", required=True,
                     help=L("URL hospedada pelo operador da página educativa.",
                             "Operator-hosted URL of the educational landing page."))
    gen.add_argument("--org-contact", dest="org_contact",
                     help=L("Como os treinandos devem contatar a equipe de segurança.",
                             "How trainees should reach the security team."))
    gen.add_argument("-o", "--output-dir", dest="output_dir", type=Path,
                     default=Path("awareness_campaign"),
                     help=L(
                         "Diretório onde escrever os artefatos (padrão: ./awareness_campaign).",
                         "Directory to write artifacts into (default: ./awareness_campaign)."))

    tally = aw_sub.add_parser(
        "tally",
        help=L(
            "Calcula métricas agregadas e não-punitivas de cliques a partir de "
            "uma lista de tokens e um log de cliques.",
            "Compute aggregate, non-punitive click metrics from a token list "
            "and a click log.",
        ),
    )
    tally.add_argument("--tokens-file", type=Path, required=True,
                       help=L("CSV (recipient,token,tracking_url) ou lista de tokens por linha.",
                               "CSV (recipient,token,tracking_url) or newline token list."))
    tally.add_argument("--click-log", dest="click_log", type=Path, required=True,
                       help=L(
                           "Arquivo de tokens observados (um por linha) dos logs web do operador.",
                           "File of observed tokens (one per line) from operator web logs."))


def _cmd_list(registry: Registry) -> int:
    for cat in Category:
        mods = registry.by_category(cat)
        if not mods:
            continue
        print(f"\n[{cat.value}]")
        for m in mods:
            scope = L("restrito a escopo", "scope-gated") if m.requires_scope \
                else L("passivo", "passive")
            print(f"  {m.id:<32} {m.name}  ({m.intensity.value}, {scope})")
    print()
    return 0


def _select(registry: Registry, args: argparse.Namespace) -> list:
    if args.module:
        selected = []
        for mid in args.module:
            m = registry.get(mid)
            if m is None:
                print(Lf("erro: módulo desconhecido {mid!r}",
                         "error: unknown module {mid!r}", mid=mid),
                      file=sys.stderr)
                raise SystemExit(2)
            selected.append(m)
        return selected
    if args.category:
        return registry.by_category(Category(args.category))
    # Safe default: passive-only, so a bare `run` never touches an out-of-scope host.
    return [m for m in registry.all() if not m.requires_scope]


_INT_RE = re.compile(r"^-?\d+$")
_FLOAT_RE = re.compile(r"^-?\d+\.\d+$")


def _coerce(value: str) -> Any:
    """Coerce a raw string option value to a bool/int/float/str, in that order.

    Only the exact forms are coerced: ``true``/``false`` (case-insensitive) to
    bool, ``^-?\\d+$`` to int, ``^-?\\d+\\.\\d+$`` to float; anything else is
    left as the original string (so ``http://x?a=b`` stays a string).
    """
    low = value.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if _INT_RE.match(value):
        return int(value)
    if _FLOAT_RE.match(value):
        return float(value)
    return value


def _parse_opts(items: list[str]) -> dict[str, Any]:
    """Parse ``KEY=VALUE`` strings into a dict, coercing each value.

    The first ``=`` separates key from value, so the value may itself contain
    ``=`` (e.g. ``url=http://x?a=b``). An item without any ``=`` is a usage
    error. For a repeated key, the last occurrence wins.
    """
    out: dict[str, Any] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(
                f"invalid --opt {item!r}: expected KEY=VALUE (missing '=')"
            )
        key, value = item.split("=", 1)
        out[key] = _coerce(value)
    return out


def _resolve_intrusive_confirmation(
    modules: list, args: argparse.Namespace
) -> dict[str, object]:
    """Decide whether INTRUSIVE modules are confirmed for this run.

    The engine enforces a *second* barrier beyond scope for INTRUSIVE modules:
    it only runs them when ``options["confirm_intrusive"]`` is ``True``. This
    helper is where the CLI earns that confirmation:

    * ``--confirm-intrusive`` on the command line → confirmed (good for CI).
    * otherwise, if any selected module is INTRUSIVE and we have a TTY, warn the
      operator and require them to re-type the exact target. A mismatch (or any
      other answer) leaves it unconfirmed, so the engine skips the module with a
      clear reason.
    * no flag and no TTY → unconfirmed; the engine skips with a clear reason.
    """
    options: dict[str, object] = {}
    if args.confirm_intrusive:
        options["confirm_intrusive"] = True
        return options

    intrusive = [m for m in modules if m.intensity == Intensity.INTRUSIVE]
    if intrusive and sys.stdin.isatty():
        ids = ", ".join(m.id for m in intrusive)
        print(Lf(
            "\n!! Módulo(s) INTRUSIVE selecionado(s): {ids}\n"
            "   Estes podem ALTERAR ou PERTURBAR o alvo (ex.: teste de carga).\n"
            "   Para confirmar, digite o alvo exatamente ({target}); "
            "qualquer outra coisa os aborta.",
            "\n!! INTRUSIVE module(s) selected: {ids}\n"
            "   These may ALTER or DISRUPT the target (e.g. load testing).\n"
            "   To confirm, type the target exactly ({target}); "
            "anything else aborts them.",
            ids=ids, target=args.target,
        ))
        try:
            answer = input(L("   Confirmar alvo> ", "   Confirm target> ")).strip()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer == args.target:
            options["confirm_intrusive"] = True
        else:
            print(L(
                "   Confirmação falhou — módulos intrusivos serão pulados.",
                "   Confirmation failed — intrusive modules will be skipped.",
            ))
    return options


async def _cmd_run(registry: Registry, args: argparse.Namespace) -> int:
    scope = None
    if args.scope:
        try:
            scope = Scope.from_file(args.scope)
        except ScopeError as e:
            print(Lf("erro de escopo: {e}", "scope error: {e}", e=e), file=sys.stderr)
            return 2
        print(Lf("Escopo carregado: {s}", "Scope loaded: {s}", s=scope.summary()))

    modules = _select(registry, args)
    options = _resolve_intrusive_confirmation(modules, args)
    try:
        options.update(_parse_opts(args.opt))
    except ValueError as e:
        print(Lf("erro: {e}", "error: {e}", e=e), file=sys.stderr)
        return 2
    engine = Engine(registry, scope=scope, options=options)
    report = Report(engagement=scope.engagement if scope else "ad-hoc")

    print(Lf("Rodando {n} módulo(s) contra {t}\n",
             "Running {n} module(s) against {t}\n", n=len(modules), t=args.target))
    for m in modules:
        result = await engine.run_module(m, args.target)
        if result.skipped:
            print(Lf("  ~ {mid}: PULADO — {r}", "  ~ {mid}: SKIPPED — {r}",
                     mid=m.id, r=result.skip_reason))
            continue
        if not result.ok:
            print(Lf("  ! {mid}: ERRO — {e}", "  ! {mid}: ERROR — {e}",
                     mid=m.id, e=result.error))
            continue
        report.add(result.findings)
        notable = [f for f in result.findings if f.severity.name != "INFO"]
        print(Lf("  ✓ {mid}: {n} finding(s), {k} notável(is)",
                 "  ✓ {mid}: {n} finding(s), {k} notable",
                 mid=m.id, n=len(result.findings), k=len(notable)))

    print("\n" + L("Resumo: ", "Summary: ")
          + ", ".join(f"{k} {v}" for k, v in report.counts().items()))

    if args.output:
        _write_report(report, args.output)
        print(Lf("Relatório salvo em {p}", "Report written to {p}", p=args.output))

    if args.store:
        try:
            store = FindingStore(args.store)
            run_id = store.save_run(report.engagement, args.target, report.findings)
            print(Lf("Execução #{rid} persistida no store {s}",
                     "Run #{rid} persisted to store {s}", rid=run_id, s=args.store))
        except StoreError as e:
            print(Lf("erro de store: {e}", "store error: {e}", e=e), file=sys.stderr)
            return 2
    return 0


def _write_report(report: Report, path: Path) -> None:
    ext = path.suffix.lower()
    if ext == ".json":
        path.write_text(report.to_json())
    elif ext in (".md", ".markdown"):
        path.write_text(report.to_markdown())
    elif ext in (".html", ".htm"):
        path.write_text(report.to_html())
    else:
        raise SystemExit(Lf(
            "Formato de relatório desconhecido: {ext!r} (use .json/.md/.html)",
            "Unknown report format: {ext!r} (use .json/.md/.html)", ext=ext))


def _cmd_diff(args: argparse.Namespace) -> int:
    try:
        store = FindingStore(args.store)
        result = store.diff_latest(args.target)
    except StoreError as e:
        print(Lf("erro de store: {e}", "store error: {e}", e=e), file=sys.stderr)
        return 2

    if result["run_b"] is None:
        print(Lf("Nenhuma execução encontrada para {t!r} em {s}.",
                 "No runs found for {t!r} in {s}.", t=args.target, s=args.store))
        return 0
    if result["run_a"] is None:
        print(Lf(
            "Apenas uma execução (#{rb}) para {t!r}; são necessárias ao menos "
            "duas para comparar.",
            "Only one run (#{rb}) for {t!r}; need at least two to diff.",
            rb=result["run_b"], t=args.target,
        ))
        return 0

    print(Lf(
        "Diff de {t} — execução #{ra} (base) vs execução #{rb} (mais recente)\n",
        "Diff for {t} — run #{ra} (baseline) vs run #{rb} (latest)\n",
        t=args.target, ra=result["run_a"], rb=result["run_b"],
    ))

    new = result["new"]
    resolved = result["resolved"]
    changed = result["changed_severity"]
    none_txt = L("    (nenhum)", "    (none)")

    print(Lf("  Novos ({n}):", "  New ({n}):", n=len(new)))
    for f in sorted(new, key=lambda x: -x["severity_level"]):
        print(f"    + [{f['severity']}] {f['title']}  ({f['module']} / {f['target']})")
    if not new:
        print(none_txt)

    print(Lf("\n  Resolvidos ({n}):", "\n  Resolved ({n}):", n=len(resolved)))
    for f in sorted(resolved, key=lambda x: -x["severity_level"]):
        print(f"    - [{f['severity']}] {f['title']}  ({f['module']} / {f['target']})")
    if not resolved:
        print(none_txt)

    print(Lf("\n  Severidade alterada ({n}):",
             "\n  Changed severity ({n}):", n=len(changed)))
    for c in changed:
        print(
            f"    ~ {c['title']}  ({c['module']} / {c['target']}): "
            f"{c['from']} -> {c['to']}"
        )
    if not changed:
        print(none_txt)
    print()
    return 0


def _cmd_dashboard(args: argparse.Namespace) -> int:
    try:
        store = FindingStore(args.store)
        target = args.target or _resolve_latest_target(store)
        if target is None:
            print(Lf("Nenhuma execução encontrada em {s}; nada a renderizar.",
                     "No runs found in {s}; nothing to render.", s=args.store))
            return 0
        if not store.list_runs(target=target):
            print(Lf("Nenhuma execução encontrada para {t!r} em {s}.",
                     "No runs found for {t!r} in {s}.", t=target, s=args.store))
            return 0
        html = render_dashboard(store, target)
    except StoreError as e:
        print(Lf("erro de store: {e}", "store error: {e}", e=e), file=sys.stderr)
        return 2

    out = args.output or Path("dashboard.html")
    out.write_text(html)
    print(Lf("Dashboard salvo em {o}", "Dashboard written to {o}", o=out))
    return 0


def _resolve_latest_target(store: FindingStore) -> str | None:
    runs = store.list_runs()
    return runs[0]["target"] if runs else None


def _read_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _read_tokens(path: Path) -> list[str]:
    """Read tokens from a plain list OR the CSV written by `generate`."""
    import csv as _csv

    text = path.read_text(encoding="utf-8")
    first = text.splitlines()[0] if text.splitlines() else ""
    if "," in first and "token" in first.lower():
        reader = _csv.DictReader(text.splitlines())
        return [row["token"].strip() for row in reader if row.get("token", "").strip()]
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def _cmd_awareness(args: argparse.Namespace) -> int:
    from .awareness import (
        Allowlist,
        Authorization,
        AwarenessError,
        Campaign,
        render_email_template,
        render_landing_page,
        tally_clicks,
    )

    if args.action == "generate":
        try:
            authorization = Authorization.create(args.authorized_by, args.authorized_on)

            entries = list(args.allow)
            if args.allowlist_file:
                entries += _read_lines(args.allowlist_file)
            allowlist = Allowlist.from_entries(entries)

            recipients = list(args.recipient)
            if args.recipients_file:
                recipients += _read_lines(args.recipients_file)
            if not recipients:
                print(L(
                    "erro de awareness: nenhum destinatário informado (use "
                    "--recipient ou --recipients-file)",
                    "awareness error: no recipients provided (use --recipient "
                    "or --recipients-file)",
                ), file=sys.stderr)
                return 2

            campaign = Campaign(
                name=args.name,
                authorization=authorization,
                allowlist=allowlist,
                base_url=args.base_url,
                recipients=recipients,
            )
        except AwarenessError as e:
            print(Lf("erro de awareness: {e}", "awareness error: {e}", e=e),
                  file=sys.stderr)
            return 2

        out = args.output_dir
        out.mkdir(parents=True, exist_ok=True)
        landing = render_landing_page(
            campaign_name=campaign.name,
            authorized_by=authorization.authorized_by,
            authorized_on=authorization.authorized_on,
            org_contact=args.org_contact,
        )
        email = render_email_template(
            campaign_name=campaign.name,
            authorized_by=authorization.authorized_by,
            authorized_on=authorization.authorized_on,
        )
        (out / "landing_page.html").write_text(landing, encoding="utf-8")
        (out / "email_template.txt").write_text(email, encoding="utf-8")
        (out / "tokens.csv").write_text(campaign.tokens_to_csv(), encoding="utf-8")
        (out / "tokens.json").write_text(campaign.tokens_to_json(), encoding="utf-8")

        print(Lf("Autorizado por {by} em {on}", "Authorized by {by} on {on}",
                 by=authorization.authorized_by,
                 on=authorization.authorized_on.isoformat()))
        print(Lf("Allowlist OK · {n} destinatário(s) validado(s)",
                 "Allowlist OK · {n} recipient(s) validated",
                 n=len(campaign.recipients)))
        print(Lf("Artefatos escritos em {out}/:", "Artifacts written to {out}/:",
                 out=out))
        print(L("  landing_page.html   (educativa — SEM captura de credenciais)",
                "  landing_page.html   (educational — NO credential capture)"))
        print(L("  email_template.txt  (modelo de treino — NÃO enviado por esta ferramenta)",
                "  email_template.txt  (training template — NOT sent by this tool)"))
        print(L("  tokens.csv, tokens.json  (tokens de rastreio por destinatário)",
                "  tokens.csv, tokens.json  (per-recipient tracking tokens)"))
        return 0

    if args.action == "tally":
        try:
            tokens = _read_tokens(args.tokens_file)
            clicks = _read_lines(args.click_log)
        except OSError as e:
            print(Lf("erro de awareness: {e}", "awareness error: {e}", e=e),
                  file=sys.stderr)
            return 2
        metrics = tally_clicks(tokens, clicks)
        print(L("Métricas agregadas de conscientização (não-punitivas):",
                "Aggregate awareness metrics (non-punitive):"))
        print(L("  enviados     ", "  sent         ") + str(metrics["sent"]))
        print(L("  clicaram     ", "  clicked      ") + str(metrics["clicked"]))
        print(L("  não clicaram ", "  not clicked  ") + str(metrics["not_clicked"]))
        print(L("  taxa cliques ", "  click rate   ")
              + f"{metrics['click_rate'] * 100:.1f}%")
        if metrics["unknown_hits"]:
            print(Lf("  hits desconhecidos {n} (tokens fora do conjunto emitido)",
                     "  unknown hits {n} (tokens not in issued set)",
                     n=metrics["unknown_hits"]))
        return 0

    return 1


def _resolve_lang(argv: list[str]) -> None:
    """Resolve the active language *before* parsers are built.

    Priority: an explicit ``--lang`` on the command line wins; otherwise
    ``THURSEC_LANG`` from the environment; otherwise the default (``pt``). This
    runs before :func:`_build_parser` so that even the ``--help`` text comes out
    translated. Parsing here is intentionally lenient (no argparse yet): an
    invalid value falls back to ``pt`` via :func:`set_lang`.
    """
    init_lang_from_env()
    for i, tok in enumerate(argv):
        if tok == "--lang" and i + 1 < len(argv):
            set_lang(argv[i + 1])
            return
        if tok.startswith("--lang="):
            set_lang(tok.split("=", 1)[1])
            return


def main(argv: list[str] | None = None) -> int:
    effective_argv = list(sys.argv[1:] if argv is None else argv)
    _resolve_lang(effective_argv)
    args = _build_parser().parse_args(argv)
    # A parsed --lang re-confirms the choice (and is a no-op if already set).
    if getattr(args, "lang", None):
        set_lang(args.lang)
    registry = Registry().discover()

    if args.command == "list":
        print(_banner())
        return _cmd_list(registry)
    if args.command == "run":
        return asyncio.run(_cmd_run(registry, args))
    if args.command == "diff":
        return _cmd_diff(args)
    if args.command == "dashboard":
        return _cmd_dashboard(args)
    if args.command == "awareness":
        return _cmd_awareness(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
