"""ThurSec command-line entry point.

A thin layer over the engine: discover modules, optionally load a scope, run a
selection against a target, and write a report. A Textual TUI can sit on top of
these same primitives later — the CLI keeps the toolkit scriptable for CI.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from . import __version__
from .core.engine import Engine, Registry
from .core.module import Category, Intensity
from .core.dashboard import render_dashboard
from .core.report import Report
from .core.scope import Scope, ScopeError
from .core.store import FindingStore, StoreError

_BANNER = r"""
  _____ _                 ____
 |_   _| |__  _   _ _ __ / ___|  ___  ___
   | | | '_ \| | | | '__|\___ \ / _ \/ __|
   | | | | | | |_| | |    ___) |  __/ (__
   |_| |_| |_|\__,_|_|   |____/ \___|\___|
 modular security assessment · authorized use only
"""


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="thursec", description="ThurSec — modular security assessment toolkit."
    )
    p.add_argument("--version", action="version", version=f"ThurSec {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List available modules.")

    run = sub.add_parser("run", help="Run modules against a target.")
    run.add_argument("target", help="Host, IP, or URL to assess (must be in scope).")
    run.add_argument(
        "-m", "--module", action="append", default=[],
        help="Module id to run (repeatable). Default: all passive modules.",
    )
    run.add_argument(
        "-c", "--category", choices=[c.value for c in Category],
        help="Run every module in a category.",
    )
    run.add_argument("--scope", type=Path, help="Path to an authorized scope YAML file.")
    run.add_argument(
        "--confirm-intrusive", action="store_true",
        help=(
            "Confirm up front that INTRUSIVE modules (which may alter or disrupt "
            "the target) are authorized. Without this flag an interactive run "
            "prompts for confirmation; a non-interactive run skips them."
        ),
    )
    run.add_argument(
        "-o", "--output", type=Path,
        help="Write a report. Format inferred from extension (.json/.md/.html).",
    )
    run.add_argument(
        "--store", type=Path,
        help="Persist this run to a historical SQLite findings store (opt-in).",
    )

    diff = sub.add_parser(
        "diff", help="Diff the two most recent runs of a target in a store."
    )
    diff.add_argument(
        "--store", type=Path, required=True,
        help="Path to the SQLite findings store to read from.",
    )
    diff.add_argument("target", help="Target whose last two runs to compare.")

    dash = sub.add_parser(
        "dashboard",
        help="Generate an HTML posture dashboard over a findings store.",
    )
    dash.add_argument(
        "--store", type=Path, required=True,
        help="Path to the SQLite findings store to read from.",
    )
    dash.add_argument(
        "target", nargs="?",
        help="Target to report on. Default: the most recently run target.",
    )
    dash.add_argument(
        "-o", "--output", type=Path,
        help="Write the dashboard here (default: dashboard.html).",
    )

    _add_awareness_parser(sub)
    return p


def _add_awareness_parser(sub) -> None:
    aw = sub.add_parser(
        "awareness",
        help="Authorized security-awareness (anti-phishing training) tooling.",
    )
    aw_sub = aw.add_subparsers(dest="action", required=True)

    gen = aw_sub.add_parser(
        "generate",
        help="Generate an EDUCATIONAL landing page, training e-mail template, "
             "and per-recipient tracking tokens for an authorized campaign.",
    )
    gen.add_argument("--name", default="Security Awareness Exercise",
                     help="Campaign name (used in generated artifacts).")
    gen.add_argument("--authorized-by", dest="authorized_by",
                     help="Name of the person who approved this exercise (required).")
    gen.add_argument("--authorized-on", dest="authorized_on",
                     help="Approval date, ISO format YYYY-MM-DD (required).")
    gen.add_argument("--allow", action="append", default=[], metavar="DOMAIN|EMAIL",
                     help="Allowlist entry: a domain or e-mail (repeatable).")
    gen.add_argument("--allowlist-file", type=Path,
                     help="File with one allowlist entry (domain or e-mail) per line.")
    gen.add_argument("--recipient", action="append", default=[], metavar="EMAIL",
                     help="Recipient e-mail (repeatable).")
    gen.add_argument("--recipients-file", type=Path,
                     help="File with one recipient e-mail per line.")
    gen.add_argument("--base-url", dest="base_url", required=True,
                     help="Operator-hosted URL of the educational landing page.")
    gen.add_argument("--org-contact", dest="org_contact",
                     help="How trainees should reach the security team.")
    gen.add_argument("-o", "--output-dir", dest="output_dir", type=Path,
                     default=Path("awareness_campaign"),
                     help="Directory to write artifacts into (default: ./awareness_campaign).")

    tally = aw_sub.add_parser(
        "tally",
        help="Compute aggregate, non-punitive click metrics from a token list "
             "and a click log.",
    )
    tally.add_argument("--tokens-file", type=Path, required=True,
                       help="CSV (recipient,token,tracking_url) or newline token list.")
    tally.add_argument("--click-log", dest="click_log", type=Path, required=True,
                       help="File of observed tokens (one per line) from operator web logs.")


def _cmd_list(registry: Registry) -> int:
    for cat in Category:
        mods = registry.by_category(cat)
        if not mods:
            continue
        print(f"\n[{cat.value}]")
        for m in mods:
            scope = "scope-gated" if m.requires_scope else "passive"
            print(f"  {m.id:<32} {m.name}  ({m.intensity.value}, {scope})")
    print()
    return 0


def _select(registry: Registry, args: argparse.Namespace) -> list:
    if args.module:
        selected = []
        for mid in args.module:
            m = registry.get(mid)
            if m is None:
                print(f"error: unknown module {mid!r}", file=sys.stderr)
                raise SystemExit(2)
            selected.append(m)
        return selected
    if args.category:
        return registry.by_category(Category(args.category))
    # Safe default: passive-only, so a bare `run` never touches an out-of-scope host.
    return [m for m in registry.all() if not m.requires_scope]


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
        print(
            f"\n!! INTRUSIVE module(s) selected: {ids}\n"
            "   These may ALTER or DISRUPT the target (e.g. load testing).\n"
            f"   To confirm, type the target exactly ({args.target}); "
            "anything else aborts them."
        )
        try:
            answer = input("   Confirm target> ").strip()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer == args.target:
            options["confirm_intrusive"] = True
        else:
            print("   Confirmation failed — intrusive modules will be skipped.")
    return options


async def _cmd_run(registry: Registry, args: argparse.Namespace) -> int:
    scope = None
    if args.scope:
        try:
            scope = Scope.from_file(args.scope)
        except ScopeError as e:
            print(f"scope error: {e}", file=sys.stderr)
            return 2
        print(f"Scope loaded: {scope.summary()}")

    modules = _select(registry, args)
    options = _resolve_intrusive_confirmation(modules, args)
    engine = Engine(registry, scope=scope, options=options)
    report = Report(engagement=scope.engagement if scope else "ad-hoc")

    print(f"Running {len(modules)} module(s) against {args.target}\n")
    for m in modules:
        result = await engine.run_module(m, args.target)
        if result.skipped:
            print(f"  ~ {m.id}: SKIPPED — {result.skip_reason}")
            continue
        if not result.ok:
            print(f"  ! {m.id}: ERROR — {result.error}")
            continue
        report.add(result.findings)
        notable = [f for f in result.findings if f.severity.name != "INFO"]
        print(f"  ✓ {m.id}: {len(result.findings)} finding(s), {len(notable)} notable")

    print("\nSummary: " + ", ".join(f"{k} {v}" for k, v in report.counts().items()))

    if args.output:
        _write_report(report, args.output)
        print(f"Report written to {args.output}")

    if args.store:
        try:
            store = FindingStore(args.store)
            run_id = store.save_run(report.engagement, args.target, report.findings)
            print(f"Run #{run_id} persisted to store {args.store}")
        except StoreError as e:
            print(f"store error: {e}", file=sys.stderr)
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
        raise SystemExit(f"Unknown report format: {ext!r} (use .json/.md/.html)")


def _cmd_diff(args: argparse.Namespace) -> int:
    try:
        store = FindingStore(args.store)
        result = store.diff_latest(args.target)
    except StoreError as e:
        print(f"store error: {e}", file=sys.stderr)
        return 2

    if result["run_b"] is None:
        print(f"No runs found for {args.target!r} in {args.store}.")
        return 0
    if result["run_a"] is None:
        print(
            f"Only one run (#{result['run_b']}) for {args.target!r}; "
            "need at least two to diff."
        )
        return 0

    print(
        f"Diff for {args.target} — run #{result['run_a']} (baseline) "
        f"vs run #{result['run_b']} (latest)\n"
    )

    new = result["new"]
    resolved = result["resolved"]
    changed = result["changed_severity"]

    print(f"  New ({len(new)}):")
    for f in sorted(new, key=lambda x: -x["severity_level"]):
        print(f"    + [{f['severity']}] {f['title']}  ({f['module']} / {f['target']})")
    if not new:
        print("    (none)")

    print(f"\n  Resolved ({len(resolved)}):")
    for f in sorted(resolved, key=lambda x: -x["severity_level"]):
        print(f"    - [{f['severity']}] {f['title']}  ({f['module']} / {f['target']})")
    if not resolved:
        print("    (none)")

    print(f"\n  Changed severity ({len(changed)}):")
    for c in changed:
        print(
            f"    ~ {c['title']}  ({c['module']} / {c['target']}): "
            f"{c['from']} -> {c['to']}"
        )
    if not changed:
        print("    (none)")
    print()
    return 0


def _cmd_dashboard(args: argparse.Namespace) -> int:
    try:
        store = FindingStore(args.store)
        target = args.target or _resolve_latest_target(store)
        if target is None:
            print(f"No runs found in {args.store}; nothing to render.")
            return 0
        if not store.list_runs(target=target):
            print(f"No runs found for {target!r} in {args.store}.")
            return 0
        html = render_dashboard(store, target)
    except StoreError as e:
        print(f"store error: {e}", file=sys.stderr)
        return 2

    out = args.output or Path("dashboard.html")
    out.write_text(html)
    print(f"Dashboard written to {out}")
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
                print("awareness error: no recipients provided (use --recipient "
                      "or --recipients-file)", file=sys.stderr)
                return 2

            campaign = Campaign(
                name=args.name,
                authorization=authorization,
                allowlist=allowlist,
                base_url=args.base_url,
                recipients=recipients,
            )
        except AwarenessError as e:
            print(f"awareness error: {e}", file=sys.stderr)
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

        print(f"Authorized by {authorization.authorized_by} on "
              f"{authorization.authorized_on.isoformat()}")
        print(f"Allowlist OK · {len(campaign.recipients)} recipient(s) validated")
        print(f"Artifacts written to {out}/:")
        print("  landing_page.html   (educational — NO credential capture)")
        print("  email_template.txt  (training template — NOT sent by this tool)")
        print("  tokens.csv, tokens.json  (per-recipient tracking tokens)")
        return 0

    if args.action == "tally":
        try:
            tokens = _read_tokens(args.tokens_file)
            clicks = _read_lines(args.click_log)
        except OSError as e:
            print(f"awareness error: {e}", file=sys.stderr)
            return 2
        metrics = tally_clicks(tokens, clicks)
        print("Aggregate awareness metrics (non-punitive):")
        print(f"  sent         {metrics['sent']}")
        print(f"  clicked      {metrics['clicked']}")
        print(f"  not clicked  {metrics['not_clicked']}")
        print(f"  click rate   {metrics['click_rate'] * 100:.1f}%")
        if metrics["unknown_hits"]:
            print(f"  unknown hits {metrics['unknown_hits']} (tokens not in issued set)")
        return 0

    return 1


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    registry = Registry().discover()

    if args.command == "list":
        print(_BANNER)
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
