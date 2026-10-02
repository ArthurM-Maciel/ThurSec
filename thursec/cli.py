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
from .core.module import Category
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
    return p


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


async def _cmd_run(registry: Registry, args: argparse.Namespace) -> int:
    scope = None
    if args.scope:
        try:
            scope = Scope.from_file(args.scope)
        except ScopeError as e:
            print(f"scope error: {e}", file=sys.stderr)
            return 2
        print(f"Scope loaded: {scope.summary()}")

    engine = Engine(registry, scope=scope)
    modules = _select(registry, args)
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
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
