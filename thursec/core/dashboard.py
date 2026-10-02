"""Posture dashboard — a bird's-eye view over the findings store (PLAT2).

Where :class:`~thursec.core.report.Report` renders a *single* run's findings,
the dashboard renders *history*: it reads the :class:`~thursec.core.store.FindingStore`
built in PLAT1 and turns many runs into one self-contained HTML page —

* **summary tiles** with the per-severity counts of the most recent run,
* a **trend** of severity mix across runs, drawn as an inline-SVG stacked bar
  chart (no JavaScript, no external libraries, no CDN),
* the **latest diff** (what appeared, was resolved, or changed severity between
  the two most recent runs), and
* a **findings table** for the latest run, ordered by severity.

Everything is generated locally from the SQLite store; nothing here touches the
network. The severity colour scheme is shared with ``report.py`` for a
consistent visual language across deliverables.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

from .finding import Severity
from .store import FindingStore

# Severity palette — kept in sync with report.Report.to_html() so a severity
# always reads the same colour whether it shows up in a report or a dashboard.
SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "#7c1d1d",
    "HIGH": "#9a3412",
    "MEDIUM": "#854d0e",
    "LOW": "#1e3a5f",
    "INFO": "#334155",
}

# High-contrast accents used for text/borders tied to a severity on the dark
# background (the fill colours above are intentionally muted for large areas).
SEVERITY_ACCENTS: dict[str, str] = {
    "CRITICAL": "#f87171",
    "HIGH": "#fb923c",
    "MEDIUM": "#fbbf24",
    "LOW": "#60a5fa",
    "INFO": "#94a3b8",
}

# Severity names, most-severe first (CRITICAL … INFO).
_SEV_ORDER: list[str] = [s.name for s in reversed(Severity)]


class DashboardError(Exception):
    """Raised when a dashboard cannot be built (e.g. the store has no runs)."""


def _counts_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {name: 0 for name in _SEV_ORDER}
    for f in findings:
        name = str(f.get("severity", "")).upper()
        if name in counts:
            counts[name] += 1
    return counts


def _fmt_ts(ts: str) -> str:
    """Render an ISO timestamp compactly; fall back to the raw value."""
    try:
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return ts


def _resolve_target(store: FindingStore, target: str | None) -> str | None:
    """Return the target to report on: the given one, or the latest run's."""
    if target is not None:
        return target
    runs = store.list_runs()
    return runs[0]["target"] if runs else None


# --- SVG trend chart -------------------------------------------------------
def _render_trend_svg(runs_oldest_first: list[dict[str, Any]]) -> str:
    """Stacked bar chart (inline SVG) of severity mix per run.

    ``runs_oldest_first`` items carry an extra ``counts`` dict (per severity).
    Pure SVG: no scripts, no external assets. Each segment gets a ``<title>``
    for an accessible, no-JS hover tooltip.
    """
    if not runs_oldest_first:
        return "<p class='empty'>No runs to chart yet.</p>"

    # Geometry.
    pad_left, pad_right, pad_top, pad_bottom = 44, 12, 12, 34
    plot_h = 220
    n = len(runs_oldest_first)
    bar_w = 40
    gap = 20
    plot_w = n * bar_w + (n - 1) * gap if n > 0 else bar_w
    width = pad_left + plot_w + pad_right
    height = pad_top + plot_h + pad_bottom

    max_total = max(
        (sum(r["counts"].values()) for r in runs_oldest_first), default=0
    )
    max_total = max(max_total, 1)  # avoid division by zero; flat empty chart

    def y_for(value: float) -> float:
        return pad_top + plot_h - (value / max_total) * plot_h

    parts: list[str] = [
        f"<svg viewBox='0 0 {width} {height}' width='100%' "
        f"preserveAspectRatio='xMidYMid meet' role='img' "
        f"aria-label='Findings per run by severity' "
        f"style='max-width:{width}px'>"
    ]

    # Horizontal gridlines + y-axis ticks (0, mid, max).
    ticks = sorted({0, (max_total + 1) // 2, max_total})
    for t in ticks:
        y = y_for(t)
        parts.append(
            f"<line x1='{pad_left}' y1='{y:.1f}' x2='{width - pad_right}' "
            f"y2='{y:.1f}' stroke='#1e293b' stroke-width='1'/>"
        )
        parts.append(
            f"<text x='{pad_left - 8}' y='{y + 4:.1f}' text-anchor='end' "
            f"font-size='11' fill='#94a3b8'>{t}</text>"
        )

    # Bars.
    for i, run in enumerate(runs_oldest_first):
        x = pad_left + i * (bar_w + gap)
        y_cursor = pad_top + plot_h  # baseline, stack upward
        for sev in reversed(_SEV_ORDER):  # INFO at bottom … CRITICAL on top
            c = run["counts"].get(sev, 0)
            if c <= 0:
                continue
            seg_h = (c / max_total) * plot_h
            y_cursor -= seg_h
            parts.append(
                f"<rect x='{x}' y='{y_cursor:.1f}' width='{bar_w}' "
                f"height='{seg_h:.1f}' fill='{SEVERITY_COLORS[sev]}'>"
                f"<title>Run #{run['id']} — {sev.capitalize()}: {c}</title></rect>"
            )
        # x-axis label: run id.
        parts.append(
            f"<text x='{x + bar_w / 2:.1f}' y='{pad_top + plot_h + 16}' "
            f"text-anchor='middle' font-size='11' fill='#94a3b8'>"
            f"#{run['id']}</text>"
        )

    parts.append("</svg>")
    return "".join(parts)


def _render_legend() -> str:
    items = []
    for sev in _SEV_ORDER:
        items.append(
            f"<span class='legend-item'><span class='swatch' "
            f"style='background:{SEVERITY_COLORS[sev]}'></span>"
            f"{sev.capitalize()}</span>"
        )
    return "<div class='legend'>" + "".join(items) + "</div>"


def _render_tiles(counts: dict[str, int]) -> str:
    total = sum(counts.values())
    tiles = [
        "<div class='tile tile-total'>"
        f"<div class='tile-num'>{total}</div>"
        "<div class='tile-label'>Total</div></div>"
    ]
    for sev in _SEV_ORDER:
        n = counts[sev]
        dim = " dim" if n == 0 else ""
        tiles.append(
            f"<div class='tile{dim}' style='--accent:{SEVERITY_ACCENTS[sev]}'>"
            f"<div class='tile-num'>{n}</div>"
            f"<div class='tile-label'>{sev.capitalize()}</div></div>"
        )
    return "<div class='tiles'>" + "".join(tiles) + "</div>"


def _render_diff(diff: dict[str, Any]) -> str:
    if diff.get("run_a") is None:
        return (
            "<p class='empty'>Only one run so far — need at least two runs of "
            "this target to compute a diff.</p>"
        )

    new = diff.get("new", [])
    resolved = diff.get("resolved", [])
    changed = diff.get("changed_severity", [])

    def finding_list(items: list[dict[str, Any]], sign: str) -> str:
        if not items:
            return "<li class='none'>(none)</li>"
        rows = []
        for f in sorted(items, key=lambda x: -int(x.get("severity_level", 0))):
            sev = str(f["severity"]).upper()
            rows.append(
                f"<li><span class='dot' style='background:{SEVERITY_COLORS.get(sev, '#334155')}'></span>"
                f"<span class='sign'>{sign}</span>"
                f"<span class='ftitle'>{html.escape(f['title'])}</span>"
                f"<span class='fmeta'>{html.escape(f['module'])} · {html.escape(f['target'])}</span></li>"
            )
        return "".join(rows)

    def changed_list(items: list[dict[str, Any]]) -> str:
        if not items:
            return "<li class='none'>(none)</li>"
        rows = []
        for c in sorted(items, key=lambda x: -int(x.get("to_level", 0))):
            frm = str(c["from"]).upper()
            to = str(c["to"]).upper()
            rows.append(
                "<li><span class='sign'>~</span>"
                f"<span class='ftitle'>{html.escape(c['title'])}</span>"
                f"<span class='change'>"
                f"<span class='badge' style='background:{SEVERITY_COLORS.get(frm, '#334155')}'>{c['from'].capitalize()}</span>"
                f"<span class='arrow'>&rarr;</span>"
                f"<span class='badge' style='background:{SEVERITY_COLORS.get(to, '#334155')}'>{c['to'].capitalize()}</span></span>"
                f"<span class='fmeta'>{html.escape(c['module'])} · {html.escape(c['target'])}</span></li>"
            )
        return "".join(rows)

    return (
        "<div class='diff-grid'>"
        f"<div class='diff-col'><h3>New <span class='cnt'>{len(new)}</span></h3>"
        f"<ul class='diff-list new'>{finding_list(new, '+')}</ul></div>"
        f"<div class='diff-col'><h3>Resolved <span class='cnt'>{len(resolved)}</span></h3>"
        f"<ul class='diff-list resolved'>{finding_list(resolved, '-')}</ul></div>"
        f"<div class='diff-col'><h3>Changed severity <span class='cnt'>{len(changed)}</span></h3>"
        f"<ul class='diff-list changed'>{changed_list(changed)}</ul></div>"
        "</div>"
    )


def _render_table(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "<p class='empty'>No findings in the latest run.</p>"
    rows = []
    for f in findings:  # store.get_findings already sorts by severity desc
        sev = str(f["severity"]).upper()
        rows.append(
            f"<tr><td><span class='sev' style='background:{SEVERITY_COLORS.get(sev, '#334155')}'>"
            f"{html.escape(f['severity'].capitalize())}</span></td>"
            f"<td>{html.escape(f['title'])}</td>"
            f"<td><code>{html.escape(f['module'])}</code></td>"
            f"<td><code>{html.escape(f['target'])}</code></td>"
            f"<td>{html.escape(f.get('recommendation', '') or '')}</td></tr>"
        )
    return (
        "<table><thead><tr><th>Severity</th><th>Finding</th><th>Module</th>"
        "<th>Target</th><th>Recommendation</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


_STYLE = """
 *{box-sizing:border-box}
 body{font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;margin:0;
      background:#0f172a;color:#e2e8f0}
 .wrap{max-width:1100px;margin:0 auto;padding:32px 16px 64px}
 h1{margin:0 0 4px;font-size:26px;letter-spacing:-.01em}
 .meta{color:#94a3b8;margin-bottom:28px;font-size:14px}
 section{margin:36px 0}
 h2{font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:#94a3b8;
    margin:0 0 14px;padding-bottom:8px;border-bottom:1px solid #1e293b}
 .tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px}
 .tile{background:#1e293b;border:1px solid #334155;border-radius:10px;
       padding:16px;border-left:4px solid var(--accent,#475569)}
 .tile-total{border-left-color:#e2e8f0}
 .tile.dim{opacity:.5}
 .tile-num{font-size:30px;font-weight:700;line-height:1}
 .tile-label{color:#94a3b8;font-size:12px;text-transform:uppercase;
             letter-spacing:.05em;margin-top:6px}
 .card{background:#111c33;border:1px solid #1e293b;border-radius:12px;padding:20px}
 .legend{display:flex;flex-wrap:wrap;gap:16px;margin-top:14px;font-size:13px;
         color:#cbd5e1}
 .legend-item{display:inline-flex;align-items:center;gap:6px}
 .swatch{width:12px;height:12px;border-radius:3px;display:inline-block}
 .diff-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}
 .diff-col h3{margin:0 0 10px;font-size:14px;font-weight:600}
 .diff-col h3 .cnt{display:inline-block;min-width:22px;text-align:center;
   background:#1e293b;border-radius:10px;padding:1px 8px;font-size:12px;
   color:#cbd5e1;margin-left:4px}
 .diff-list{list-style:none;margin:0;padding:0;font-size:14px}
 .diff-list li{display:flex;align-items:center;flex-wrap:wrap;gap:8px;
   padding:8px 0;border-bottom:1px solid #1e293b}
 .diff-list li.none{color:#64748b;font-style:italic;border-bottom:none}
 .dot{width:9px;height:9px;border-radius:50%;flex:0 0 auto}
 .sign{font-weight:700;color:#94a3b8;width:12px;flex:0 0 auto}
 .diff-list.new .sign{color:#4ade80}
 .diff-list.resolved .sign{color:#60a5fa}
 .ftitle{font-weight:500}
 .fmeta{color:#64748b;font-size:12px;width:100%;padding-left:20px}
 .change{display:inline-flex;align-items:center;gap:6px}
 .arrow{color:#94a3b8}
 .badge{color:#fff;font-size:11px;font-weight:600;padding:1px 7px;border-radius:4px}
 table{width:100%;border-collapse:collapse;margin-top:4px}
 th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #1e293b;
       vertical-align:top}
 th{color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
 .sev{display:inline-block;padding:2px 8px;border-radius:4px;color:#fff;
      font-size:12px;font-weight:600}
 code{background:#1e293b;padding:1px 5px;border-radius:3px;font-size:13px}
 .empty{color:#64748b;font-style:italic}
 @media (max-width:640px){.wrap{padding:20px 12px 48px}h1{font-size:22px}}
"""


def render_dashboard(store: FindingStore, target: str | None = None) -> str:
    """Build the self-contained dashboard HTML for ``target``.

    If ``target`` is ``None``, the most recently run target is used. When the
    store has no runs (for that target) a valid empty-state page is returned
    rather than raising.
    """
    resolved_target = _resolve_target(store, target)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    if resolved_target is None:
        return _page(
            title="ThurSec posture",
            subtitle=f"No runs recorded yet · generated {generated}",
            body="<section><p class='empty'>This store has no runs. Run a scan "
            "with <code>--store</code> to populate it.</p></section>",
        )

    runs = store.list_runs(target=resolved_target)
    if not runs:
        return _page(
            title="ThurSec posture",
            subtitle=f"{html.escape(resolved_target)} · no runs · generated {generated}",
            body="<section><p class='empty'>No runs recorded for this target.</p></section>",
        )

    latest = runs[0]
    latest_findings = store.get_findings(latest["id"])
    counts = _counts_by_severity(latest_findings)

    # Trend: oldest → newest, capped for readability.
    trend_runs = list(reversed(runs[:15]))
    for r in trend_runs:
        r["counts"] = _counts_by_severity(store.get_findings(r["id"]))

    diff = store.diff_latest(resolved_target)

    subtitle = (
        f"{html.escape(resolved_target)} · {len(runs)} run(s) · "
        f"latest run #{latest['id']} at {_fmt_ts(latest['finished_at'])} · "
        f"generated {generated}"
    )

    if diff.get("run_a") is not None:
        diff_heading = (
            f"Latest diff (run #{diff['run_a']} &rarr; #{diff['run_b']})"
        )
    else:
        diff_heading = "Latest diff"

    body = (
        "<section><h2>Current posture — latest run</h2>"
        f"{_render_tiles(counts)}</section>"
        "<section><h2>Trend across runs</h2>"
        f"<div class='card'>{_render_trend_svg(trend_runs)}{_render_legend()}</div>"
        "</section>"
        f"<section><h2>{diff_heading}</h2>{_render_diff(diff)}</section>"
        "<section><h2>Findings — latest run</h2>"
        f"{_render_table(latest_findings)}</section>"
    )

    return _page(title="ThurSec posture", subtitle=subtitle, body=body)


def _page(title: str, subtitle: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>{_STYLE}</style></head>
<body><div class="wrap">
<h1>ThurSec posture dashboard</h1>
<div class="meta">{subtitle}</div>
{body}
</div></body></html>"""
