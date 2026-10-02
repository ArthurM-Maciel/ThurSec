"""Reporting — turn collected findings into something a human hands over.

A report is what separates a toolkit from a product. We dedup by fingerprint,
sort by severity, and export to JSON (machine), Markdown (PRs/tickets) and a
self-contained HTML file (the client deliverable).
"""

from __future__ import annotations

import html
import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .finding import Finding, Severity


@dataclass(slots=True)
class Report:
    engagement: str = "ad-hoc"
    findings: list[Finding] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def add(self, findings: list[Finding]) -> None:
        seen = {f.fingerprint for f in self.findings}
        for f in findings:
            if f.fingerprint not in seen:
                self.findings.append(f)
                seen.add(f.fingerprint)

    def sorted(self) -> list[Finding]:
        return sorted(
            self.findings, key=lambda f: (-int(f.severity), f.module, f.target)
        )

    def counts(self) -> dict[str, int]:
        c = Counter(f.severity for f in self.findings)
        return {s.name: c.get(s, 0) for s in reversed(Severity)}

    # --- exporters ---------------------------------------------------------
    def to_json(self) -> str:
        return json.dumps(
            {
                "engagement": self.engagement,
                "generated_at": self.generated_at.isoformat(),
                "summary": self.counts(),
                "findings": [f.to_dict() for f in self.sorted()],
            },
            indent=2,
        )

    def to_markdown(self) -> str:
        lines = [
            f"# ThurSec report — {self.engagement}",
            "",
            f"_Generated {self.generated_at.isoformat(timespec='seconds')}_",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "| --- | --- |",
        ]
        for sev, n in self.counts().items():
            lines.append(f"| {sev.capitalize()} | {n} |")
        lines += ["", "## Findings", ""]
        if not self.findings:
            lines.append("_No findings._")
        for f in self.sorted():
            lines += [
                f"### [{f.severity}] {f.title}",
                "",
                f"- **Module:** `{f.module}`",
                f"- **Target:** `{f.target}`",
            ]
            if f.description:
                lines += ["", f.description]
            if f.evidence:
                lines += ["", "**Evidence:**", "", "```", f.evidence.strip(), "```"]
            if f.recommendation:
                lines += ["", f"**Recommendation:** {f.recommendation}"]
            if f.references:
                lines += ["", "**References:**"] + [f"- {r}" for r in f.references]
            lines.append("")
        return "\n".join(lines)

    def to_html(self) -> str:
        rows = []
        colors = {
            "CRITICAL": "#7c1d1d", "HIGH": "#9a3412", "MEDIUM": "#854d0e",
            "LOW": "#1e3a5f", "INFO": "#334155",
        }
        for f in self.sorted():
            sev = f.severity.name
            rows.append(
                f"<tr><td><span class='sev' style='background:{colors[sev]}'>"
                f"{html.escape(str(f.severity))}</span></td>"
                f"<td>{html.escape(f.title)}</td>"
                f"<td><code>{html.escape(f.module)}</code></td>"
                f"<td><code>{html.escape(f.target)}</code></td>"
                f"<td>{html.escape(f.recommendation)}</td></tr>"
            )
        summary = " · ".join(
            f"{k.capitalize()}: {v}" for k, v in self.counts().items()
        )
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ThurSec report — {html.escape(self.engagement)}</title>
<style>
 body{{font:15px/1.5 system-ui,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}}
 .wrap{{max-width:1000px;margin:0 auto;padding:32px 16px}}
 h1{{margin:0 0 4px}} .meta{{color:#94a3b8;margin-bottom:24px}}
 table{{width:100%;border-collapse:collapse}}
 th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid #1e293b;vertical-align:top}}
 th{{color:#94a3b8;font-size:13px;text-transform:uppercase;letter-spacing:.04em}}
 .sev{{display:inline-block;padding:2px 8px;border-radius:4px;color:#fff;font-size:12px;font-weight:600}}
 code{{background:#1e293b;padding:1px 5px;border-radius:3px;font-size:13px}}
</style></head><body><div class="wrap">
<h1>ThurSec report</h1>
<div class="meta">{html.escape(self.engagement)} — generated
{html.escape(self.generated_at.isoformat(timespec='seconds'))}<br>{html.escape(summary)}</div>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Module</th><th>Target</th><th>Recommendation</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=5>No findings.</td></tr>'}</tbody></table>
</div></body></html>"""
