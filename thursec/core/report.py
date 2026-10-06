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
from .i18n import L, Lf


def _sev_label(name: str) -> str:
    """Localized display label for a severity name (JSON keys stay canonical)."""
    return {
        "CRITICAL": L("Crítico", "Critical"),
        "HIGH": L("Alto", "High"),
        "MEDIUM": L("Médio", "Medium"),
        "LOW": L("Baixo", "Low"),
        "INFO": L("Informativo", "Info"),
    }.get(name.upper(), name.capitalize())


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
            Lf("# Relatório ThurSec — {e}", "# ThurSec report — {e}", e=self.engagement),
            "",
            Lf(
                "_Gerado em {g}_",
                "_Generated {g}_",
                g=self.generated_at.isoformat(timespec="seconds"),
            ),
            "",
            L("## Resumo", "## Summary"),
            "",
            L("| Severidade | Quantidade |", "| Severity | Count |"),
            "| --- | --- |",
        ]
        for sev, n in self.counts().items():
            lines.append(f"| {_sev_label(sev)} | {n} |")
        lines += ["", L("## Achados", "## Findings"), ""]
        if not self.findings:
            lines.append(L("_Nenhum achado._", "_No findings._"))
        for f in self.sorted():
            lines += [
                f"### [{_sev_label(f.severity.name)}] {f.title}",
                "",
                Lf("- **Módulo:** `{m}`", "- **Module:** `{m}`", m=f.module),
                Lf("- **Alvo:** `{t}`", "- **Target:** `{t}`", t=f.target),
            ]
            if f.description:
                lines += ["", f.description]
            if f.evidence:
                lines += [
                    "",
                    L("**Evidência:**", "**Evidence:**"),
                    "",
                    "```",
                    f.evidence.strip(),
                    "```",
                ]
            if f.recommendation:
                lines += [
                    "",
                    Lf(
                        "**Recomendação:** {r}",
                        "**Recommendation:** {r}",
                        r=f.recommendation,
                    ),
                ]
            if f.references:
                lines += ["", L("**Referências:**", "**References:**")] + [
                    f"- {r}" for r in f.references
                ]
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
                f"{html.escape(_sev_label(sev))}</span></td>"
                f"<td>{html.escape(f.title)}</td>"
                f"<td><code>{html.escape(f.module)}</code></td>"
                f"<td><code>{html.escape(f.target)}</code></td>"
                f"<td>{html.escape(f.recommendation)}</td></tr>"
            )
        summary = " · ".join(
            f"{_sev_label(k)}: {v}" for k, v in self.counts().items()
        )
        return f"""<!doctype html>
<html lang="{L('pt-BR', 'en')}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(Lf('Relatório ThurSec — {e}', 'ThurSec report — {e}', e=self.engagement))}</title>
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
<h1>{L('Relatório ThurSec', 'ThurSec report')}</h1>
<div class="meta">{html.escape(self.engagement)} — {L('gerado em', 'generated')}
{html.escape(self.generated_at.isoformat(timespec='seconds'))}<br>{html.escape(summary)}</div>
<table><thead><tr><th>{L('Severidade', 'Severity')}</th><th>{L('Achado', 'Finding')}</th><th>{L('Módulo', 'Module')}</th><th>{L('Alvo', 'Target')}</th><th>{L('Recomendação', 'Recommendation')}</th></tr></thead>
<tbody>{''.join(rows) or f'<tr><td colspan=5>{L("Nenhum achado.", "No findings.")}</td></tr>'}</tbody></table>
</div></body></html>"""
