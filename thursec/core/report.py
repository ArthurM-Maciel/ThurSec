"""Reporting — turn collected findings into something a human hands over.

A report is what separates a toolkit from a product. We dedup by fingerprint,
sort by severity, and export to JSON (machine), Markdown (PRs/tickets) and a
self-contained HTML file (the client deliverable).
"""

from __future__ import annotations

import html
import json
from collections import Counter
from typing import Any
from dataclasses import dataclass, field, replace
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


def collapse_rows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Agrupar as linhas do store como o relatório agrupa os achados.

    O store guarda tudo de propósito — é o que mantém o ``thursec diff``
    estável —, mas o painel é superfície de leitura: sem colapsar aqui, uma
    execução imprimia ALTO 1 no fim e o painel mostrava ALTO 3 para a mesma
    execução e o mesmo certificado.
    """
    grupos: dict[Any, dict[str, Any]] = {}
    ordem: list[Any] = []
    for f in findings:
        key = collapse_key(
            target=str(f.get("target", "")),
            metadata=f.get("metadata"),
            severity_level=int(f.get("severity_level", 0)),
            fingerprint=str(f.get("fingerprint", "")),
        )
        if not key:
            # Sem fingerprint nem dedup_key não há como dizer que duas linhas
            # são o mesmo defeito; agrupá-las pela chave vazia descartaria
            # achados distintos em silêncio.
            ordem.append(id(f))
            grupos[id(f)] = f
            continue
        atual = grupos.get(key)
        if atual is None:
            novo = dict(f)
            novo["metadata"] = dict(novo.get("metadata") or {})
            grupos[key] = novo
            ordem.append(key)
            continue
        # Mesmo critério de sobrevivente do relatório — menor id de módulo —
        # e o mesmo registro de quem mais viu, na mesma chave
        # (``metadata["also_seen_by"]``), para o painel não apresentar como
        # observação de um módulo só o que três encontraram.
        if str(f.get("module", "")) < str(atual.get("module", "")):
            vencedor, perdedor = dict(f), atual
            vencedor["metadata"] = dict(vencedor.get("metadata") or {})
        else:
            vencedor, perdedor = atual, f
        vistos = set(vencedor["metadata"].get("also_seen_by") or [])
        vistos.update((perdedor.get("metadata") or {}).get("also_seen_by") or [])
        vistos.add(str(perdedor.get("module", "")))
        vistos.discard(str(vencedor.get("module", "")))
        vencedor["metadata"]["also_seen_by"] = sorted(vistos)
        grupos[key] = vencedor
    return [grupos[k] for k in ordem]


def collapse_changes(changes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Agrupar mudanças de severidade por (alvo, título, de, para)."""
    grupos: dict[tuple, dict[str, Any]] = {}
    ordem: list[tuple] = []
    for c in changes:
        key = (
            str(c.get("target", "")),
            str(c.get("title", "")),
            str(c.get("from", "")),
            str(c.get("to", "")),
        )
        atual = grupos.get(key)
        if atual is None:
            grupos[key] = c
            ordem.append(key)
        elif str(c.get("module", "")) < str(atual.get("module", "")):
            grupos[key] = c
    return [grupos[k] for k in ordem]


def collapse_key(
    *,
    target: str,
    metadata: dict[str, Any] | None,
    severity_level: int,
    fingerprint: str,
) -> str:
    """A chave que diz quais achados descrevem o mesmo defeito.

    Vive fora do ``Report`` porque o painel lê linhas do SQLite, não objetos
    ``Finding``, e precisa agrupar do mesmo jeito: sem isso, uma execução
    terminava imprimindo ALTO 1 e o ``thursec dashboard`` mostrava ALTO 3 para
    a mesma execução e o mesmo certificado.

    A severidade entra de propósito: colapsar atravessando severidades deixaria
    o sobrevivente ser escolhido pelo nome do módulo e não pelo pior caso, e o
    achado mais grave sumiria do relatório enquanto seguia no histórico.
    """
    explicit = (metadata or {}).get("dedup_key")
    if not explicit:
        return fingerprint
    return f"{target}|{explicit}|{severity_level}"


def _tally(findings: list[Finding]) -> dict[str, int]:
    c = Counter(f.severity for f in findings)
    return {s.name: c.get(s, 0) for s in reversed(Severity)}


@dataclass(slots=True)
class Report:
    engagement: str = "ad-hoc"
    findings: list[Finding] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def add(self, findings: list[Finding]) -> None:
        """Acrescentar achados, deduplicando por fingerprint — como sempre.

        O que *não* acontece aqui é o colapso por ``dedup_key``: ele é só de
        apresentação (ver :meth:`collapsed`). ``findings`` continua sendo a
        lista completa porque é ela que vai para o histórico em SQLite, e lá
        cada achado precisa do seu próprio fingerprint. Colapsar antes de
        salvar fazia o ``thursec diff`` anunciar como "desapareceu" o achado
        de um módulo que simplesmente foi absorvido por outro — e, como o
        sobrevivente depende da ordem de execução, uma execução por categoria
        e uma execução completa gravavam fingerprints diferentes para o mesmo
        defeito, produzindo um par apareceu/desapareceu a cada diff.
        """
        seen = {f.fingerprint for f in self.findings}
        for f in findings:
            if f.fingerprint not in seen:
                self.findings.append(f)
                seen.add(f.fingerprint)

    def collapsed(self) -> list[Finding]:
        """A visão de leitura: um defeito do alvo aparece uma vez só.

        O ``fingerprint`` inclui o módulo — tem de incluir, porque o histórico
        é indexado por ele — então um defeito do *alvo* que três módulos
        encontram na mesma execução aparecia três vezes e contava três vezes no
        resumo. Um certificado que não cobre o domínio é um problema, não três.
        Um achado pode declarar ``metadata["dedup_key"]`` e os homônimos são
        absorvidos, com os módulos restantes listados em ``also_seen_by``.

        O sobrevivente é escolhido pelo menor id de módulo, não por ordem de
        chegada: o ``fingerprint`` e o ``module`` do achado colapsado vão para
        o relatório JSON, e por ordem de chegada ``-c config_audit`` e uma
        execução completa gravariam módulos diferentes para o mesmo defeito.
        """
        groups: dict[str, list[Finding]] = {}
        order: list[str] = []
        for f in self.findings:
            key = self._key(f)
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(f)

        result: list[Finding] = []
        for key in order:
            members = groups[key]
            if len(members) == 1:
                result.append(members[0])
                continue
            winner = min(members, key=lambda f: f.module)
            # Cópia: o colapso é uma visão, não pode sujar o que vai para o
            # store nem alterar metadata de um achado já contabilizado.
            clone = replace(winner, metadata=dict(winner.metadata))
            others = sorted({f.module for f in members if f.module != winner.module})
            if others:
                clone.metadata["also_seen_by"] = others
            result.append(clone)
        return result

    @staticmethod
    def _key(finding: Finding) -> str:
        return collapse_key(
            target=finding.target,
            metadata=finding.metadata,
            severity_level=int(finding.severity),
            fingerprint=finding.fingerprint,
        )

    def sorted(self) -> list[Finding]:
        return sorted(
            self.collapsed(), key=lambda f: (-int(f.severity), f.module, f.target)
        )

    def counts(self) -> dict[str, int]:
        return _tally(self.collapsed())

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
        # Uma vez só: ``sorted()`` e ``counts()`` refazem o agrupamento a cada
        # chamada, e este método as usava três vezes.
        findings = self.sorted()
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
        for sev, n in _tally(findings).items():
            lines.append(f"| {_sev_label(sev)} | {n} |")
        lines += ["", L("## Achados", "## Findings"), ""]
        if not findings:
            lines.append(L("_Nenhum achado._", "_No findings._"))
        for f in findings:
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
