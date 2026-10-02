"""Vulnerability scanning via nuclei — orchestrates the external binary.

`nuclei <https://github.com/projectdiscovery/nuclei>`_ is a fast,
template-driven vulnerability scanner. This module shells out to it through the
shared :class:`CommandRunner` (no shell, hard timeout, captured output), reads
its JSONL output one line at a time, and maps every match onto a ThurSec
:class:`Finding` so nuclei results land in the same table as every other module.

Safety
------
nuclei ships templates that are genuinely dangerous to run unsupervised: denial
of service, intrusive checks, and fuzzing can disrupt or alter the target. By
default this module **excludes** those tag groups (``-exclude-tags
dos,intrusive,fuzzing``) so a scan stays non-destructive. The exclusion is only
lifted when the operator explicitly sets ``ctx.options["allow_intrusive"] =
True`` — an informed, opt-in decision for engagements where that is authorized.

This module is ACTIVE (it sends traffic to the target), so the engine's scope
gate applies before it ever runs.
"""

from __future__ import annotations

import json

from ...core.context import RunContext
from ...core.finding import Finding, Severity
from ...core.module import Category, Intensity, Module
from ...core.runner import ToolNotFoundError

# Default wall-clock budget for the whole scan. Overridable via
# ctx.options["timeout"]. nuclei can run for a while on large template sets.
_DEFAULT_TIMEOUT = 600.0

# Tag groups that may be destructive / disruptive. Excluded unless the operator
# explicitly opts in via ctx.options["allow_intrusive"].
_DANGEROUS_TAGS = "dos,intrusive,fuzzing"

# nuclei severity string -> ThurSec Severity.
_SEVERITY_MAP: dict[str, Severity] = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    # nuclei also emits "unknown" for some templates.
    "unknown": Severity.INFO,
}

_INSTALL_HINT = (
    "Install nuclei (Go): 'go install -v "
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest', or grab a release "
    "from https://github.com/projectdiscovery/nuclei/releases, then re-run."
)


class NucleiScan(Module):
    id = "vuln.nuclei"
    name = "Nuclei vulnerability scan"
    category = Category.VULN
    intensity = Intensity.ACTIVE
    description = (
        "Run the nuclei template-based vulnerability scanner against the target "
        "(destructive/intrusive templates excluded by default)."
    )
    requires_tools = ("nuclei",)

    async def run(self, ctx: RunContext) -> list[Finding]:
        timeout = float(ctx.options.get("timeout", _DEFAULT_TIMEOUT))
        allow_intrusive = bool(ctx.options.get("allow_intrusive", False))

        args = ["nuclei", "-u", ctx.target, "-jsonl", "-silent"]
        if not allow_intrusive:
            # Keep the scan non-destructive by default.
            args += ["-exclude-tags", _DANGEROUS_TAGS]

        # Let the operator append extra nuclei flags (e.g. ["-tags", "cve"]).
        extra = ctx.options.get("extra_args")
        if isinstance(extra, (list, tuple)):
            args += [str(a) for a in extra]

        try:
            result = await ctx.runner.run(args, timeout=timeout)
        except ToolNotFoundError:
            # Never let a missing binary crash the run — report it as INFO.
            return [
                ctx.finding(
                    self.id,
                    "nuclei is not installed",
                    Severity.INFO,
                    description=(
                        "The nuclei binary was not found on PATH, so no "
                        "vulnerability scan was performed."
                    ),
                    recommendation=_INSTALL_HINT,
                    references=["https://github.com/projectdiscovery/nuclei"],
                )
            ]

        if result.timed_out:
            return [
                ctx.finding(
                    self.id,
                    "nuclei scan timed out",
                    Severity.LOW,
                    description=(
                        f"The nuclei scan did not finish within {timeout:.0f}s and "
                        "was terminated; results may be incomplete."
                    ),
                    recommendation=(
                        "Increase ctx.options['timeout'], narrow the template set "
                        "(e.g. -tags), or scan fewer targets at once."
                    ),
                )
            ]

        findings = self._parse(ctx, result.stdout)

        if not findings:
            if result.returncode != 0:
                # nuclei failed and produced nothing usable — surface stderr.
                return [
                    ctx.finding(
                        self.id,
                        "nuclei scan failed",
                        Severity.LOW,
                        description=(
                            "nuclei exited with a non-zero status and produced no "
                            "parseable findings."
                        ),
                        evidence=(result.stderr or "").strip()[:2000],
                        recommendation=(
                            "Check the target is reachable and the nuclei "
                            "templates are installed ('nuclei -update-templates')."
                        ),
                    )
                ]
            # Clean run, nothing matched — record that explicitly.
            return [
                ctx.finding(
                    self.id,
                    "nuclei scan completed with no matches",
                    Severity.INFO,
                    description=(
                        "nuclei ran successfully and did not match any template "
                        "against the target."
                    ),
                )
            ]

        return findings

    # --- parsing -----------------------------------------------------------
    def _parse(self, ctx: RunContext, stdout: str) -> list[Finding]:
        """Parse nuclei JSONL output into findings, skipping malformed lines."""
        findings: list[Finding] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except (ValueError, TypeError):
                # Robustness: a single garbled line must not sink the whole scan.
                continue
            if not isinstance(record, dict):
                continue
            finding = self._to_finding(ctx, record)
            if finding is not None:
                findings.append(finding)
        return findings

    def _to_finding(self, ctx: RunContext, record: dict) -> Finding | None:
        info = record.get("info")
        info = info if isinstance(info, dict) else {}

        template_id = record.get("template-id") or record.get("templateID") or ""
        name = info.get("name") or template_id or "nuclei finding"

        sev_raw = str(info.get("severity", "info")).strip().lower()
        severity = _SEVERITY_MAP.get(sev_raw, Severity.INFO)

        matched_at = (
            record.get("matched-at")
            or record.get("matched")
            or record.get("host")
            or ctx.target
        )

        description = info.get("description") or ""
        matcher = record.get("matcher-name")
        if matcher:
            suffix = f"Matcher: {matcher}."
            description = f"{description}\n{suffix}".strip() if description else suffix

        references = info.get("reference")
        if isinstance(references, str):
            references = [references]
        elif isinstance(references, list):
            references = [str(r) for r in references if r]
        else:
            references = []

        tags = info.get("tags")
        if isinstance(tags, list):
            tags = ",".join(str(t) for t in tags)

        evidence = f"matched-at: {matched_at}"
        extracted = record.get("extracted-results")
        if extracted:
            evidence += f"\nextracted: {extracted}"

        return ctx.finding(
            self.id,
            f"nuclei: {name}",
            severity,
            description=description,
            evidence=evidence,
            references=references,
            metadata={
                "template-id": template_id,
                "matched-at": matched_at,
                "nuclei-severity": sev_raw,
                "tags": tags,
                "type": record.get("type"),
            },
        )
