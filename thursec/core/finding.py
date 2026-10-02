"""Findings — the unit of everything ThurSec reports.

Every module emits ``Finding`` objects. Keeping one shared, well-typed shape is
what lets us correlate, deduplicate, rank and export results across very
different tools (a TLS check and a dependency scan land in the same table).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Ordered so findings sort naturally by how much they matter."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | "Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]

    def __str__(self) -> str:  # nicer rendering in reports/TUI
        return self.name.capitalize()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class Finding:
    """A single observation about a target.

    ``module`` and ``target`` say where it came from; ``evidence`` carries the
    raw proof (a header value, a banner, a tool line) so a human can verify it.
    """

    module: str
    target: str
    title: str
    severity: Severity
    description: str = ""
    recommendation: str = ""
    evidence: str = ""
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=_utcnow)

    def __post_init__(self) -> None:
        # Accept loose severity input ("high", 3, Severity.HIGH) at the boundary.
        self.severity = Severity.parse(self.severity)

    @property
    def fingerprint(self) -> str:
        """Stable id for dedup across runs: same issue => same fingerprint.

        Deliberately excludes timestamp and evidence so re-scanning the same
        target doesn't produce "new" findings for an unchanged problem.
        """
        raw = f"{self.module}|{self.target}|{self.title}|{int(self.severity)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "module": self.module,
            "target": self.target,
            "title": self.title,
            "severity": self.severity.name,
            "severity_level": int(self.severity),
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "references": list(self.references),
            "metadata": dict(self.metadata),
            "discovered_at": self.discovered_at.isoformat(),
        }
