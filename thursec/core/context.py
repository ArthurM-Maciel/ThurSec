"""RunContext — everything a module is handed when it runs.

Bundling these means module signatures stay stable as the engine grows: a new
shared capability becomes a field here, not a change to every ``run`` method.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .finding import Finding, Severity
from .runner import CommandRunner
from .scope import Scope


@dataclass(slots=True)
class RunContext:
    target: str
    scope: Scope | None = None
    runner: CommandRunner = field(default_factory=CommandRunner)
    options: dict[str, Any] = field(default_factory=dict)

    def finding(
        self,
        module: str,
        title: str,
        severity: Severity | str | int,
        **kwargs: Any,
    ) -> Finding:
        """Convenience factory so modules don't repeat ``target=`` everywhere."""
        return Finding(
            module=module,
            target=self.target,
            title=title,
            severity=severity,
            **kwargs,
        )
