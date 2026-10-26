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


def coerce_timeout(value: object, default: float) -> float:
    """Timeout seconds from an operator option, falling back to ``default``.

    A nonsense value must not raise — a typo in ``--opt`` would be swallowed by
    a module's error handling and reported as a network failure, pointing the
    operator at the target instead of at their own command line. Text, ``None``,
    zero and negatives all fall back.

    ``bool`` is rejected explicitly: the CLI coerces the literal ``true`` to
    ``True`` and ``float(True)`` is ``1.0``, which would otherwise pass the
    positive check and impose the shortest possible timeout.
    """
    if isinstance(value, bool):
        return default
    try:
        seconds = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return seconds if seconds > 0 else default


def scoped_options(options: dict[str, Any], module_id: str) -> dict[str, Any]:
    """Resolve the flat ``--opt`` key space into one module's view of it.

    ``--opt`` is a single namespace shared by every module in a run, so a bare
    ``timeout=60`` meant for one module used to truncate all the others — a
    ``-c vuln --opt timeout=60`` would cut ``vuln.nuclei`` from its 600s default
    down to 60. A key may therefore be prefixed with a module id:

        timeout=60                        -> every module in the run
        vuln.cve_lookup.timeout=60        -> only vuln.cve_lookup

    The scoped value wins over the bare one, and a key scoped to a *different*
    module is dropped rather than leaking through under its bare name. Modules
    read ``ctx.options`` exactly as before; the engine hands each one the dict
    this returns.
    """
    resolved: dict[str, Any] = {}
    scoped: dict[str, Any] = {}

    for key, value in options.items():
        prefix, dot, name = key.rpartition(".")
        if not dot:
            resolved[key] = value
        elif prefix == module_id and name:
            scoped[name] = value
        # else: scoped to another module — not this module's business.

    resolved.update(scoped)
    return resolved


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
