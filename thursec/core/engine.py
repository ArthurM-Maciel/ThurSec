"""Engine — discovers modules and runs them with scope + error handling.

Discovery walks ``thursec.modules`` and registers every concrete ``Module``
subclass. The engine is the one place that enforces the scope gate, so no module
can accidentally skip it.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import time
from typing import Any

from .context import RunContext
from .i18n import Lf
from .module import Category, Intensity, Module, ModuleResult
from .scope import Scope, ScopeError


class Registry:
    def __init__(self) -> None:
        self._modules: dict[str, Module] = {}

    def register(self, module: Module) -> None:
        if module.id in self._modules:
            raise ValueError(f"Duplicate module id: {module.id!r}")
        self._modules[module.id] = module

    def all(self) -> list[Module]:
        return sorted(self._modules.values(), key=lambda m: (m.category.value, m.id))

    def by_category(self, category: Category) -> list[Module]:
        return [m for m in self.all() if m.category == category]

    def get(self, module_id: str) -> Module | None:
        return self._modules.get(module_id)

    def discover(self, package: str = "thursec.modules") -> "Registry":
        pkg = importlib.import_module(package)
        for info in pkgutil.walk_packages(pkg.__path__, prefix=pkg.__name__ + "."):
            module = importlib.import_module(info.name)
            for _, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, Module)
                    and obj is not Module
                    and not inspect.isabstract(obj)
                    and obj.__module__ == module.__name__  # avoid re-registering imports
                ):
                    self.register(obj())
        return self


class Engine:
    """Runs modules behind the safety gates the core guarantees.

    Two independent barriers protect the target, applied in this order:

    1. **Scope gate** — ``ACTIVE`` and ``INTRUSIVE`` modules
       (``module.requires_scope``) may only touch a target the loaded scope
       authorizes. No scope, or an out-of-scope target, skips the module.
    2. **Intrusive confirmation** — ``INTRUSIVE`` modules may change state or
       disrupt the target, so on top of being in scope they require an
       *explicit* confirmation. The engine reads it from its run options
       (surfaced to modules as ``ctx.options``): the CLI sets
       ``confirm_intrusive=True`` when the operator passes ``--confirm-intrusive``
       or answers the interactive prompt. The two barriers are independent —
       confirmation never substitutes for scope, and scope never implies
       confirmation. An intrusive module runs only with *both*.

    ``options`` is a free-form dict threaded into every ``RunContext`` so
    callers can pass run-wide flags (like the confirmation above) to modules
    without widening the ``run`` signature.
    """

    def __init__(
        self,
        registry: Registry,
        scope: Scope | None = None,
        options: dict[str, Any] | None = None,
    ):
        self.registry = registry
        self.scope = scope
        self.options: dict[str, Any] = options or {}

    async def run_module(self, module: Module, target: str) -> ModuleResult:
        # Barrier 1 — scope gate: active/intrusive modules require an
        # authorized target.
        if module.requires_scope:
            if self.scope is None:
                return ModuleResult(
                    module=module.id,
                    skipped=True,
                    skip_reason=Lf(
                        "{mid} é {intensity}; carregue um arquivo de escopo "
                        "(--scope) antes de executá-lo contra {target!r}.",
                        "{mid} is {intensity}; load a scope file "
                        "(--scope) before running it against {target!r}.",
                        mid=module.id,
                        intensity=module.intensity.value,
                        target=target,
                    ),
                )
            try:
                self.scope.enforce(target)
            except ScopeError as e:
                return ModuleResult(
                    module=module.id, skipped=True, skip_reason=str(e)
                )

        # Barrier 2 — intrusive confirmation: being in scope is not enough for
        # a module that may disrupt the target; it also needs an explicit
        # confirmation (set by the CLI via --confirm-intrusive or its prompt).
        if (
            module.intensity == Intensity.INTRUSIVE
            and self.options.get("confirm_intrusive") is not True
        ):
            return ModuleResult(
                module=module.id,
                skipped=True,
                skip_reason=Lf(
                    "{mid} é INTRUSIVE e pode perturbar o alvo; execute "
                    "novamente com confirmação explícita (--confirm-intrusive) "
                    "para prosseguir.",
                    "{mid} is INTRUSIVE and may disrupt the target; "
                    "re-run with explicit confirmation (--confirm-intrusive) "
                    "to proceed.",
                    mid=module.id,
                ),
            )

        ctx = RunContext(target=target, scope=self.scope, options=self.options)
        started = time.monotonic()
        try:
            findings = await module.run(ctx)
        except Exception as e:  # a broken module must not sink the whole run
            return ModuleResult(
                module=module.id,
                ok=False,
                error=f"{type(e).__name__}: {e}",
            )
        result = ModuleResult(module=module.id, findings=list(findings))
        result_elapsed = time.monotonic() - started
        for f in result.findings:
            f.metadata.setdefault("elapsed_s", round(result_elapsed, 3))
        return result
