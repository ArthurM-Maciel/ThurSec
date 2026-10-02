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

from .context import RunContext
from .module import Category, Module, ModuleResult
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
    def __init__(self, registry: Registry, scope: Scope | None = None):
        self.registry = registry
        self.scope = scope

    async def run_module(self, module: Module, target: str) -> ModuleResult:
        # Scope gate: active/intrusive modules require an authorized target.
        if module.requires_scope:
            if self.scope is None:
                return ModuleResult(
                    module=module.id,
                    skipped=True,
                    skip_reason=(
                        f"{module.id} is {module.intensity.value}; load a scope file "
                        f"(--scope) before running it against {target!r}."
                    ),
                )
            try:
                self.scope.enforce(target)
            except ScopeError as e:
                return ModuleResult(
                    module=module.id, skipped=True, skip_reason=str(e)
                )

        ctx = RunContext(target=target, scope=self.scope)
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
