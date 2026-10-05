"""The plugin contract every ThurSec module implements.

The whole point of the architecture: a module is a self-describing class. The
engine discovers modules, shows them in the menu, enforces scope for the active
ones, runs them, and collects their findings — without the core knowing anything
about *what* a given module does. Adding a capability = dropping in a new class.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from .finding import Finding

if TYPE_CHECKING:
    from .context import RunContext


class Category(str, Enum):
    RECON = "recon"
    VULN = "vuln"
    DEPS_SECRETS = "deps_secrets"
    CONFIG_AUDIT = "config_audit"
    RESILIENCE = "resilience"


class Intensity(str, Enum):
    """How much the module *touches* the target — drives the scope gate.

    PASSIVE  : no packets to the target (whois, cert transparency, repo scan).
    ACTIVE   : normal interaction (requests, port scan) — scope enforced.
    INTRUSIVE: may change state / be disruptive — scope enforced + confirmation.
    """

    PASSIVE = "passive"
    ACTIVE = "active"
    INTRUSIVE = "intrusive"


@dataclass(slots=True)
class ModuleResult:
    module: str
    findings: list[Finding] = field(default_factory=list)
    ok: bool = True
    error: str | None = None
    skipped: bool = False
    skip_reason: str | None = None


class Module(abc.ABC):
    """Base class for all ThurSec modules.

    Subclasses set the class attributes and implement :meth:`run`. Keep ``run``
    focused on producing findings; the engine handles scope, timing and errors.
    """

    id: str = ""
    name: str = ""
    category: Category
    intensity: Intensity = Intensity.ACTIVE
    description: str = ""
    # External binaries this module shells out to (for pre-flight checks /
    # install hints). Empty means pure-Python, always available.
    requires_tools: tuple[str, ...] = ()

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        # Fail loudly at import time if a module is mis-declared.
        if getattr(cls, "__abstractmethods__", None):
            return
        if not cls.id:
            raise TypeError(f"{cls.__name__} must define a non-empty `id`.")
        if not getattr(cls, "category", None):
            raise TypeError(f"{cls.__name__} must define a `category`.")

    @property
    def requires_scope(self) -> bool:
        """Active and intrusive modules may only run against in-scope targets."""
        return self.intensity in (Intensity.ACTIVE, Intensity.INTRUSIVE)

    @abc.abstractmethod
    async def run(self, ctx: "RunContext") -> list[Finding]:
        """Do the work and return findings. Raise on unrecoverable error."""
        raise NotImplementedError
