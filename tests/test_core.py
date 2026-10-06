import pytest

from thursec.core import i18n
from thursec.core.context import RunContext
from thursec.core.engine import Engine, Registry
from thursec.core.finding import Finding, Severity
from thursec.core.module import Category, Intensity, Module
from thursec.core.report import Report
from thursec.core.scope import Scope


@pytest.fixture(autouse=True)
def _english_engine_messages():
    """Engine skip reasons are now i18n'd (pt by default). These tests assert on
    the English wording, so pin the language to 'en' for the module and restore
    it afterwards."""
    previous = i18n.get_lang()
    i18n.set_lang("en")
    try:
        yield
    finally:
        i18n.set_lang(previous)


# --- findings -------------------------------------------------------------
def test_severity_parse():
    assert Severity.parse("high") is Severity.HIGH
    assert Severity.parse(3) is Severity.HIGH
    assert Severity.parse(Severity.LOW) is Severity.LOW


def test_fingerprint_is_stable_and_ignores_evidence():
    a = Finding("m", "t", "title", Severity.HIGH, evidence="x")
    b = Finding("m", "t", "title", Severity.HIGH, evidence="DIFFERENT")
    assert a.fingerprint == b.fingerprint


def test_report_dedups_and_sorts():
    r = Report()
    r.add([Finding("m", "t", "low", Severity.LOW)])
    r.add([Finding("m", "t", "crit", Severity.CRITICAL)])
    r.add([Finding("m", "t", "low", Severity.LOW)])  # dup
    assert len(r.findings) == 2
    assert r.sorted()[0].title == "crit"


# --- a fake module to drive the engine ------------------------------------
class _PassiveMod(Module):
    id = "test.passive"
    name = "passive"
    category = Category.RECON
    intensity = Intensity.PASSIVE

    async def run(self, ctx: RunContext):
        return [ctx.finding(self.id, "hello", Severity.INFO)]


class _ActiveMod(Module):
    id = "test.active"
    name = "active"
    category = Category.VULN
    intensity = Intensity.ACTIVE

    async def run(self, ctx: RunContext):
        return [ctx.finding(self.id, "touched", Severity.LOW)]


@pytest.mark.asyncio
async def test_active_module_skipped_without_scope():
    reg = Registry()
    reg.register(_ActiveMod())
    res = await Engine(reg, scope=None).run_module(reg.get("test.active"), "x.example")
    assert res.skipped and "scope" in res.skip_reason.lower()


@pytest.mark.asyncio
async def test_active_module_runs_when_in_scope():
    reg = Registry()
    reg.register(_ActiveMod())
    scope = Scope(engagement="t", authorized_by="me", targets=["x.example"])
    res = await Engine(reg, scope=scope).run_module(reg.get("test.active"), "x.example")
    assert res.ok and len(res.findings) == 1


@pytest.mark.asyncio
async def test_active_module_skipped_out_of_scope():
    reg = Registry()
    reg.register(_ActiveMod())
    scope = Scope(engagement="t", authorized_by="me", targets=["only.example"])
    res = await Engine(reg, scope=scope).run_module(reg.get("test.active"), "x.example")
    assert res.skipped


@pytest.mark.asyncio
async def test_passive_module_runs_without_scope():
    reg = Registry()
    reg.register(_PassiveMod())
    res = await Engine(reg, scope=None).run_module(reg.get("test.passive"), "x.example")
    assert res.ok and len(res.findings) == 1


# --- intrusive double barrier (scope + explicit confirmation) --------------
class _IntrusiveMod(Module):
    id = "test.intrusive"
    name = "intrusive"
    category = Category.VULN
    intensity = Intensity.INTRUSIVE

    async def run(self, ctx: RunContext):
        return [ctx.finding(self.id, "disrupted", Severity.MEDIUM)]


def _scope() -> Scope:
    return Scope(engagement="t", authorized_by="me", targets=["x.example"])


@pytest.mark.asyncio
async def test_intrusive_skipped_without_scope():
    # Barrier 1 (scope) fails first, regardless of confirmation.
    reg = Registry()
    reg.register(_IntrusiveMod())
    eng = Engine(reg, scope=None, options={"confirm_intrusive": True})
    res = await eng.run_module(reg.get("test.intrusive"), "x.example")
    assert res.skipped and "scope" in res.skip_reason.lower()


@pytest.mark.asyncio
async def test_intrusive_skipped_in_scope_without_confirmation():
    # Barrier 1 passes but barrier 2 (confirmation) blocks it.
    reg = Registry()
    reg.register(_IntrusiveMod())
    eng = Engine(reg, scope=_scope())
    res = await eng.run_module(reg.get("test.intrusive"), "x.example")
    assert res.skipped
    assert "INTRUSIVE" in res.skip_reason
    assert "--confirm-intrusive" in res.skip_reason


@pytest.mark.asyncio
async def test_intrusive_runs_with_scope_and_confirmation():
    # Both barriers satisfied → the module runs.
    reg = Registry()
    reg.register(_IntrusiveMod())
    eng = Engine(reg, scope=_scope(), options={"confirm_intrusive": True})
    res = await eng.run_module(reg.get("test.intrusive"), "x.example")
    assert res.ok and len(res.findings) == 1


@pytest.mark.asyncio
async def test_intrusive_confirmation_requires_exact_true():
    # A truthy-but-not-True value does not count as confirmation.
    reg = Registry()
    reg.register(_IntrusiveMod())
    eng = Engine(reg, scope=_scope(), options={"confirm_intrusive": "yes"})
    res = await eng.run_module(reg.get("test.intrusive"), "x.example")
    assert res.skipped and "--confirm-intrusive" in res.skip_reason


@pytest.mark.asyncio
async def test_active_module_runs_in_scope_without_confirmation():
    # Non-regression: ACTIVE needs scope only, never intrusive confirmation.
    reg = Registry()
    reg.register(_ActiveMod())
    eng = Engine(reg, scope=_scope())
    res = await eng.run_module(reg.get("test.active"), "x.example")
    assert res.ok and len(res.findings) == 1
