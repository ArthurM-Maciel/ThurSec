import pytest

from thursec.core.context import RunContext
from thursec.core.engine import Engine, Registry
from thursec.core.finding import Finding, Severity
from thursec.core.module import Category, Intensity, Module
from thursec.core.report import Report
from thursec.core.scope import Scope


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
