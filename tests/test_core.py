import pytest

from thursec.core import i18n
from thursec.core.context import RunContext, coerce_timeout, scoped_options
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


# --- opções com escopo por módulo ------------------------------------------
def test_scoped_options_module_prefix_wins_over_bare():
    opts = {"timeout": 60, "vuln.cve_lookup.timeout": 120, "product": "nginx"}

    assert scoped_options(opts, "vuln.cve_lookup") == {
        "timeout": 120,
        "product": "nginx",
    }
    # Outro módulo continua com o valor nu, sem enxergar a chave alheia.
    assert scoped_options(opts, "vuln.nuclei") == {"timeout": 60, "product": "nginx"}


def test_scoped_options_does_not_leak_another_modules_key():
    """Uma chave de outro módulo é descartada, não rebaixada para nua."""
    opts = {"recon.nmap.timeout": 30}

    assert scoped_options(opts, "vuln.nuclei") == {}
    assert scoped_options(opts, "recon.nmap") == {"timeout": 30}


def test_scoped_options_passes_through_an_empty_or_flat_dict():
    assert scoped_options({}, "recon.nmap") == {}
    assert scoped_options({"max_rps": 10}, "resilience.load_test") == {"max_rps": 10}


@pytest.mark.asyncio
async def test_engine_gives_each_module_its_own_option_view():
    """O caso que motivou a mudança: -c vuln --opt timeout não corta o nuclei."""
    seen: dict[str, object] = {}

    class _Fast(Module):
        id = "vuln.fast"
        category = Category.VULN
        intensity = Intensity.PASSIVE

        async def run(self, ctx):
            seen[self.id] = ctx.options.get("timeout")
            return []

    class _Slow(_Fast):
        id = "vuln.slow"

    reg = Registry()
    reg.register(_Fast())
    reg.register(_Slow())
    engine = Engine(reg, options={"timeout": 600, "vuln.fast.timeout": 60})
    for mid in ("vuln.fast", "vuln.slow"):
        await engine.run_module(reg.get(mid), "example.com")

    assert seen == {"vuln.fast": 60, "vuln.slow": 600}


# --- coerce_timeout compartilhado ------------------------------------------
def test_coerce_timeout_falls_back_on_nonsense():
    assert coerce_timeout(5, 30.0) == 5.0
    assert coerce_timeout("7.5", 30.0) == 7.5
    for bad in ("rapido", None, 0, -1, "", [], {}):
        assert coerce_timeout(bad, 30.0) == 30.0


def test_coerce_timeout_rejects_booleans():
    """--opt timeout=true vira True no CLI; float(True) daria 1s de timeout."""
    assert coerce_timeout(True, 30.0) == 30.0
    assert coerce_timeout(False, 30.0) == 30.0
