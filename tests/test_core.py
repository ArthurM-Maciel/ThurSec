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


# --- coerce_bool -----------------------------------------------------------
import pytest as _pytest

from thursec.core.context import coerce_bool


@_pytest.mark.parametrize(
    "value, expected",
    [
        (True, True),
        (False, False),
        ("true", True),
        ("True", True),
        ("1", True),
        ("yes", True),
        ("false", False),
        ("False", False),
        ("FALSE", False),
        ("0", False),
        ("no", False),
        ("off", False),
        ("nao", False),
        ("não", False),
        ("  false  ", False),
        ("", False),
        (1, True),
        (0, False),
    ],
)
def test_coerce_bool_le_texto_como_bandeira(value, expected):
    """``bool("false")`` é verdadeiro — numa bandeira que desliga proteção, isso inverte a intenção."""
    assert coerce_bool(value) is expected


def test_coerce_bool_ausente_usa_o_padrao():
    assert coerce_bool(None) is False
    assert coerce_bool(None, True) is True


@_pytest.mark.parametrize("typo", ["flase", "nao-quero", "talvez", "treu", "sure"])
def test_coerce_bool_erro_de_digitacao_cai_no_padrao(typo):
    """Desconhecido como verdadeiro faria um typo *ligar* allow_intrusive/insecure_tls."""
    assert coerce_bool(typo) is False
    assert coerce_bool(typo, True) is True


# --- dedup de um defeito do alvo visto por vários módulos ------------------
def test_report_colapsa_o_mesmo_defeito_visto_por_modulos_diferentes():
    """Um certificado que não cobre o domínio é um problema, não três."""
    from thursec.core.finding import Finding
    from thursec.core.report import Report

    def cert(module):
        return Finding(
            module=module,
            target="https://alvo",
            title="Certificado TLS não cobre este domínio",
            severity=Severity.HIGH,
            metadata={"dedup_key": "cert-verify:alvo:443:62"},
        )

    report = Report(engagement="x")
    report.add([cert("config_audit.tls_headers")])
    report.add([cert("config_audit.cookies"), cert("vuln.http_methods")])

    # A leitura mostra um problema só...
    collapsed = report.collapsed()
    assert len(collapsed) == 1
    assert report.counts()["HIGH"] == 1
    # ...e o sobrevivente é o menor id de módulo, não o que chegou primeiro: o
    # fingerprint e o módulo do colapsado vão para o JSON, e por ordem de
    # chegada uma execução por categoria e uma completa divergiriam.
    assert collapsed[0].module == "config_audit.cookies"
    assert collapsed[0].metadata["also_seen_by"] == [
        "config_audit.tls_headers",
        "vuln.http_methods",
    ]

    # ...mas o store recebe os três, cada um com seu fingerprint, senão o
    # `thursec diff` anunciaria dois como "desapareceram" na execução seguinte.
    assert len(report.findings) == 3
    assert len({f.fingerprint for f in report.findings}) == 3

    # O colapso é uma visão: não suja o que vai ser gravado.
    assert all("also_seen_by" not in f.metadata for f in report.findings)


def test_report_sem_dedup_key_segue_separando_por_modulo():
    """Sem a chave explícita, nada muda: dois módulos, dois achados."""
    from thursec.core.finding import Finding
    from thursec.core.report import Report

    def f(module):
        return Finding(
            module=module, target="https://alvo", title="Mesmo título", severity=Severity.LOW
        )

    report = Report(engagement="x")
    report.add([f("a.b"), f("c.d")])
    assert len(report.collapsed()) == 2


def test_duplicata_simples_nao_cria_also_seen_by_vazio():
    """Uma lista vazia no metadata engana quem testa `if "also_seen_by" in ...`."""
    from thursec.core.finding import Finding
    from thursec.core.report import Report

    f = Finding(
        module="a.b",
        target="https://alvo",
        title="Mesmo achado",
        severity=Severity.LOW,
        metadata={"dedup_key": "k"},
    )
    report = Report(engagement="x")
    report.add([f, f])

    assert "also_seen_by" not in report.collapsed()[0].metadata


def test_o_colapso_nao_depende_da_ordem_de_execucao():
    """Duas seleções de módulos não podem gravar fingerprints diferentes."""
    from thursec.core.finding import Finding
    from thursec.core.report import Report

    def cert(module):
        return Finding(
            module=module,
            target="https://alvo",
            title="Certificado TLS não cobre este domínio",
            severity=Severity.HIGH,
            metadata={"dedup_key": "cert-verify:alvo:443:62"},
        )

    modules = ["vuln.http_methods", "config_audit.tls_headers", "config_audit.cookies"]

    a = Report(engagement="x")
    a.add([cert(m) for m in modules])
    b = Report(engagement="x")
    b.add([cert(m) for m in reversed(modules)])

    assert a.collapsed()[0].fingerprint == b.collapsed()[0].fingerprint
    assert a.collapsed()[0].module == b.collapsed()[0].module


def test_severidades_diferentes_nao_se_colapsam_sob_a_mesma_chave():
    """O mais grave sumiria do relatório enquanto seguia no histórico."""
    from thursec.core.finding import Finding
    from thursec.core.report import Report

    def f(module, severity):
        return Finding(
            module=module,
            target="https://alvo",
            title="Mesmo defeito",
            severity=severity,
            metadata={"dedup_key": "k"},
        )

    report = Report(engagement="x")
    report.add([f("z.modulo", Severity.CRITICAL), f("a.modulo", Severity.LOW)])

    assert len(report.collapsed()) == 2
    assert report.counts()["CRITICAL"] == 1
    assert report.counts()["LOW"] == 1


def test_um_certificado_ruim_conta_uma_vez_so_entre_modulos():
    """Nem o desfecho de cada módulo separa: o defeito do alvo é um só.

    Houve duas idas e voltas aqui. Descrever o desfecho por módulo fazia o
    relatório afirmar uma continuação que não houve para quem sobreviveu ao
    colapso; separar o desfecho na chave consertava a frase e trazia de volta
    a contagem dupla. A saída foi a descrição falar da configuração da
    execução, que é igual para todos os módulos.
    """
    import ssl

    from thursec.core.context import RunContext
    from thursec.core.report import Report
    from thursec.core.tls import cert_verification_finding

    def erro():
        e = ssl.SSLCertVerificationError("certificate verify failed")
        e.verify_code = 62
        e.verify_message = "Hostname mismatch"
        return e

    ctx = RunContext(target="https://alvo")
    a = cert_verification_finding(ctx, "a.modulo", erro(), "alvo", 443, insecure=True)
    z = cert_verification_finding(ctx, "z.modulo", erro(), "alvo", 443, insecure=True)

    report = Report(engagement="x")
    report.add([a, z])

    colapsados = report.collapsed()
    assert len(colapsados) == 1
    assert report.counts()["HIGH"] == 1
    assert colapsados[0].metadata["also_seen_by"] == ["z.modulo"]
    # E a descrição não afirma o que este ou aquele módulo conseguiu fazer.
    assert "seguiu" not in colapsados[0].description


def test_bandeira_com_escopo_nao_faz_o_colapso_negar_o_que_houve():
    """`--opt config_audit.cookies.insecure_tls=true` vale para um módulo só.

    O colapso guardava o menor id de módulo, então o achado do que parou podia
    sobreviver negando a continuação que houve no outro — e levando junto a
    ausência da marca de canal não verificado.
    """
    import ssl

    from thursec.core.context import RunContext
    from thursec.core.report import Report
    from thursec.core.tls import cert_verification_finding

    def erro():
        e = ssl.SSLCertVerificationError("certificate verify failed")
        e.verify_code = 62
        e.verify_message = "Hostname mismatch"
        return e

    ctx = RunContext(target="https://alvo")
    parou = cert_verification_finding(ctx, "a.modulo", erro(), "alvo", 443, insecure=False)
    seguiu = cert_verification_finding(ctx, "z.modulo", erro(), "alvo", 443, insecure=True)

    report = Report(engagement="x")
    report.add([parou, seguiu])

    colapsados = report.collapsed()
    assert len(colapsados) == 2
    descricoes = sorted(f.description for f in colapsados)
    assert any("insecure_tls=true" in d for d in descricoes)       # o que parou
    assert any("tls_verified: false" in d for d in descricoes)     # o que seguiu


def test_bandeira_uniforme_continua_colapsando():
    """O caso normal: a mesma bandeira para todos, um defeito, uma contagem."""
    import ssl

    from thursec.core.context import RunContext
    from thursec.core.report import Report
    from thursec.core.tls import cert_verification_finding

    def erro():
        e = ssl.SSLCertVerificationError("certificate verify failed")
        e.verify_code = 62
        e.verify_message = "Hostname mismatch"
        return e

    ctx = RunContext(target="https://alvo")
    report = Report(engagement="x")
    report.add([
        cert_verification_finding(ctx, m, erro(), "alvo", 443, insecure=True)
        for m in ("a.modulo", "m.modulo", "z.modulo")
    ])

    assert len(report.collapsed()) == 1
    assert report.counts()["HIGH"] == 1
