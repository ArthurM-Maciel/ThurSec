"""config_audit.electron_fuses — tests against REA's real output contract.

The canned documents below follow `electronFuseReportSchema` in REA
(`src/domain/electron/electronFuses.ts`): the report sits under
`normalized_result`, fuse bytes live in `slices[].sentinels[].fuses[]` as
`{index, name, state, raw_byte}`, and `state` is one of enabled/disabled/
removed/unknown. The REA binary is never invoked — `ctx.runner` is replaced.
"""

import json

import pytest

from thursec.core.context import RunContext
from thursec.core.finding import Severity
from thursec.core.runner import CommandResult, ToolNotFoundError
from thursec.modules.config_audit.electron_fuses import ElectronFuses

# Index order is FuseV1: RunAsNode, EnableCookieEncryption,
# EnableNodeOptionsEnvironmentVariable, EnableNodeCliInspectArguments,
# EnableEmbeddedAsarIntegrityValidation, OnlyLoadAppFromAsar,
# LoadBrowserProcessSpecificV8Snapshot, GrantFileProtocolExtraPrivileges,
# WasmTrapHandlers.
_HARDENED = [
    ("RunAsNode", "disabled"),
    ("EnableCookieEncryption", "enabled"),
    ("EnableNodeOptionsEnvironmentVariable", "disabled"),
    ("EnableNodeCliInspectArguments", "disabled"),
    ("EnableEmbeddedAsarIntegrityValidation", "enabled"),
    ("OnlyLoadAppFromAsar", "enabled"),
    ("LoadBrowserProcessSpecificV8Snapshot", "disabled"),
    ("GrantFileProtocolExtraPrivileges", "disabled"),
    ("WasmTrapHandlers", "enabled"),
]


def _fuses(overrides=None):
    states = dict(_HARDENED)
    states.update(overrides or {})
    return [
        {
            "index": i,
            "name": name,
            "state": states[name],
            "raw_byte": {"enabled": 0x31, "disabled": 0x30}.get(states[name], 0x72),
        }
        for i, (name, _) in enumerate(_HARDENED)
    ]


def _report(overrides=None, *, complete=True, slices=None):
    return {
        "normalized_result": {
            "artifact": {
                "selected_path": "/Applications/Exemplo.app",
                "resolved_path": "/Applications/Exemplo.app/.../Electron Framework",
                "sha256": "a" * 64,
                "bytes": 1234,
                "format": "mach-o",
            },
            "slices": slices
            or [
                {
                    "index": 0,
                    "file_offset": 0,
                    "size": 1234,
                    "architecture": "arm64",
                    "sentinel_count": 1,
                    "sentinels": [
                        {
                            "sentinel_offset": 42,
                            "wire_version": 1,
                            "declared_length": 9,
                            "fuses": _fuses(overrides),
                            "complete": complete,
                        }
                    ],
                }
            ],
            "runtime_implications": [],
            "limitations": [],
        }
    }


class _Runner:
    """Stands in for ctx.runner: records args, returns a canned result."""

    def __init__(self, *, stdout="", returncode=0, timed_out=False, raises=None):
        self.stdout, self.returncode = stdout, returncode
        self.timed_out, self.raises = timed_out, raises
        self.calls = []

    async def run(self, args, *, timeout=None, input_text=None):
        self.calls.append((args, timeout))
        if self.raises:
            raise self.raises
        return CommandResult(
            args=args,
            returncode=self.returncode,
            stdout=self.stdout,
            stderr="" if self.returncode == 0 else "boom",
            timed_out=self.timed_out,
        )


def _ctx(tmp_path, runner, **options):
    app = tmp_path / "Exemplo.app"
    app.mkdir(exist_ok=True)
    ctx = RunContext(target=str(app), options=options)
    ctx.runner = runner
    return ctx


# --- caminho feliz ---------------------------------------------------------
@pytest.mark.asyncio
async def test_hardened_app_reports_no_weakness(tmp_path):
    runner = _Runner(stdout=json.dumps(_report()))
    findings = await ElectronFuses().run(_ctx(tmp_path, runner))

    assert [f.severity for f in findings] == [Severity.INFO]
    assert "0 fraca" in findings[0].title or "0 weak" in findings[0].title


@pytest.mark.asyncio
async def test_permissive_fuses_become_graded_findings(tmp_path):
    runner = _Runner(
        stdout=json.dumps(
            _report(
                {
                    "RunAsNode": "enabled",
                    "EnableNodeCliInspectArguments": "enabled",
                    "EnableCookieEncryption": "disabled",
                }
            )
        )
    )
    findings = await ElectronFuses().run(_ctx(tmp_path, runner))
    by_fuse = {f.metadata.get("fuse"): f for f in findings if f.metadata.get("fuse")}

    assert by_fuse["RunAsNode"].severity == Severity.HIGH
    assert by_fuse["EnableNodeCliInspectArguments"].severity == Severity.HIGH
    assert by_fuse["EnableCookieEncryption"].severity == Severity.MEDIUM
    assert "ELECTRON_RUN_AS_NODE" in by_fuse["RunAsNode"].description


@pytest.mark.asyncio
async def test_the_inverted_fuses_are_graded_on_disabled(tmp_path):
    """ASAR integrity e OnlyLoadAppFromAsar são fracas quando DESligadas."""
    runner = _Runner(
        stdout=json.dumps(
            _report(
                {
                    "EnableEmbeddedAsarIntegrityValidation": "disabled",
                    "OnlyLoadAppFromAsar": "disabled",
                }
            )
        )
    )
    findings = await ElectronFuses().run(_ctx(tmp_path, runner))
    weak = {f.metadata["fuse"] for f in findings if f.metadata.get("fuse")}

    assert weak == {"EnableEmbeddedAsarIntegrityValidation", "OnlyLoadAppFromAsar"}


@pytest.mark.asyncio
async def test_purely_informational_fuses_never_become_weaknesses(tmp_path):
    runner = _Runner(
        stdout=json.dumps(
            _report(
                {
                    "LoadBrowserProcessSpecificV8Snapshot": "enabled",
                    "WasmTrapHandlers": "disabled",
                }
            )
        )
    )
    findings = await ElectronFuses().run(_ctx(tmp_path, runner))
    assert [f.severity for f in findings] == [Severity.INFO]


# --- o limite que não pode ser atravessado ---------------------------------
@pytest.mark.asyncio
async def test_incomplete_sentinel_is_unknown_not_insecure(tmp_path):
    """Sentinela truncado = estado desconhecido. Nunca reportar como fraco."""
    runner = _Runner(
        stdout=json.dumps(_report({"RunAsNode": "enabled"}, complete=False))
    )
    findings = await ElectronFuses().run(_ctx(tmp_path, runner))

    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert not any(f.metadata.get("fuse") for f in findings)
    assert "NÃO" in findings[0].description or "does NOT" in findings[0].description


@pytest.mark.asyncio
async def test_no_sentinel_at_all_is_unknown(tmp_path):
    empty = [
        {
            "index": 0,
            "file_offset": 0,
            "size": 10,
            "architecture": "arm64",
            "sentinel_count": 0,
            "sentinels": [],
        }
    ]
    runner = _Runner(stdout=json.dumps(_report(slices=empty)))
    findings = await ElectronFuses().run(_ctx(tmp_path, runner))

    assert len(findings) == 1 and findings[0].severity == Severity.INFO


@pytest.mark.asyncio
async def test_universal_binary_flags_a_fuse_weak_in_any_slice(tmp_path):
    """Fatias discordando: a entrega contém a fatia fraca, então reporta."""
    hardened_slice = {
        "index": 0,
        "file_offset": 0,
        "size": 10,
        "architecture": "arm64",
        "sentinel_count": 1,
        "sentinels": [
            {
                "sentinel_offset": 1,
                "wire_version": 1,
                "declared_length": 9,
                "fuses": _fuses(),
                "complete": True,
            }
        ],
    }
    weak_slice = {
        **hardened_slice,
        "index": 1,
        "architecture": "x86_64",
        "sentinels": [
            {
                "sentinel_offset": 2,
                "wire_version": 1,
                "declared_length": 9,
                "fuses": _fuses({"RunAsNode": "enabled"}),
                "complete": True,
            }
        ],
    }
    runner = _Runner(stdout=json.dumps(_report(slices=[hardened_slice, weak_slice])))
    findings = await ElectronFuses().run(_ctx(tmp_path, runner))
    weak = [f for f in findings if f.metadata.get("fuse") == "RunAsNode"]

    assert len(weak) == 1
    assert sorted(weak[0].metadata["states"]) == ["disabled", "enabled"]


# --- caminhos de erro: sempre achado, nunca exceção ------------------------
@pytest.mark.asyncio
async def test_missing_rea_binary_degrades_gracefully(tmp_path):
    runner = _Runner(raises=ToolNotFoundError("rea"))
    findings = await ElectronFuses().run(_ctx(tmp_path, runner))

    assert len(findings) == 1 and findings[0].severity == Severity.INFO
    assert "rea-agents" in findings[0].recommendation


@pytest.mark.asyncio
async def test_timeout_and_tool_failure_and_bad_json_are_handled(tmp_path):
    for runner in (
        _Runner(timed_out=True),
        _Runner(returncode=2),
        _Runner(stdout="not json{"),
        _Runner(stdout=json.dumps({"something_else": 1})),
    ):
        findings = await ElectronFuses().run(_ctx(tmp_path, runner))
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW


@pytest.mark.asyncio
async def test_a_hostname_target_produces_no_finding(tmp_path):
    """PASSIVE roda em todo 'thursec run <host>': não poluir o relatório de rede."""
    runner = _Runner(stdout=json.dumps(_report()))

    ctx = RunContext(target="example.com")
    ctx.runner = runner
    assert await ElectronFuses().run(ctx) == []

    ctx = RunContext(target="")
    ctx.runner = runner
    assert [f.severity for f in await ElectronFuses().run(ctx)] == [Severity.INFO]

    assert runner.calls == []  # nunca chamou o REA


@pytest.mark.asyncio
async def test_an_explicit_path_that_is_missing_is_reported(tmp_path):
    """Quem passou --opt path= quis este caminho: o engano merece ser dito."""
    runner = _Runner(stdout=json.dumps(_report()))
    ctx = RunContext(
        target="example.com", options={"path": str(tmp_path / "nao-existe.app")}
    )
    ctx.runner = runner
    findings = await ElectronFuses().run(ctx)

    assert [f.severity for f in findings] == [Severity.INFO]
    assert "existe" in findings[0].title or "exist" in findings[0].title
    assert runner.calls == []


@pytest.mark.asyncio
async def test_path_option_wins_and_timeout_is_scoped(tmp_path):
    app = tmp_path / "Outro.app"
    app.mkdir()
    runner = _Runner(stdout=json.dumps(_report()))
    ctx = RunContext(
        target="ignorado", options={"path": str(app), "timeout": 5}
    )
    ctx.runner = runner
    await ElectronFuses().run(ctx)

    args, timeout = runner.calls[0]
    assert args[:2] == ["rea", "inspect-electron-fuses"]
    assert args[-1] == "--json"
    assert str(app.resolve()) in args
    assert timeout == 5.0


@pytest.mark.asyncio
async def test_a_slice_without_a_sentinel_makes_the_state_unknown(tmp_path):
    """Fatia que não pôde ser lida: não afirmar nada a partir das outras."""
    readable = {
        "index": 0,
        "file_offset": 0,
        "size": 10,
        "architecture": "arm64",
        "sentinel_count": 1,
        "sentinels": [
            {
                "sentinel_offset": 1,
                "wire_version": 1,
                "declared_length": 9,
                "fuses": _fuses({"RunAsNode": "enabled"}),
                "complete": True,
            }
        ],
    }
    unreadable = {**readable, "index": 1, "architecture": "x86_64",
                  "sentinel_count": 0, "sentinels": []}
    runner = _Runner(stdout=json.dumps(_report(slices=[readable, unreadable])))
    findings = await ElectronFuses().run(_ctx(tmp_path, runner))

    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert not any(f.metadata.get("fuse") for f in findings)


@pytest.mark.asyncio
async def test_a_malformed_contract_is_a_finding_not_a_crash(tmp_path):
    """JSON válido com forma errada vira achado, nunca exceção que sobe."""
    malformed = [
        {"normalized_result": {"artifact": "/caminho"}},
        {"normalized_result": {"artifact": {}, "slices": [None]}},
        {"normalized_result": {"artifact": {}, "slices": {"a": 1}}},
        {"normalized_result": {"artifact": {}, "slices": [{"sentinels": [None]}]}},
        {"normalized_result": {"artifact": {}, "slices": [{"sentinels": [{"fuses": [1]}]}]}},
        [1, 2, 3],
    ]
    for doc in malformed:
        runner = _Runner(stdout=json.dumps(doc))
        findings = await ElectronFuses().run(_ctx(tmp_path, runner))
        assert len(findings) == 1, doc
        assert findings[0].severity == Severity.LOW, doc


@pytest.mark.asyncio
async def test_a_plain_directory_is_not_handed_to_rea(tmp_path):
    """`thursec run .` num repositório não pode virar 'não consegui ler as fuses'."""
    runner = _Runner(stdout=json.dumps(_report()))
    repo = tmp_path / "meu-repo"
    repo.mkdir()

    ctx = RunContext(target=str(repo))
    ctx.runner = runner
    assert await ElectronFuses().run(ctx) == []
    assert runner.calls == []


@pytest.mark.asyncio
async def test_an_app_bundle_or_a_binary_is_still_audited(tmp_path):
    """O caso de uso real continua funcionando sem --opt path=."""
    bundle = tmp_path / "Exemplo.app"
    bundle.mkdir()
    binario = tmp_path / "electron-bin"
    binario.write_bytes(b"\x00")

    for alvo in (bundle, binario):
        runner = _Runner(stdout=json.dumps(_report()))
        ctx = RunContext(target=str(alvo))
        ctx.runner = runner
        findings = await ElectronFuses().run(ctx)
        assert findings, f"não auditou {alvo.name}"
        assert runner.calls, f"não chamou o REA para {alvo.name}"
