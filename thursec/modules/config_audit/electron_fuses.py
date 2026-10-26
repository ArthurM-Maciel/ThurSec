"""Electron fuse hardening audit, via REA's ``inspect-electron-fuses``.

Electron ships a row of build-time toggles — *fuses* — packed into a sentinel
inside the application binary. They decide whether a packaged app will honor
``ELECTRON_RUN_AS_NODE``, respect ``NODE_OPTIONS``, accept ``--inspect``,
validate embedded ASAR integrity, and refuse to load application code from
outside ``app.asar``. A desktop app shipped with the permissive defaults can be
turned into an arbitrary-code-execution primitive by anyone who can set an
environment variable on the machine.

Reading them means parsing the binary, so this module delegates to REA
(https://github.com/morluto/rea), which reads the fuse wire without launching
the app, modifying bytes, or touching the network. That is why this module is
PASSIVE: it sends nothing anywhere and needs no scope gate. The subject is a
local path, not a network target.

What we add on top of REA is the security judgement REA deliberately does not
make: REA reports fuse *state*, we say which states are a weakness and why.
Two limits are honored rather than papered over:

* an incomplete or missing sentinel means the state is **unknown**, not that
  every fuse is disabled — we report INFO, never a weakness; and
* a fuse is a build-time default, not proof of runtime behaviour. An app can
  still enable the Inspector from its own code, so we report exposure, never
  confirmed exploitation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ...core.context import RunContext, coerce_timeout
from ...core.finding import Finding, Severity
from ...core.i18n import L, Lf
from ...core.module import Category, Intensity, Module
from ...core.runner import ToolNotFoundError

_TOOL = "rea"
_DEFAULT_TIMEOUT = 120.0
_PROJECT_URL = "https://github.com/morluto/rea"
_ELECTRON_FUSES_DOC = "https://www.electronjs.org/docs/latest/tutorial/fuses"

# fuse name -> (state that is a weakness, severity, why PT, why EN, fix PT, fix EN)
_RISKY_STATE: dict[str, tuple[str, Severity, str, str, str, str]] = {
    "RunAsNode": (
        "enabled",
        Severity.HIGH,
        "Com RunAsNode ligado, qualquer um que possa definir ELECTRON_RUN_AS_NODE "
        "executa o binário como um Node comum, rodando código arbitrário com a "
        "identidade e as permissões do aplicativo.",
        "With RunAsNode on, anyone who can set ELECTRON_RUN_AS_NODE runs the "
        "binary as plain Node, executing arbitrary code with the application's "
        "identity and permissions.",
        "Desligue a fuse RunAsNode no empacotamento.",
        "Turn the RunAsNode fuse off at packaging time.",
    ),
    "EnableNodeOptionsEnvironmentVariable": (
        "enabled",
        Severity.HIGH,
        "Com NODE_OPTIONS respeitado, uma variável de ambiente injeta código no "
        "processo do aplicativo (por exemplo via --require).",
        "With NODE_OPTIONS respected, an environment variable injects code into "
        "the application process (for example via --require).",
        "Desligue a fuse EnableNodeOptionsEnvironmentVariable.",
        "Turn the EnableNodeOptionsEnvironmentVariable fuse off.",
    ),
    "EnableNodeCliInspectArguments": (
        "enabled",
        Severity.HIGH,
        "Com os argumentos de inspeção aceitos, --inspect anexa um depurador ao "
        "processo e dá execução de código e leitura de memória a quem conseguir "
        "iniciar o aplicativo.",
        "With inspect arguments accepted, --inspect attaches a debugger to the "
        "process, granting code execution and memory access to anyone who can "
        "start the application.",
        "Desligue a fuse EnableNodeCliInspectArguments em builds de produção.",
        "Turn the EnableNodeCliInspectArguments fuse off in production builds.",
    ),
    "EnableEmbeddedAsarIntegrityValidation": (
        "disabled",
        Severity.HIGH,
        "Sem validação de integridade do ASAR, o app.asar pode ser trocado ou "
        "editado no disco e o aplicativo carrega o código adulterado sem notar.",
        "Without ASAR integrity validation, app.asar can be swapped or edited on "
        "disk and the application loads the tampered code without noticing.",
        "Ligue a fuse EnableEmbeddedAsarIntegrityValidation.",
        "Turn the EnableEmbeddedAsarIntegrityValidation fuse on.",
    ),
    "OnlyLoadAppFromAsar": (
        "disabled",
        Severity.HIGH,
        "Sem essa restrição, o Electron também procura código fora do app.asar, "
        "então um arquivo plantado ao lado do pacote passa a ser carregado.",
        "Without this restriction, Electron also looks for code outside "
        "app.asar, so a file planted next to the bundle gets loaded.",
        "Ligue a fuse OnlyLoadAppFromAsar.",
        "Turn the OnlyLoadAppFromAsar fuse on.",
    ),
    "GrantFileProtocolExtraPrivileges": (
        "enabled",
        Severity.MEDIUM,
        "Páginas file:// recebem privilégios extras, ampliando o que um HTML "
        "local malicioso consegue alcançar.",
        "file:// pages get extra privileges, widening what a malicious local "
        "HTML file can reach.",
        "Desligue a fuse GrantFileProtocolExtraPrivileges se o aplicativo não "
        "depende dela.",
        "Turn the GrantFileProtocolExtraPrivileges fuse off unless the "
        "application depends on it.",
    ),
    "EnableCookieEncryption": (
        "disabled",
        Severity.MEDIUM,
        "Os cookies do aplicativo ficam em claro no disco, então qualquer "
        "processo do mesmo usuário lê sessões autenticadas.",
        "The application's cookies sit unencrypted on disk, so any process "
        "running as the same user can read authenticated sessions.",
        "Ligue a fuse EnableCookieEncryption.",
        "Turn the EnableCookieEncryption fuse on.",
    ),
}

# Fuses lidas e relatadas, mas que não são um endurecimento de segurança por si.
_INFORMATIONAL = {"LoadBrowserProcessSpecificV8Snapshot", "WasmTrapHandlers"}


class ElectronFuses(Module):
    id = "config_audit.electron_fuses"
    category = Category.CONFIG_AUDIT
    intensity = Intensity.PASSIVE
    requires_tools = (_TOOL,)

    @property
    def name(self) -> str:
        return L("Fuses de segurança do Electron", "Electron security fuses")

    @property
    def description(self) -> str:
        return L(
            "Audita as fuses de build de um aplicativo Electron empacotado "
            "(RunAsNode, NODE_OPTIONS, --inspect, integridade do ASAR). Lê o "
            "binário local via REA; não executa o aplicativo nem usa a rede. "
            "Informe o caminho via options['path'] ou como alvo.",
            "Audit a packaged Electron application's build-time fuses "
            "(RunAsNode, NODE_OPTIONS, --inspect, ASAR integrity). Reads the "
            "local binary via REA; never launches the app or uses the network. "
            "Give it a path via options['path'] or as the target.",
        )

    async def run(self, ctx: RunContext) -> list[Finding]:
        explicit = str(ctx.options.get("path") or "").strip()
        raw_path = explicit or str(ctx.target or "").strip()
        if not raw_path:
            return [self._usage_finding(ctx)]

        path = Path(raw_path).expanduser()
        if not explicit and not _plausibly_electron(path):
            # This module is PASSIVE, so it runs in every bare `thursec run X`.
            # Without an explicit --opt path= it stays silent unless the target
            # really looks like a packaged app: a hostname is not a path, and a
            # repository directory is not an Electron bundle. Running REA on one
            # anyway produced a LOW "could not read the fuses" on every audit.
            return []
        if not path.exists():
            return [self._missing_path_finding(ctx, path)]

        timeout = coerce_timeout(ctx.options.get("timeout"), _DEFAULT_TIMEOUT)
        args = [_TOOL, "inspect-electron-fuses", str(path.resolve()), "--json"]

        try:
            result = await ctx.runner.run(args, timeout=timeout)
        except ToolNotFoundError as e:
            return [self._tool_missing_finding(ctx, e)]

        if result.timed_out:
            return [self._timeout_finding(ctx, path, timeout)]
        if not result.ok:
            return [self._tool_failed_finding(ctx, path, result)]

        try:
            report = _extract_report(json.loads(result.stdout))
        except (ValueError, KeyError, TypeError) as e:
            return [self._unparsable_finding(ctx, path, e)]

        return _findings_from_report(ctx, self.id, path, report)

    # --- handled error paths, each a finding rather than an exception -----
    def _usage_finding(self, ctx: RunContext) -> Finding:
        return ctx.finding(
            self.id,
            L("Nenhum aplicativo Electron informado", "No Electron application given"),
            Severity.INFO,
            description=L(
                "Este módulo audita um aplicativo Electron empacotado no disco, "
                "não um alvo de rede.",
                "This module audits a packaged Electron application on disk, not "
                "a network target.",
            ),
            recommendation=L(
                "Informe um caminho, por exemplo "
                "--opt path=/Applications/Exemplo.app (no macOS, o bundle .app; "
                "no Windows/Linux, o executável principal do Electron).",
                "Provide a path, for example "
                "--opt path=/Applications/Example.app (on macOS the .app bundle; "
                "on Windows/Linux the main Electron executable).",
            ),
            references=[_ELECTRON_FUSES_DOC],
        )

    def _missing_path_finding(self, ctx: RunContext, path: Path) -> Finding:
        return ctx.finding(
            self.id,
            Lf("Caminho não existe: {p}", "Path does not exist: {p}", p=path),
            Severity.INFO,
            description=L(
                "O caminho informado não foi encontrado, então nenhuma fuse "
                "pôde ser lida.",
                "The given path was not found, so no fuse could be read.",
            ),
            metadata={"path": str(path)},
        )

    def _tool_missing_finding(self, ctx: RunContext, e: Exception) -> Finding:
        return ctx.finding(
            self.id,
            L("REA não instalado", "REA not installed"),
            Severity.INFO,
            description=L(
                "O binário 'rea' não foi encontrado no PATH, então a auditoria "
                "de fuses do Electron foi ignorada.",
                "The 'rea' binary was not found on PATH, so the Electron fuse "
                "audit was skipped.",
            ),
            evidence=str(e),
            recommendation=L(
                "Instale o REA ('npm install --global rea-agents'; exige Node "
                "^22.23.4, ^24.22.1 ou >=26.12.1) e execute este módulo de novo.",
                "Install REA ('npm install --global rea-agents'; requires Node "
                "^22.23.4, ^24.22.1 or >=26.12.1) and re-run this module.",
            ),
            references=[_PROJECT_URL],
        )

    def _timeout_finding(self, ctx: RunContext, path: Path, timeout: float) -> Finding:
        return ctx.finding(
            self.id,
            Lf(
                "Leitura das fuses expirou após {t:g}s",
                "Fuse read timed out after {t:g}s",
                t=timeout,
            ),
            Severity.LOW,
            description=Lf(
                "O REA não terminou de ler {p} em {t:g} segundos.",
                "REA did not finish reading {p} within {t:g} seconds.",
                p=path,
                t=timeout,
            ),
            recommendation=L(
                "Aumente o tempo com "
                "--opt config_audit.electron_fuses.timeout=<segundos>.",
                "Raise it with --opt config_audit.electron_fuses.timeout=<seconds>.",
            ),
            metadata={"path": str(path), "timeout": timeout},
        )

    def _tool_failed_finding(self, ctx: RunContext, path: Path, result: Any) -> Finding:
        return ctx.finding(
            self.id,
            L("O REA não conseguiu ler as fuses", "REA could not read the fuses"),
            Severity.LOW,
            description=Lf(
                "O REA saiu com código {rc} ao inspecionar {p}.",
                "REA exited with code {rc} while inspecting {p}.",
                rc=result.returncode,
                p=path,
            ),
            evidence=(result.stderr or result.stdout or "").strip()[:2000],
            recommendation=L(
                "Confirme que o caminho é um aplicativo Electron empacotado: no "
                "macOS o bundle .app ou o Electron Framework; no Windows e no "
                "Linux o executável principal.",
                "Check the path is a packaged Electron application: on macOS the "
                ".app bundle or the Electron Framework; on Windows and Linux the "
                "main executable.",
            ),
            metadata={"path": str(path), "returncode": result.returncode},
        )

    def _unparsable_finding(self, ctx: RunContext, path: Path, e: Exception) -> Finding:
        return ctx.finding(
            self.id,
            L(
                "Resposta do REA não reconhecida",
                "Unrecognised REA response",
            ),
            Severity.LOW,
            description=L(
                "O REA respondeu, mas o JSON não tinha o formato esperado — "
                "provavelmente uma versão do REA com outro contrato de saída.",
                "REA responded, but the JSON did not have the expected shape — "
                "most likely a REA version with a different output contract.",
            ),
            evidence=f"{type(e).__name__}: {e}",
            recommendation=L(
                "Atualize o REA ('rea update') ou abra uma issue do ThurSec com "
                "a saída de 'rea --version'.",
                "Update REA ('rea update'), or open a ThurSec issue with the "
                "output of 'rea --version'.",
            ),
            metadata={"path": str(path)},
            references=[_PROJECT_URL],
        )


def _plausibly_electron(path: Path) -> bool:
    """True when *path* could be a packaged Electron app, without opening it.

    macOS ships the app as an ``.app`` bundle; Windows and Linux ship a single
    executable file. An ordinary directory is neither, and that is the case we
    must not hand to REA during a repository audit.

    This also skips an *unpacked* install directory (``/opt/slack``,
    ``C:\\Program Files\\Slack``), which is a real Electron app. That is the
    price of staying quiet during a repository audit, and the way out is to
    name the executable — or the directory — explicitly with
    ``--opt config_audit.electron_fuses.path=...``, which bypasses this check.
    """
    if not path.exists():
        return False
    return path.suffix.lower() == ".app" or path.is_file()


# --- report handling -------------------------------------------------------
def _extract_report(doc: Any) -> dict[str, Any]:
    """Pull REA's fuse report out of its Evidence envelope.

    The CLI wraps the report in ``normalized_result``; a future or reduced
    envelope that hands us the report directly is accepted too. Anything else
    is a contract mismatch and raises, which the caller turns into a finding.
    """
    if not isinstance(doc, dict):
        raise TypeError(f"expected a JSON object, got {type(doc).__name__}")

    report = doc.get("normalized_result", doc)
    if not isinstance(report, dict) or "artifact" not in report:
        raise KeyError("no fuse report found (missing 'artifact')")
    if not isinstance(report["artifact"], dict):
        raise TypeError("'artifact' is not an object")

    # Validate the nesting we are about to walk. A REA version with a different
    # contract must become the "unrecognised response" finding, not an
    # AttributeError escaping run() and marking the module as crashed.
    slices = report.get("slices") or []
    if not isinstance(slices, list):
        raise TypeError("'slices' is not an array")
    for slice_ in slices:
        if not isinstance(slice_, dict):
            raise TypeError("a slice entry is not an object")
        sentinels = slice_.get("sentinels") or []
        if not isinstance(sentinels, list):
            raise TypeError("'sentinels' is not an array")
        for sentinel in sentinels:
            if not isinstance(sentinel, dict):
                raise TypeError("a sentinel entry is not an object")
            fuses = sentinel.get("fuses") or []
            if not isinstance(fuses, list):
                raise TypeError("'fuses' is not an array")
            if any(not isinstance(fuse, dict) for fuse in fuses):
                raise TypeError("a fuse entry is not an object")
    return report


def _collect_states(report: dict[str, Any]) -> tuple[dict[str, set[str]], bool]:
    """Map each named fuse to the states seen across every slice and sentinel.

    A universal Mach-O carries one sentinel per slice and they can disagree, so
    a fuse keeps the *set* of states observed: if any slice is weak, the
    application ships a weak slice. Returns ``(states, complete)`` where
    ``complete`` is False when a sentinel is missing or truncated — in which
    case the state is unknown and must not be read as "disabled".
    """
    states: dict[str, set[str]] = {}
    sentinels = 0
    complete = True

    for slice_ in report.get("slices") or []:
        slice_sentinels = slice_.get("sentinels") or []
        if not slice_sentinels:
            # A shipped slice we could not read at all. Saying anything about
            # "the application" from the other slices would overstate it.
            complete = False
        for sentinel in slice_sentinels:
            sentinels += 1
            if not sentinel.get("complete", False):
                complete = False
            for fuse in sentinel.get("fuses") or []:
                name = fuse.get("name")
                state = fuse.get("state")
                if name and state:
                    states.setdefault(name, set()).add(state)

    return states, complete and sentinels > 0


def _findings_from_report(
    ctx: RunContext, module_id: str, path: Path, report: dict[str, Any]
) -> list[Finding]:
    artifact = report.get("artifact") or {}
    states, complete = _collect_states(report)
    identity = {
        "path": str(path),
        "resolved_path": artifact.get("resolved_path"),
        "sha256": artifact.get("sha256"),
        "format": artifact.get("format"),
    }

    if not complete:
        return [_unknown_state_finding(ctx, module_id, path, artifact, identity)]

    findings = [
        _fuse_finding(ctx, module_id, name, states[name], identity)
        for name in _RISKY_STATE
        if name in states and _RISKY_STATE[name][0] in states[name]
    ]

    findings.append(
        _summary_finding(ctx, module_id, path, artifact, states, identity, findings)
    )
    return findings


def _fuse_finding(
    ctx: RunContext,
    module_id: str,
    name: str,
    observed: set[str],
    identity: dict[str, Any],
) -> Finding:
    risky, severity, why_pt, why_en, fix_pt, fix_en = _RISKY_STATE[name]
    mixed = len(observed) > 1

    title = Lf(
        "Fuse do Electron em estado fraco: {name} está {state}",
        "Weak Electron fuse: {name} is {state}",
        name=name,
        state=risky,
    )
    description = L(why_pt, why_en)
    if mixed:
        description = Lf(
            "{why} Fatias do binário discordam ({seen}), então ao menos uma "
            "fatia entregue é a fraca.",
            "{why} Slices of the binary disagree ({seen}), so at least one "
            "shipped slice is the weak one.",
            why=description,
            seen=", ".join(sorted(observed)),
        )

    return ctx.finding(
        module_id,
        title,
        severity,
        description=description,
        evidence=f"{name}: {', '.join(sorted(observed))}",
        recommendation=L(fix_pt, fix_en),
        references=[_ELECTRON_FUSES_DOC, _PROJECT_URL],
        metadata={**identity, "fuse": name, "states": sorted(observed)},
    )


def _unknown_state_finding(
    ctx: RunContext,
    module_id: str,
    path: Path,
    artifact: dict[str, Any],
    identity: dict[str, Any],
) -> Finding:
    return ctx.finding(
        module_id,
        L(
            "Estado das fuses do Electron desconhecido",
            "Electron fuse state is unknown",
        ),
        Severity.INFO,
        description=Lf(
            "O sentinela de fuses em {p} está ausente ou truncado. Isso NÃO "
            "significa que as fuses estejam desligadas — significa que não dá "
            "para afirmar nada sobre elas a partir deste binário.",
            "The fuse sentinel in {p} is missing or truncated. This does NOT "
            "mean the fuses are off — it means nothing can be claimed about "
            "them from this binary.",
            p=path,
        ),
        evidence=f"format={artifact.get('format')} sha256={artifact.get('sha256')}",
        recommendation=L(
            "Confirme que o caminho é um binário do Electron (e não um "
            "lançador) e que a versão do Electron grava a wire de fuses.",
            "Check the path is an Electron binary (not a launcher) and that the "
            "Electron version writes the fuse wire.",
        ),
        references=[_ELECTRON_FUSES_DOC],
        metadata=identity,
    )


def _summary_finding(
    ctx: RunContext,
    module_id: str,
    path: Path,
    artifact: dict[str, Any],
    states: dict[str, set[str]],
    identity: dict[str, Any],
    weaknesses: list[Finding],
) -> Finding:
    lines = [
        f"{name}: {', '.join(sorted(seen))}" for name, seen in sorted(states.items())
    ]
    return ctx.finding(
        module_id,
        Lf(
            "Fuses do Electron lidas: {n} fraca(s) de {total}",
            "Electron fuses read: {n} weak of {total}",
            n=len(weaknesses),
            total=len(states),
        ),
        Severity.INFO,
        description=Lf(
            "Estado das fuses lido de {p} ({fmt}). As fuses são padrões de "
            "build, não prova de comportamento em execução: um aplicativo ainda "
            "pode ligar o Inspector pelo próprio código. Exposição, não "
            "exploração confirmada.",
            "Fuse state read from {p} ({fmt}). Fuses are build-time defaults, "
            "not proof of runtime behaviour: an application can still enable "
            "the Inspector from its own code. Exposure, not confirmed "
            "exploitation.",
            p=path,
            fmt=artifact.get("format"),
        ),
        evidence="\n".join(lines),
        references=[_ELECTRON_FUSES_DOC, _PROJECT_URL],
        metadata={**identity, "states": {k: sorted(v) for k, v in states.items()}},
    )
