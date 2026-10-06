"""Port & service discovery via nmap — the first *real* ACTIVE module.

Unlike the passive recon modules, this one actually sends packets to the target,
so it is ``Intensity.ACTIVE`` and the engine's scope gate must clear the target
before :meth:`run` is ever called — nothing here re-checks scope, it only
declares the intensity and does the work.

Design choices that keep it safe-by-default:

  * ``-sT`` (TCP connect scan) instead of ``-sS`` — no raw sockets, so no root.
  * ``-sV`` for service/version detection, ``-T3`` timing (moderate, not noisy).
  * ``--top-ports`` rather than a full 65k sweep, configurable via options.
  * **No** ``-A`` and **no** arbitrary NSE scripts; if the operator passes
    ``options["scripts"]`` we only forward scripts from the ``safe``/``default``
    categories, never anything that could be intrusive.
  * Structured XML output (``-oX -``) parsed with the stdlib ``xml`` module — no
    screen-scraping, no extra dependencies.

Every failure mode (tool missing, timeout, non-zero exit, host down, unparseable
XML) is turned into a Finding; :meth:`run` never raises.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from ...core.context import RunContext
from ...core.finding import Finding, Severity
from ...core.i18n import L, Lf
from ...core.module import Category, Intensity, Module
from ...core.runner import ToolNotFoundError
from ...core.target import TargetError, validate_target

# Sensible, non-intrusive defaults. All overridable via ``ctx.options``.
_DEFAULT_TOP_PORTS = 1000
_DEFAULT_TIMING = 3  # nmap -T3, "normal" timing
_DEFAULT_TIMEOUT = 600.0  # seconds

# Service versions we flag as clearly obsolete/risky. Kept deliberately small
# and conservative: a match only nudges INFO -> LOW with a recommendation.
# Each value is a (pt, en) pair, localized at the call site so the language
# toggle applies at runtime rather than at import time.
_RISKY_SERVICES: dict[str, tuple[str, str]] = {
    "telnet": (
        "O Telnet transmite credenciais em texto puro; substitua-o por SSH.",
        "Telnet transmits credentials in cleartext; replace it with SSH.",
    ),
    "ftp": (
        "O FTP puro não é criptografado; prefira SFTP/FTPS ou desative-o.",
        "Plain FTP is unencrypted; prefer SFTP/FTPS or disable it.",
    ),
    "rlogin": (
        "Os r-services são protocolos legados inseguros; desative-os.",
        "The r-services are insecure legacy protocols; disable them.",
    ),
    "rsh": (
        "Os r-services são protocolos legados inseguros; desative-os.",
        "The r-services are insecure legacy protocols; disable them.",
    ),
    "vnc": (
        "Exponha o VNC apenas através de um túnel VPN/SSH, nunca diretamente na "
        "internet.",
        "Expose VNC only over a VPN/SSH tunnel, never directly to the internet.",
    ),
}


class NmapScan(Module):
    id = "recon.nmap"
    category = Category.RECON
    intensity = Intensity.ACTIVE
    requires_tools = ("nmap",)

    @property
    def name(self) -> str:
        return L("Varredura de portas e serviços com Nmap", "Nmap port & service scan")

    @property
    def description(self) -> str:
        return L(
            "Varredura de portas TCP connect com detecção de serviço/versão via "
            "nmap. Padrões não intrusivos (-sT -sV -T3 --top-ports); restrito a "
            "escopo.",
            "TCP connect port scan with service/version detection via nmap. "
            "Non-intrusive defaults (-sT -sV -T3 --top-ports); scope-gated.",
        )

    async def run(self, ctx: RunContext) -> list[Finding]:
        # Security gate: a target that looks like a flag (e.g. "-sS",
        # "--script=exploit", "-oN/tmp/x") would be parsed as an nmap option and
        # bypass the script allowlist. Validate BEFORE building the argv, and
        # refuse (without ever invoking nmap) if it is unsafe/implausible.
        try:
            target = validate_target(ctx.target)
        except TargetError as e:
            return [
                ctx.finding(
                    self.id,
                    L(
                        "Recusando-se a escanear: alvo inseguro/inválido",
                        "Refusing to scan: unsafe/invalid target",
                    ),
                    Severity.LOW,
                    description=L(
                        "O alvo foi rejeitado antes de executar o nmap por estar "
                        "vazio, malformado, ou por poder ser interpretado como uma "
                        "flag de linha de comando (injeção de argumentos).",
                        "The target was rejected before running nmap because it "
                        "is empty, malformed, or could be interpreted as a "
                        "command-line flag (argument injection).",
                    ),
                    evidence=str(e),
                    recommendation=L(
                        "Forneça um hostname puro, endereço IP, rede CIDR ou URL.",
                        "Provide a bare hostname, IP address, CIDR network or URL.",
                    ),
                    metadata={"target": ctx.target},
                )
            ]

        timeout = _as_float(ctx.options.get("timeout"), _DEFAULT_TIMEOUT)
        args = _build_args(target, ctx.options)

        try:
            result = await ctx.runner.run(args, timeout=timeout)
        except ToolNotFoundError as e:
            return [
                ctx.finding(
                    self.id,
                    L("nmap não instalado", "nmap not installed"),
                    Severity.INFO,
                    description=L(
                        "O binário do nmap não foi encontrado no PATH, então a "
                        "varredura de portas foi ignorada.",
                        "The nmap binary was not found on PATH, so the port scan "
                        "was skipped.",
                    ),
                    evidence=str(e),
                    recommendation=L(
                        "Instale o nmap (ex.: 'brew install nmap', "
                        "'apt install nmap') e execute este módulo novamente.",
                        "Install nmap (e.g. 'brew install nmap', "
                        "'apt install nmap') and re-run this module.",
                    ),
                    references=["https://nmap.org/"],
                    metadata={"target": target},
                )
            ]

        if result.timed_out:
            return [
                ctx.finding(
                    self.id,
                    Lf(
                        "varredura nmap expirou após {timeout:g}s",
                        "nmap scan timed out after {timeout:g}s",
                        timeout=timeout,
                    ),
                    Severity.LOW,
                    description=Lf(
                        "A varredura nmap de {target} não terminou em {timeout:g} "
                        "segundos e foi encerrada.",
                        "The nmap scan of {target} did not finish within "
                        "{timeout:g} seconds and was terminated.",
                        target=target,
                        timeout=timeout,
                    ),
                    evidence=" ".join(args),
                    recommendation=L(
                        "Aumente options['timeout'], reduza options['top_ports'] ou "
                        "escaneie menos hosts.",
                        "Increase options['timeout'], reduce options['top_ports'], "
                        "or scan fewer hosts.",
                    ),
                    metadata={"target": target, "timeout": timeout},
                )
            ]

        if result.returncode != 0:
            return [
                ctx.finding(
                    self.id,
                    Lf(
                        "nmap encerrou com status {code}",
                        "nmap exited with status {code}",
                        code=result.returncode,
                    ),
                    Severity.LOW,
                    description=Lf(
                        "O nmap não foi concluído com sucesso para {target}.",
                        "nmap did not complete successfully for {target}.",
                        target=target,
                    ),
                    evidence=(result.stderr or result.stdout or "").strip()[:500],
                    recommendation=L(
                        "Verifique a sintaxe do alvo e seus privilégios e tente "
                        "novamente.",
                        "Check the target syntax and your privileges, then retry.",
                    ),
                    metadata={"target": target, "returncode": result.returncode},
                )
            ]

        try:
            hosts = _parse_xml(result.stdout)
        except ET.ParseError as e:
            return [
                ctx.finding(
                    self.id,
                    L(
                        "Não foi possível fazer o parse da saída XML do nmap",
                        "Could not parse nmap XML output",
                    ),
                    Severity.LOW,
                    description=Lf(
                        "A saída XML do nmap para {target} não pôde ser analisada.",
                        "The nmap XML output for {target} was not parseable.",
                        target=target,
                    ),
                    evidence=f"{type(e).__name__}: {e}",
                    recommendation=L(
                        "Execute a varredura novamente; a saída pode ter sido "
                        "truncada.",
                        "Re-run the scan; the output may have been truncated.",
                    ),
                    metadata={"target": target},
                )
            ]

        return self._findings_for_hosts(ctx, target, hosts)

    # --- finding construction ---------------------------------------------
    def _findings_for_hosts(
        self, ctx: RunContext, target: str, hosts: list["_Host"]
    ) -> list[Finding]:
        up = [h for h in hosts if h.state == "up"]
        open_ports = [(h, p) for h in up for p in h.ports if p.state == "open"]

        if not up:
            return [
                ctx.finding(
                    self.id,
                    Lf(
                        "Host {target} parece estar inativo (down)",
                        "Host {target} appears to be down",
                        target=target,
                    ),
                    Severity.INFO,
                    description=Lf(
                        "O nmap não reportou nenhum host ativo para {target} "
                        "(host inativo, filtrado ou inacessível).",
                        "nmap reported no hosts up for {target} "
                        "(host down, filtered, or unreachable).",
                        target=target,
                    ),
                    metadata={"target": target, "hosts_up": 0},
                )
            ]

        if not open_ports:
            return [
                ctx.finding(
                    self.id,
                    Lf(
                        "Host {target} ativo — nenhuma porta aberta encontrada",
                        "Host {target} up — no open ports found",
                        target=target,
                    ),
                    Severity.INFO,
                    description=Lf(
                        "{n} host(s) responderam, mas nenhuma porta aberta foi "
                        "encontrada entre as escaneadas.",
                        "{n} host(s) responded but no open ports were found "
                        "among those scanned.",
                        n=len(up),
                    ),
                    metadata={"target": target, "hosts_up": len(up)},
                )
            ]

        findings: list[Finding] = []
        for host, port in open_ports:
            findings.append(self._port_finding(ctx, host, port))
        return findings

    def _port_finding(self, ctx: RunContext, host: "_Host", port: "_Port") -> Finding:
        svc_desc = " ".join(
            part for part in (port.product, port.version) if part
        ).strip()
        service_label = port.service or "unknown"
        open_port = Lf(
            "Porta aberta {port}/{proto}",
            "Open port {port}/{proto}",
            port=port.port,
            proto=port.protocol,
        )
        title = (
            f"{open_port} — {service_label}" + (f" {svc_desc}" if svc_desc else "")
        )

        severity = Severity.INFO
        recommendation = ""
        risky_hint = _RISKY_SERVICES.get(service_label.lower())
        if risky_hint:
            severity = Severity.LOW
            recommendation = L(*risky_hint)

        metadata = {
            "host": host.address,
            "port": port.port,
            "protocol": port.protocol,
            "service": port.service,
            "product": port.product,
            "version": port.version,
            "state": port.state,
        }
        evidence = _evidence_line(host, port)
        description = Lf(
            "A porta {port}/{proto} está aberta em {addr}",
            "Port {port}/{proto} is open on {addr}",
            port=port.port,
            proto=port.protocol,
            addr=host.address,
        )
        if service_label != "unknown":
            description += Lf(
                " executando {svc}", " running {svc}", svc=service_label
            )
        if svc_desc:
            description += f" ({svc_desc})"
        description += "."
        return ctx.finding(
            self.id,
            title,
            severity,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
            metadata=metadata,
        )


# --- argument building -----------------------------------------------------
def _build_args(target: str, options: dict) -> list[str]:
    """Assemble a safe-by-default nmap command line (as an argv list)."""
    top_ports = _as_int(options.get("top_ports"), _DEFAULT_TOP_PORTS)
    timing = _as_int(options.get("timing"), _DEFAULT_TIMING)
    if timing < 0 or timing > 5:
        timing = _DEFAULT_TIMING

    args = [
        "nmap",
        "-sT",  # TCP connect scan — no raw sockets, no root required
        "-sV",  # service/version detection
        f"-T{timing}",
        "--top-ports",
        str(top_ports),
        "-oX",
        "-",  # XML to stdout
    ]

    scripts = _safe_scripts(options.get("scripts"))
    if scripts:
        args += ["--script", ",".join(scripts)]

    args.append(target)
    return args


# Only these NSE script selectors are ever forwarded. Anything else is dropped.
_ALLOWED_SCRIPTS = frozenset({"safe", "default"})


def _safe_scripts(value: object) -> list[str]:
    """Filter operator-supplied NSE scripts down to safe/default categories only."""
    if value is None:
        return []
    if isinstance(value, str):
        raw = value.split(",")
    elif isinstance(value, (list, tuple, set)):
        raw = [str(v) for v in value]
    else:
        return []
    allowed = [s.strip().lower() for s in raw if s.strip().lower() in _ALLOWED_SCRIPTS]
    # Deduplicate while preserving a stable order.
    seen: set[str] = set()
    out: list[str] = []
    for s in allowed:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


# --- XML parsing -----------------------------------------------------------
class _Port:
    __slots__ = ("port", "protocol", "state", "service", "product", "version")

    def __init__(
        self,
        port: int,
        protocol: str,
        state: str,
        service: str,
        product: str,
        version: str,
    ) -> None:
        self.port = port
        self.protocol = protocol
        self.state = state
        self.service = service
        self.product = product
        self.version = version


class _Host:
    __slots__ = ("address", "state", "ports")

    def __init__(self, address: str, state: str, ports: list[_Port]) -> None:
        self.address = address
        self.state = state
        self.ports = ports


def _parse_xml(xml_text: str) -> list[_Host]:
    """Parse nmap XML into a list of hosts. Raises ET.ParseError on bad XML."""
    text = (xml_text or "").strip()
    if not text:
        return []
    root = ET.fromstring(text)

    hosts: list[_Host] = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        state = status_el.get("state", "unknown") if status_el is not None else "unknown"

        address = ""
        for addr_el in host_el.findall("address"):
            address = addr_el.get("addr", "") or address
            if addr_el.get("addrtype") in ("ipv4", "ipv6"):
                break

        ports: list[_Port] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                pstate_el = port_el.find("state")
                pstate = pstate_el.get("state", "unknown") if pstate_el is not None else "unknown"
                svc_el = port_el.find("service")
                service = svc_el.get("name", "") if svc_el is not None else ""
                product = svc_el.get("product", "") if svc_el is not None else ""
                version = svc_el.get("version", "") if svc_el is not None else ""
                try:
                    port_num = int(port_el.get("portid", "0"))
                except ValueError:
                    port_num = 0
                ports.append(
                    _Port(
                        port=port_num,
                        protocol=port_el.get("protocol", "tcp"),
                        state=pstate,
                        service=service,
                        product=product,
                        version=version,
                    )
                )
        hosts.append(_Host(address=address, state=state, ports=ports))
    return hosts


# --- small helpers ---------------------------------------------------------
def _evidence_line(host: "_Host", port: "_Port") -> str:
    svc = " ".join(p for p in (port.service, port.product, port.version) if p)
    return f"{host.address}  {port.port}/{port.protocol}  {port.state}  {svc}".strip()


def _as_int(value: object, default: int) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _as_float(value: object, default: float) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
