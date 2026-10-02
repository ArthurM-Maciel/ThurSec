"""Tests for the nmap port/service scan module.

Crucially, nmap is *never* actually executed: we monkeypatch ``ctx.runner.run``
to return a canned ``CommandResult`` carrying sample nmap XML (or a timeout /
non-zero exit), so the tests are fast, deterministic and safe to run anywhere.
"""

import pytest

from thursec.core.context import RunContext
from thursec.core.finding import Severity
from thursec.core.module import Category, Intensity
from thursec.core.runner import CommandResult, ToolNotFoundError
from thursec.modules.recon.nmap_scan import (
    NmapScan,
    _build_args,
    _parse_xml,
    _safe_scripts,
)

# A realistic (trimmed) nmap -oX output: host up with three open ports, each
# carrying service/product/version, plus one closed port that must be ignored.
_XML_UP = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -sV example.com">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" method="probed"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18.0" method="probed"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="open" reason="syn-ack"/>
        <service name="telnet" method="table"/>
      </port>
      <port protocol="tcp" portid="81">
        <state state="closed" reason="conn-refused"/>
        <service name="hosts2-ns"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

# Host down: a run that completed fine but found nobody home.
_XML_DOWN = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="down" reason="no-response"/>
    <address addr="10.0.0.9" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


def _ctx(target="example.com", **options):
    return RunContext(target=target, options=options)


def _patch_run(monkeypatch, ctx, result):
    async def fake_run(args, *, timeout=None, input_text=None):
        fake_run.calls.append({"args": args, "timeout": timeout})
        return result

    fake_run.calls = []
    monkeypatch.setattr(ctx.runner, "run", fake_run)
    return fake_run


# --- module declaration ----------------------------------------------------
def test_module_is_active_recon_with_nmap_tool():
    m = NmapScan()
    assert m.id == "recon.nmap"
    assert m.category is Category.RECON
    assert m.intensity is Intensity.ACTIVE
    assert m.requires_scope is True  # ACTIVE => scope-gated by the engine
    assert m.requires_tools == ("nmap",)


# --- argument building (safe-by-default) -----------------------------------
def test_build_args_defaults_are_non_intrusive():
    args = _build_args("example.com", {})
    assert args[0] == "nmap"
    assert "-sT" in args  # connect scan, no root
    assert "-sV" in args
    assert "-T3" in args
    assert "--top-ports" in args
    assert args[args.index("--top-ports") + 1] == "1000"
    assert "-oX" in args and "-" in args
    assert args[-1] == "example.com"  # target is last
    # Never aggressive / scripted by default.
    assert "-A" not in args
    assert "-sS" not in args
    assert "--script" not in args


def test_build_args_honors_top_ports_and_timing():
    args = _build_args("t", {"top_ports": 100, "timing": 2})
    assert args[args.index("--top-ports") + 1] == "100"
    assert "-T2" in args


def test_scripts_filtered_to_safe_default_only():
    # Dangerous categories are dropped; only safe/default survive.
    assert _safe_scripts("safe,vuln,intrusive,exploit") == ["safe"]
    assert _safe_scripts(["default", "brute", "safe"]) == ["default", "safe"]
    assert _safe_scripts(None) == []
    assert _safe_scripts("http-shellshock") == []
    args = _build_args("t", {"scripts": "safe,exploit"})
    assert "--script" in args
    assert args[args.index("--script") + 1] == "safe"


# --- XML parsing & open-port findings --------------------------------------
async def test_run_parses_open_ports(monkeypatch):
    ctx = _ctx()
    result = CommandResult(args=["nmap"], returncode=0, stdout=_XML_UP, stderr="")
    _patch_run(monkeypatch, ctx, result)

    findings = await NmapScan().run(ctx)
    # One finding per *open* port (closed 81 ignored) => 3.
    assert len(findings) == 3

    by_port = {f.metadata["port"]: f for f in findings}
    assert set(by_port) == {22, 80, 23}

    ssh = by_port[22]
    assert ssh.metadata["service"] == "ssh"
    assert ssh.metadata["product"] == "OpenSSH"
    assert ssh.metadata["version"] == "8.9p1"
    assert ssh.metadata["protocol"] == "tcp"
    assert ssh.metadata["state"] == "open"
    assert ssh.metadata["host"] == "93.184.216.34"
    assert ssh.severity is Severity.INFO
    assert "Open port 22/tcp" in ssh.title
    assert "ssh" in ssh.title and "OpenSSH 8.9p1" in ssh.title
    assert "OpenSSH" in ssh.evidence

    http = by_port[80]
    assert http.metadata["product"] == "nginx"
    assert http.severity is Severity.INFO


async def test_run_elevates_risky_service_to_low(monkeypatch):
    ctx = _ctx()
    result = CommandResult(args=["nmap"], returncode=0, stdout=_XML_UP, stderr="")
    _patch_run(monkeypatch, ctx, result)

    findings = await NmapScan().run(ctx)
    telnet = next(f for f in findings if f.metadata["port"] == 23)
    assert telnet.metadata["service"] == "telnet"
    assert telnet.severity is Severity.LOW
    assert telnet.recommendation  # a hint was attached


async def test_run_host_down_is_info(monkeypatch):
    ctx = _ctx(target="10.0.0.9")
    result = CommandResult(args=["nmap"], returncode=0, stdout=_XML_DOWN, stderr="")
    _patch_run(monkeypatch, ctx, result)

    findings = await NmapScan().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert "down" in findings[0].title.lower()
    assert findings[0].metadata["hosts_up"] == 0


async def test_run_empty_xml_is_info(monkeypatch):
    ctx = _ctx()
    result = CommandResult(args=["nmap"], returncode=0, stdout="", stderr="")
    _patch_run(monkeypatch, ctx, result)

    findings = await NmapScan().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO


# --- failure modes (never raise) -------------------------------------------
async def test_run_timeout_is_low(monkeypatch):
    ctx = _ctx(timeout=5)
    result = CommandResult(
        args=["nmap"], returncode=-1, stdout="", stderr="", timed_out=True
    )
    _patch_run(monkeypatch, ctx, result)

    findings = await NmapScan().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert "timed out" in findings[0].title.lower()


async def test_run_nonzero_exit_is_low_with_stderr(monkeypatch):
    ctx = _ctx()
    result = CommandResult(
        args=["nmap"], returncode=1, stdout="", stderr="Failed to resolve target"
    )
    _patch_run(monkeypatch, ctx, result)

    findings = await NmapScan().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert "Failed to resolve" in findings[0].evidence


async def test_run_bad_xml_is_low(monkeypatch):
    ctx = _ctx()
    result = CommandResult(
        args=["nmap"], returncode=0, stdout="<nmaprun><host", stderr=""
    )
    _patch_run(monkeypatch, ctx, result)

    findings = await NmapScan().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert "parse" in findings[0].title.lower()


async def test_run_tool_not_found_is_info(monkeypatch):
    ctx = _ctx()

    async def boom(args, *, timeout=None, input_text=None):
        raise ToolNotFoundError("nmap")

    monkeypatch.setattr(ctx.runner, "run", boom)

    findings = await NmapScan().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert "not installed" in findings[0].title.lower()
    assert "install" in findings[0].recommendation.lower()


# --- argument-injection defense --------------------------------------------
@pytest.mark.parametrize(
    "bad_target",
    ["-sS", "--script=http-shellshock,exploit", "-oN/tmp/pwned", "", "bad target"],
)
async def test_run_refuses_unsafe_target_without_invoking_nmap(
    monkeypatch, bad_target
):
    ctx = _ctx(target=bad_target)
    fake = _patch_run(
        monkeypatch,
        ctx,
        CommandResult(args=["nmap"], returncode=0, stdout=_XML_UP, stderr=""),
    )

    findings = await NmapScan().run(ctx)

    # nmap must NEVER have been invoked for a dangerous/invalid target.
    assert fake.calls == []
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert "Refusing to scan" in findings[0].title


# --- target normalization --------------------------------------------------
async def test_run_normalizes_url_target(monkeypatch):
    ctx = _ctx(target="https://example.com:8443/path")
    result = CommandResult(args=["nmap"], returncode=0, stdout=_XML_UP, stderr="")
    fake = _patch_run(monkeypatch, ctx, result)

    await NmapScan().run(ctx)
    assert fake.calls[0]["args"][-1] == "example.com"


def test_parse_xml_blank_returns_empty():
    assert _parse_xml("") == []
    assert _parse_xml("   ") == []
