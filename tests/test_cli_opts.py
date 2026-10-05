"""Tests for the CLI `run --opt KEY=VALUE` module-options plumbing."""

import pytest

from thursec import cli
from thursec.core.context import RunContext
from thursec.core.engine import Registry
from thursec.core.finding import Severity
from thursec.core.module import Category, Intensity, Module


# --- _parse_opts / _coerce ------------------------------------------------
def test_parse_opts_coerces_types():
    out = cli._parse_opts(
        ["max_rps=50", "allow_intrusive=true", "q=abc", "r=1.5", "neg=-3"]
    )
    assert out == {
        "max_rps": 50,
        "allow_intrusive": True,
        "q": "abc",
        "r": 1.5,
        "neg": -3,
    }
    assert out["max_rps"] == 50 and isinstance(out["max_rps"], int)
    assert out["allow_intrusive"] is True
    assert isinstance(out["r"], float)


def test_parse_opts_bool_is_case_insensitive():
    out = cli._parse_opts(["a=TRUE", "b=False", "c=True"])
    assert out == {"a": True, "b": False, "c": True}


def test_parse_opts_missing_equals_raises():
    with pytest.raises(ValueError):
        cli._parse_opts(["max_rps"])


def test_parse_opts_equals_in_value_is_preserved():
    out = cli._parse_opts(["url=http://x?a=b"])
    assert out["url"] == "http://x?a=b"


def test_parse_opts_last_key_wins():
    out = cli._parse_opts(["port=80", "port=8080"])
    assert out["port"] == 8080


def test_parse_opts_empty_value_is_empty_string():
    out = cli._parse_opts(["k="])
    assert out["k"] == ""


def test_parse_opts_floats_vs_ints_vs_strings():
    out = cli._parse_opts(["i=0", "f=0.0", "s=1.2.3", "v=v1"])
    assert out["i"] == 0 and isinstance(out["i"], int)
    assert out["f"] == 0.0 and isinstance(out["f"], float)
    assert out["s"] == "1.2.3"  # not a plain int/float -> string
    assert out["v"] == "v1"


# --- integration: options reach ctx.options -------------------------------
class _EchoMod(Module):
    """A PASSIVE module that echoes ctx.options into a finding's metadata."""

    id = "test.echo_opts"
    name = "echo options"
    category = Category.RECON
    intensity = Intensity.PASSIVE

    async def run(self, ctx: RunContext):
        return [
            ctx.finding(
                self.id, "options echo", Severity.INFO, metadata=dict(ctx.options)
            )
        ]


def test_opts_reach_ctx_options(monkeypatch, capsys):
    captured: dict = {}

    orig_add = __import__(
        "thursec.core.report", fromlist=["Report"]
    ).Report.add

    def _spy_add(self, findings):
        for f in findings:
            if f.module == "test.echo_opts":
                captured.update(f.metadata)
        return orig_add(self, findings)

    monkeypatch.setattr("thursec.core.report.Report.add", _spy_add)

    def _fake_discover(self, package="thursec.modules"):
        self.register(_EchoMod())
        return self

    monkeypatch.setattr(Registry, "discover", _fake_discover)

    rc = cli.main(
        [
            "run", "echo.example",
            "-m", "test.echo_opts",
            "--opt", "max_rps=50",
            "--opt", "product=nginx",
            "--opt", "allow_intrusive=true",
        ]
    )
    assert rc == 0
    assert captured["max_rps"] == 50
    assert captured["product"] == "nginx"
    assert captured["allow_intrusive"] is True


def test_opt_missing_equals_exits_2(monkeypatch):
    def _fake_discover(self, package="thursec.modules"):
        self.register(_EchoMod())
        return self

    monkeypatch.setattr(Registry, "discover", _fake_discover)

    rc = cli.main(
        ["run", "echo.example", "-m", "test.echo_opts", "--opt", "bogus"]
    )
    assert rc == 2


def test_run_without_opts_still_works(monkeypatch):
    def _fake_discover(self, package="thursec.modules"):
        self.register(_EchoMod())
        return self

    monkeypatch.setattr(Registry, "discover", _fake_discover)

    rc = cli.main(["run", "echo.example", "-m", "test.echo_opts"])
    assert rc == 0
