"""Tests for the nuclei vulnerability module.

nuclei is never actually executed: we replace ``ctx.runner.run`` with a fake
coroutine that returns a canned :class:`CommandResult`, so these run fast and
offline while still exercising parsing, severity mapping, and every error path.
"""

import json

import pytest

from thursec.core.context import RunContext
from thursec.core.finding import Severity
from thursec.core.i18n import get_lang, set_lang
from thursec.core.runner import CommandResult, ToolNotFoundError
from thursec.modules.vuln.nuclei import NucleiScan


@pytest.fixture(autouse=True)
def _force_english():
    """These tests assert the English finding text; pin the language to en."""
    prev = get_lang()
    set_lang("en")
    try:
        yield
    finally:
        set_lang(prev)


# Three real-shaped JSONL records of differing severity, plus a line of garbage
# in the middle that the parser must skip without blowing up.
_SAMPLE_JSONL = "\n".join(
    [
        json.dumps(
            {
                "template-id": "tech-detect",
                "info": {"name": "Nginx detected", "severity": "info"},
                "type": "http",
                "host": "https://example.com",
                "matched-at": "https://example.com",
            }
        ),
        "this is not json {{{",  # malformed — must be ignored
        json.dumps(
            {
                "template-id": "weak-tls",
                "info": {
                    "name": "Weak TLS version",
                    "severity": "medium",
                    "description": "Server supports an outdated TLS version.",
                    "reference": ["https://example.org/tls"],
                    "tags": ["ssl", "tls"],
                },
                "type": "ssl",
                "matched-at": "example.com:443",
                "matcher-name": "tls-1.0",
            }
        ),
        json.dumps(
            {
                "template-id": "CVE-2021-44228",
                "info": {
                    "name": "Apache Log4j RCE",
                    "severity": "critical",
                    "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                },
                "type": "http",
                "matched-at": "https://example.com/api",
                "extracted-results": ["jndi:ldap"],
            }
        ),
    ]
)


class _FakeRunner:
    """Stands in for CommandRunner: records args, returns a canned result."""

    def __init__(self, result=None, raise_exc=None):
        self._result = result
        self._raise = raise_exc
        self.calls: list[list[str]] = []

    async def run(self, args, *, timeout=None, input_text=None):
        self.calls.append(list(args))
        if self._raise is not None:
            raise self._raise
        return self._result


def _ctx(runner, target="https://example.com", **options):
    return RunContext(target=target, runner=runner, options=options)


def _result(stdout="", stderr="", returncode=0, timed_out=False):
    return CommandResult(
        args=["nuclei"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
    )


async def test_parses_findings_and_maps_severity():
    runner = _FakeRunner(_result(stdout=_SAMPLE_JSONL))
    findings = await NucleiScan().run(_ctx(runner))

    # Three valid records -> three findings; the malformed line is dropped.
    assert len(findings) == 3
    by_sev = {f.metadata["template-id"]: f.severity for f in findings}
    assert by_sev["tech-detect"] is Severity.INFO
    assert by_sev["weak-tls"] is Severity.MEDIUM
    assert by_sev["CVE-2021-44228"] is Severity.CRITICAL


async def test_finding_fields_mapped():
    runner = _FakeRunner(_result(stdout=_SAMPLE_JSONL))
    findings = await NucleiScan().run(_ctx(runner))
    tls = next(f for f in findings if f.metadata["template-id"] == "weak-tls")

    assert tls.title == "nuclei: Weak TLS version"
    assert "outdated TLS" in tls.description
    assert "tls-1.0" in tls.description  # matcher-name folded in
    assert tls.references == ["https://example.org/tls"]
    assert "example.com:443" in tls.evidence
    assert tls.metadata["matched-at"] == "example.com:443"
    assert tls.metadata["nuclei-severity"] == "medium"

    # A string "reference" is normalised to a list.
    log4j = next(f for f in findings if f.metadata["template-id"] == "CVE-2021-44228")
    assert log4j.references == ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
    assert "jndi:ldap" in log4j.evidence


async def test_malformed_line_does_not_raise():
    only_garbage = "not json\n{broken\n\n   \n}}}"
    runner = _FakeRunner(_result(stdout=only_garbage, returncode=0))
    findings = await NucleiScan().run(_ctx(runner))
    # No parseable findings on a clean exit -> single INFO "no matches".
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert "no matches" in findings[0].title.lower()


async def test_excludes_dangerous_tags_by_default():
    runner = _FakeRunner(_result(stdout=""))
    await NucleiScan().run(_ctx(runner))
    args = runner.calls[0]
    assert "-exclude-tags" in args
    idx = args.index("-exclude-tags")
    assert args[idx + 1] == "dos,intrusive,fuzzing"
    assert "-jsonl" in args and "-silent" in args


async def test_allow_intrusive_drops_exclusion():
    runner = _FakeRunner(_result(stdout=""))
    await NucleiScan().run(_ctx(runner, allow_intrusive=True))
    assert "-exclude-tags" not in runner.calls[0]


async def test_timeout_path():
    runner = _FakeRunner(_result(timed_out=True, returncode=-1))
    findings = await NucleiScan().run(_ctx(runner, timeout=5))
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert "timed out" in findings[0].title.lower()


async def test_tool_not_installed_path():
    runner = _FakeRunner(raise_exc=ToolNotFoundError("nuclei"))
    findings = await NucleiScan().run(_ctx(runner))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.INFO
    assert "not installed" in f.title.lower()
    assert "go install" in f.recommendation.lower()


async def test_nonzero_exit_without_findings_is_low():
    runner = _FakeRunner(
        _result(stdout="", stderr="connection refused", returncode=1)
    )
    findings = await NucleiScan().run(_ctx(runner))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.LOW
    assert "failed" in f.title.lower()
    assert "connection refused" in f.evidence


async def test_passes_target_and_extra_args():
    runner = _FakeRunner(_result(stdout=""))
    await NucleiScan().run(_ctx(runner, extra_args=["-tags", "cve"]))
    args = runner.calls[0]
    assert args[:3] == ["nuclei", "-u", "https://example.com"]
    assert args[-2:] == ["-tags", "cve"]


# --- argument-injection hardening -----------------------------------------
import pytest

from thursec.core.context import RunContext
from thursec.modules.vuln.nuclei import NucleiScan


class _RecordingRunner:
    """Fake runner that records whether it was ever called."""

    def __init__(self):
        self.calls = []

    async def run(self, args, timeout=None, input_text=None):  # pragma: no cover
        self.calls.append(args)
        raise AssertionError("runner must not be called for an unsafe target")


@pytest.mark.parametrize("bad", ["-config", "--list-templates", "-H", "", "  ", "a b"])
async def test_nuclei_rejects_unsafe_target_without_invoking_binary(bad):
    runner = _RecordingRunner()
    ctx = RunContext(target=bad, runner=runner)
    findings = await NucleiScan().run(ctx)
    assert runner.calls == []  # binary never invoked
    assert len(findings) == 1
    assert "Refusing to scan" in findings[0].title
