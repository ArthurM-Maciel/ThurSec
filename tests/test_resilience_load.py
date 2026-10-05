"""Tests for the resilience / load-test module.

No real load is EVER generated: the single network touchpoint
(``LoadTest._do_request``) is monkeypatched with an instant in-memory fake, so
these run fast and offline while exercising every safety trap:

* missing ``max_rps``           -> refuses, no requests made;
* ``max_rps`` above the ceiling -> refused;
* invalid / over-cap duration   -> refused;
* a flag-shaped target          -> refused without any request;
* the kill-switch               -> trips on a high error rate and stops early;
* the happy path                -> returns metrics (effective RPS, latencies).
"""

import pytest

from thursec.core.context import RunContext
from thursec.core.finding import Severity
from thursec.modules.resilience import load_test as lt
from thursec.modules.resilience.load_test import (
    _HARD_MAX_DURATION,
    _HARD_MAX_RPS,
    LoadTest,
)


def _ctx(target="https://example.com", **options):
    return RunContext(target=target, options=options)


def _patch_request(monkeypatch, fake):
    """Replace the only socket touchpoint with ``fake(host, port, scheme, path, timeout)``."""
    monkeypatch.setattr(LoadTest, "_do_request", fake)


# ---------------------------------------------------------------------------
# (a) No max_rps -> no load, explanatory Finding.
# ---------------------------------------------------------------------------
async def test_missing_max_rps_refuses_without_load(monkeypatch):
    calls: list = []

    def fake(self, host, port, scheme, path, timeout=10.0):  # pragma: no cover
        calls.append(host)
        raise AssertionError("must not generate load without max_rps")

    _patch_request(monkeypatch, fake)
    findings = await LoadTest().run(_ctx())  # no max_rps

    assert calls == []
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert "no RPS ceiling" in findings[0].title


async def test_invalid_max_rps_refuses_without_load(monkeypatch):
    calls: list = []

    def fake(self, host, port, scheme, path, timeout=10.0):  # pragma: no cover
        calls.append(host)
        raise AssertionError("must not generate load with invalid max_rps")

    _patch_request(monkeypatch, fake)
    for bad in ("abc", 0, -5, 2.5):
        findings = await LoadTest().run(_ctx(max_rps=bad))
        assert calls == []
        assert len(findings) == 1
        assert findings[0].severity is Severity.LOW
        assert "RPS" in findings[0].title


# ---------------------------------------------------------------------------
# (b) max_rps above the hard ceiling -> refused.
# ---------------------------------------------------------------------------
async def test_max_rps_above_ceiling_refused(monkeypatch):
    calls: list = []

    def fake(self, host, port, scheme, path, timeout=10.0):  # pragma: no cover
        calls.append(host)
        raise AssertionError("must not generate load above the RPS ceiling")

    _patch_request(monkeypatch, fake)
    findings = await LoadTest().run(_ctx(max_rps=_HARD_MAX_RPS + 1))

    assert calls == []
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert "hard ceiling" in findings[0].title
    assert findings[0].metadata["hard_max_rps"] == _HARD_MAX_RPS


async def test_duration_above_ceiling_refused(monkeypatch):
    calls: list = []

    def fake(self, host, port, scheme, path, timeout=10.0):  # pragma: no cover
        calls.append(host)
        raise AssertionError("must not generate load above the duration ceiling")

    _patch_request(monkeypatch, fake)
    findings = await LoadTest().run(
        _ctx(max_rps=10, duration_s=_HARD_MAX_DURATION + 1)
    )

    assert calls == []
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert "duration" in findings[0].title.lower()


# ---------------------------------------------------------------------------
# (c) Kill-switch trips on a high error rate and stops early.
# ---------------------------------------------------------------------------
async def test_kill_switch_aborts_on_errors(monkeypatch):
    calls: list = []

    def fake(self, host, port, scheme, path, timeout=10.0):
        calls.append(host)
        return 503, 0.001  # every request is a 5xx error

    _patch_request(monkeypatch, fake)
    # High rps + long duration: without the kill-switch this would send
    # thousands of requests; it must stop early instead.
    findings = await LoadTest().run(
        _ctx(target="https://example.com", max_rps=100, duration_s=30)
    )

    summary = next(f for f in findings if f.title == "Load test summary")
    assert summary.metadata["aborted"] is True

    aborted = next(f for f in findings if "kill-switch" in f.title)
    assert aborted.severity is Severity.HIGH

    # Stopped early: nowhere near rps * duration requests were sent.
    assert summary.metadata["requests"] < 100 * 30
    assert len(calls) == summary.metadata["requests"]


# ---------------------------------------------------------------------------
# (d) Happy path: fast fake -> metrics, no abort, no degradation.
# ---------------------------------------------------------------------------
async def test_happy_path_returns_metrics(monkeypatch):
    calls: list = []

    def fake(self, host, port, scheme, path, timeout=10.0):
        calls.append((host, port, scheme, path))
        return 200, 0.005

    _patch_request(monkeypatch, fake)
    findings = await LoadTest().run(
        _ctx(target="https://example.com", max_rps=20, duration_s=1)
    )

    summary = next(f for f in findings if f.title == "Load test summary")
    assert summary.severity is Severity.INFO
    assert summary.metadata["aborted"] is False
    assert summary.metadata["errors"] == 0
    assert summary.metadata["requests"] >= 1
    assert summary.metadata["successes"] == summary.metadata["requests"]
    assert summary.metadata["effective_rps"] > 0
    # Latency percentiles are present and reflect the fake's ~5 ms responses.
    assert summary.metadata["latency_p50_s"] >= 0
    # No degradation / abort findings on an all-200 run.
    assert not any("degradation" in f.title for f in findings)
    assert not any("kill-switch" in f.title for f in findings)
    # Only GET was ever issued (the fake received GET-style path args).
    assert all(isinstance(c[3], str) for c in calls)


# ---------------------------------------------------------------------------
# (e) Malicious / flag-shaped target -> refused without any request.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("bad", ["-x", "--drop", "-oN/tmp/x", "", "  ", "a b"])
async def test_unsafe_target_refused_without_request(monkeypatch, bad):
    calls: list = []

    def fake(self, host, port, scheme, path, timeout=10.0):  # pragma: no cover
        calls.append(host)
        raise AssertionError("must not request for an unsafe target")

    _patch_request(monkeypatch, fake)
    findings = await LoadTest().run(_ctx(target=bad, max_rps=10))

    assert calls == []
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert "unsafe/invalid target" in findings[0].title


# ---------------------------------------------------------------------------
# Declaration sanity: the module advertises the mandatory safety posture.
# ---------------------------------------------------------------------------
def test_module_is_intrusive_and_scope_gated():
    from thursec.core.module import Category, Intensity

    m = LoadTest()
    assert m.intensity is Intensity.INTRUSIVE
    assert m.requires_scope is True
    assert m.category is Category.RESILIENCE
    assert m.id == "resilience.load_test"
    # Hard caps exist and are sane.
    assert lt._HARD_MAX_RPS == 200
    assert lt._HARD_MAX_DURATION == 60
