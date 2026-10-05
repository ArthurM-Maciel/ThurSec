"""Controlled resilience / load test — the *legitimate* counterpart to a "DoS".

This module measures how **your own, authorized** infrastructure behaves under a
bounded amount of HTTP GET traffic. It is emphatically **not** a weapon: it only
ever runs against in-scope targets, and it is wrapped in several hard, mandatory
safety caps that cannot be removed or loosened:

* **INTRUSIVE intensity.** The engine therefore enforces the scope gate *and* an
  explicit operator confirmation (a double barrier) before ``run`` is ever
  called. This module does not re-implement that gate — it only declares itself
  intrusive so the engine applies it.
* **Mandatory RPS ceiling.** The operator *must* pass ``options["max_rps"]``.
  If it is missing or invalid, **no load is generated** — a Finding explains
  why. A hard ceiling (:data:`_HARD_MAX_RPS`) is enforced in code: any requested
  rate above it is refused.
* **Duration ceiling.** ``options["duration_s"]`` (short default) is clamped by a
  hard ceiling (:data:`_HARD_MAX_DURATION`); a value above it is refused.
* **Automatic kill-switch.** If the error rate (5xx responses + failed
  connections) over a recent window exceeds :data:`_KILL_ERROR_RATE` once a
  minimum number of samples has been seen, the test aborts itself immediately
  and reports that it did so.
* **GET only.** Only idempotent, read-only ``GET`` requests are sent, so running
  the test cannot change target state. The target is routed through
  :func:`validate_target` first (argument-injection / bad-target guard).

The single network touchpoint is isolated in :meth:`LoadTest._do_request` so the
whole module is unit-testable without ever generating real traffic.
"""

from __future__ import annotations

import asyncio
from collections import deque
from urllib.parse import urlparse

from ...core.context import RunContext
from ...core.finding import Finding, Severity
from ...core.module import Category, Intensity, Module
from ...core.target import TargetError, validate_target

# --- HARD, NON-REMOVABLE SAFETY CAPS ---------------------------------------
# These bound the blast radius even against an authorized, in-scope target.
# Operator-supplied values are clamped/refused against them; they are not
# configurable from options on purpose.
_HARD_MAX_RPS = 200  # requests/second ceiling — requests above this are refused
_HARD_MAX_DURATION = 60  # seconds ceiling — longer runs are refused
_DEFAULT_DURATION = 10  # seconds, when the operator does not specify one

# Kill-switch: once at least _KILL_MIN_SAMPLES requests have completed, if the
# error rate within the most recent _KILL_WINDOW outcomes exceeds this fraction,
# the test aborts itself.
_KILL_ERROR_RATE = 0.25
_KILL_MIN_SAMPLES = 20
_KILL_WINDOW = 50

# Degradation reporting thresholds (applied to a run that completed normally).
_DEGRADE_MEDIUM_ERROR_RATE = 0.10
_DEGRADE_HIGH_ERROR_RATE = 0.25

_DEFAULT_TIMEOUT = 10.0
# Never launch more than this many in-flight requests at once, regardless of RPS
# (a second guard so a slow target cannot make us pile up unbounded tasks).
_MAX_CONCURRENCY = 50


class LoadTest(Module):
    id = "resilience.load_test"
    name = "Resilience / load test"
    category = Category.RESILIENCE
    intensity = Intensity.INTRUSIVE
    description = (
        "Controlled HTTP GET load test to measure how your OWN authorized "
        "infrastructure behaves under load. Requires an explicit max_rps and is "
        "hard-capped on rate and duration, with an automatic error-rate "
        "kill-switch. GET-only (never changes state)."
    )

    async def run(self, ctx: RunContext) -> list[Finding]:
        # 1) Argument-injection / invalid-target guard — refuse BEFORE any load.
        try:
            validate_target(ctx.target)
        except TargetError as e:
            return [
                ctx.finding(
                    self.id,
                    "Refusing to run: unsafe/invalid target",
                    Severity.LOW,
                    description=(
                        "The target was rejected before any traffic because it is "
                        "not a valid host/URL and could be read as a command-line "
                        "option."
                    ),
                    evidence=str(e),
                    recommendation="Provide a plain hostname, IP, or URL you own.",
                )
            ]

        # 2) Mandatory RPS ceiling — no load unless a valid max_rps is given.
        rps = _coerce_positive_int(ctx.options.get("max_rps"))
        if rps is None:
            return [
                ctx.finding(
                    self.id,
                    "Refusing to run: no RPS ceiling provided",
                    Severity.LOW,
                    description=(
                        "A load test must be bounded. The operator must set "
                        "options['max_rps'] to an integer between 1 and "
                        f"{_HARD_MAX_RPS}. No traffic was generated."
                    ),
                    recommendation=(
                        f"Re-run with a max_rps of 1..{_HARD_MAX_RPS}, e.g. "
                        "max_rps=20."
                    ),
                    metadata={"hard_max_rps": _HARD_MAX_RPS},
                )
            ]
        if rps > _HARD_MAX_RPS:
            return [
                ctx.finding(
                    self.id,
                    "Refusing to run: requested RPS exceeds hard ceiling",
                    Severity.LOW,
                    description=(
                        f"Requested max_rps={rps} is above the hard ceiling of "
                        f"{_HARD_MAX_RPS} req/s. This cap is non-negotiable; no "
                        "traffic was generated."
                    ),
                    evidence=f"max_rps={rps} > _HARD_MAX_RPS={_HARD_MAX_RPS}",
                    recommendation=f"Lower max_rps to at most {_HARD_MAX_RPS}.",
                    metadata={"requested_rps": rps, "hard_max_rps": _HARD_MAX_RPS},
                )
            ]

        # 3) Duration ceiling (short default, hard cap).
        if "duration_s" in ctx.options:
            duration = _coerce_positive_int(ctx.options.get("duration_s"))
            if duration is None:
                return [
                    ctx.finding(
                        self.id,
                        "Refusing to run: invalid duration",
                        Severity.LOW,
                        description=(
                            "options['duration_s'] must be an integer between 1 "
                            f"and {_HARD_MAX_DURATION} seconds. No traffic was "
                            "generated."
                        ),
                        recommendation=(
                            f"Provide duration_s in 1..{_HARD_MAX_DURATION}."
                        ),
                        metadata={"hard_max_duration": _HARD_MAX_DURATION},
                    )
                ]
            if duration > _HARD_MAX_DURATION:
                return [
                    ctx.finding(
                        self.id,
                        "Refusing to run: duration exceeds hard ceiling",
                        Severity.LOW,
                        description=(
                            f"Requested duration_s={duration} is above the hard "
                            f"ceiling of {_HARD_MAX_DURATION}s. This cap is "
                            "non-negotiable; no traffic was generated."
                        ),
                        evidence=(
                            f"duration_s={duration} > "
                            f"_HARD_MAX_DURATION={_HARD_MAX_DURATION}"
                        ),
                        recommendation=(
                            f"Lower duration_s to at most {_HARD_MAX_DURATION}."
                        ),
                        metadata={
                            "requested_duration": duration,
                            "hard_max_duration": _HARD_MAX_DURATION,
                        },
                    )
                ]
        else:
            duration = _DEFAULT_DURATION

        scheme, host, port, path = _parse_target(ctx.target, ctx.options)
        timeout = _coerce_timeout(ctx.options.get("timeout"))

        # 4) Generate the bounded load and collect metrics.
        stats = await self._generate_load(
            host, port, scheme, path, rps, duration, timeout
        )
        return self._report(ctx, stats, rps, duration)

    # --- load generation ---------------------------------------------------
    async def _generate_load(
        self,
        host: str,
        port: int,
        scheme: str,
        path: str,
        rps: int,
        duration: int,
        timeout: float,
    ) -> "_Stats":
        """Drive GET requests at ~``rps`` for ``duration`` seconds.

        Requests are launched on a fixed schedule (one every ``1/rps`` seconds)
        and executed concurrently under a bounded semaphore. The kill-switch can
        stop the run early. Pure orchestration — the only socket work happens in
        :meth:`_do_request`, which is isolated for testing.
        """
        loop = asyncio.get_event_loop()
        stats = _Stats()
        abort = asyncio.Event()
        window: deque[bool] = deque(maxlen=_KILL_WINDOW)
        sem = asyncio.Semaphore(min(_MAX_CONCURRENCY, max(1, rps)))

        def record(latency: float, is_error: bool) -> None:
            stats.total += 1
            stats.latencies.append(latency)
            if is_error:
                stats.errors += 1
            else:
                stats.successes += 1
            window.append(is_error)
            # Kill-switch: enough samples AND the recent window is too error-y.
            if (
                not abort.is_set()
                and stats.total >= _KILL_MIN_SAMPLES
                and sum(window) / len(window) > _KILL_ERROR_RATE
            ):
                abort.set()
                stats.aborted = True
                stats.abort_error_rate = sum(window) / len(window)

        async def worker() -> None:
            async with sem:
                if abort.is_set():
                    return
                t0 = loop.time()
                try:
                    status, latency = await asyncio.to_thread(
                        self._do_request, host, port, scheme, path, timeout
                    )
                    is_error = status is None or status >= 500
                except Exception:
                    # Connection refused / reset / timeout / DNS — counts as a
                    # failed request for the error rate and kill-switch.
                    latency = loop.time() - t0
                    is_error = True
                record(latency, is_error)

        interval = 1.0 / rps
        start = loop.time()
        next_launch = start
        tasks: list[asyncio.Task] = []
        while True:
            now = loop.time()
            if abort.is_set() or (now - start) >= duration:
                break
            tasks.append(asyncio.create_task(worker()))
            next_launch += interval
            sleep_for = next_launch - loop.time()
            if sleep_for > 0:
                try:
                    await asyncio.wait_for(abort.wait(), timeout=sleep_for)
                except asyncio.TimeoutError:
                    pass  # normal: slept the full interval without aborting

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        stats.elapsed = max(loop.time() - start, 1e-9)
        return stats

    # --- findings ----------------------------------------------------------
    def _report(
        self, ctx: RunContext, stats: "_Stats", rps: int, duration: int
    ) -> list[Finding]:
        if stats.total == 0:
            return [
                ctx.finding(
                    self.id,
                    "Load test generated no completed requests",
                    Severity.INFO,
                    description=(
                        "No requests completed within the window. The target may "
                        "be unreachable on this host/port."
                    ),
                    metadata={"target_max_rps": rps, "duration_s": duration},
                )
            ]

        error_rate = stats.errors / stats.total
        effective_rps = stats.total / stats.elapsed
        p50, p90, p99 = _percentiles(stats.latencies)
        metadata = {
            "requests": stats.total,
            "successes": stats.successes,
            "errors": stats.errors,
            "error_rate": round(error_rate, 4),
            "target_max_rps": rps,
            "effective_rps": round(effective_rps, 2),
            "duration_s": duration,
            "elapsed_s": round(stats.elapsed, 3),
            "latency_p50_s": round(p50, 4),
            "latency_p90_s": round(p90, 4),
            "latency_p99_s": round(p99, 4),
            "aborted": stats.aborted,
        }
        summary = (
            f"{stats.total} GET requests, {effective_rps:.1f} eff. req/s, "
            f"error rate {error_rate:.1%}, "
            f"latency p50/p90/p99 = {p50*1000:.0f}/{p90*1000:.0f}/"
            f"{p99*1000:.0f} ms"
        )

        findings: list[Finding] = [
            ctx.finding(
                self.id,
                "Load test summary",
                Severity.INFO,
                description=summary,
                evidence=(
                    f"target<= {rps} req/s for up to {duration}s; "
                    f"sent {stats.total}, errors {stats.errors}"
                ),
                metadata=metadata,
            )
        ]

        if stats.aborted:
            findings.append(
                ctx.finding(
                    self.id,
                    "Load test aborted by kill-switch",
                    Severity.HIGH,
                    description=(
                        "The automatic kill-switch tripped: the recent error rate "
                        f"({stats.abort_error_rate:.1%}) exceeded the "
                        f"{_KILL_ERROR_RATE:.0%} threshold, so the test stopped "
                        "early to avoid piling load onto a failing target."
                    ),
                    evidence=(
                        f"window error rate {stats.abort_error_rate:.1%} > "
                        f"{_KILL_ERROR_RATE:.0%} after {stats.total} requests"
                    ),
                    recommendation=(
                        "The target is failing under this load. Investigate "
                        "capacity/health before testing again at this rate."
                    ),
                    metadata=metadata,
                )
            )
        elif error_rate >= _DEGRADE_HIGH_ERROR_RATE:
            findings.append(
                ctx.finding(
                    self.id,
                    "Target showed degradation under load",
                    Severity.HIGH,
                    description=(
                        f"The target returned a high error rate ({error_rate:.1%}) "
                        f"while serving ~{effective_rps:.0f} req/s."
                    ),
                    evidence=f"errors {stats.errors}/{stats.total}",
                    recommendation=(
                        "Review server capacity, timeouts and autoscaling at this "
                        "request rate."
                    ),
                    metadata=metadata,
                )
            )
        elif error_rate >= _DEGRADE_MEDIUM_ERROR_RATE:
            findings.append(
                ctx.finding(
                    self.id,
                    "Target showed degradation under load",
                    Severity.MEDIUM,
                    description=(
                        f"The target returned an elevated error rate "
                        f"({error_rate:.1%}) while serving ~{effective_rps:.0f} "
                        "req/s."
                    ),
                    evidence=f"errors {stats.errors}/{stats.total}",
                    recommendation=(
                        "Investigate the failing responses; the target may be "
                        "approaching its capacity limit."
                    ),
                    metadata=metadata,
                )
            )
        return findings

    # --- the only network touchpoint (isolated for tests) ------------------
    def _do_request(
        self,
        host: str,
        port: int,
        scheme: str,
        path: str,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> tuple[int, float]:
        """Send a single ``GET`` and return ``(status, latency_seconds)``.

        Blocking (stdlib ``http.client``); callers run it via
        ``asyncio.to_thread``. GET-only by construction, so it cannot change
        target state. Raises on connection failure (the caller treats that as an
        errored request). This is deliberately the ONLY place a socket is opened,
        so the rest of the module is unit-testable with no real traffic.
        """
        import http.client
        import time

        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        t0 = time.monotonic()
        try:
            conn.request("GET", path or "/", headers={"User-Agent": "ThurSec/0.1"})
            resp = conn.getresponse()
            resp.read()  # drain so the connection closes cleanly
            return resp.status, time.monotonic() - t0
        finally:
            conn.close()


# --- internal state --------------------------------------------------------
class _Stats:
    __slots__ = (
        "total",
        "successes",
        "errors",
        "latencies",
        "aborted",
        "abort_error_rate",
        "elapsed",
    )

    def __init__(self) -> None:
        self.total = 0
        self.successes = 0
        self.errors = 0
        self.latencies: list[float] = []
        self.aborted = False
        self.abort_error_rate = 0.0
        self.elapsed = 0.0


# --- helpers ---------------------------------------------------------------
def _coerce_positive_int(value: object) -> int | None:
    """Return a strictly-positive int, or ``None`` for anything invalid.

    Booleans are rejected (``True`` is an int in Python but is never a valid
    rate/duration); floats like ``5.0`` are accepted, ``5.5`` is not.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, float):
            if not value.is_integer():
                return None
            ivalue = int(value)
        else:
            ivalue = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return ivalue if ivalue >= 1 else None


def _coerce_timeout(value: object) -> float:
    try:
        t = float(value)  # type: ignore[arg-type]
        return t if t > 0 else _DEFAULT_TIMEOUT
    except (TypeError, ValueError):
        return _DEFAULT_TIMEOUT


def _percentiles(latencies: list[float]) -> tuple[float, float, float]:
    """Return (p50, p90, p99) using the nearest-rank method; empty -> zeros."""
    if not latencies:
        return 0.0, 0.0, 0.0
    ordered = sorted(latencies)
    n = len(ordered)

    def pick(pct: float) -> float:
        rank = max(1, int(round(pct / 100.0 * n)))
        return ordered[min(rank, n) - 1]

    return pick(50), pick(90), pick(99)


def _parse_target(target: str, options: dict) -> tuple[str, str, int, str]:
    """Derive ``(scheme, host, port, path)`` from the target and options.

    Understands a full URL (scheme/host/port/path honored), a bare ``host`` and
    a ``host:port``. Defaults to https/443; ``http`` with no port uses 80.
    ``options['port']`` overrides a port that is otherwise unspecified;
    ``options['path']`` overrides the request path.
    """
    t = target.strip()
    scheme = "https"
    port: int | None = None
    path = "/"

    if "://" in t:
        parsed = urlparse(t)
        scheme = (parsed.scheme or "https").lower()
        host = parsed.hostname or ""
        port = parsed.port
        if parsed.path:
            path = parsed.path
    elif t.count(":") == 1:
        host, _, p = t.partition(":")
        try:
            port = int(p)
        except ValueError:
            port = None
    else:
        host = t

    if "port" in options and port is None:
        try:
            port = int(options["port"])
        except (TypeError, ValueError):
            port = None
    if options.get("path"):
        path = str(options["path"])

    if port is None:
        port = 443 if scheme == "https" else 80
    return scheme, host, port, path
