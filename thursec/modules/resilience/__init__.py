"""Resilience / load-testing modules.

The *legitimate* counterpart to a "stress / DoS" tool: measure how your **own,
authorized** infrastructure behaves under controlled load, never weaponize it
against someone else. Every module here is :class:`Intensity.INTRUSIVE`, so the
engine enforces the scope gate *and* an explicit confirmation before any load is
generated, and each module carries its own hard, non-removable safety caps
(RPS ceiling, duration ceiling, an automatic error-rate kill-switch, GET-only).
"""
