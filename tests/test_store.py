"""Tests for the historical findings store (PLAT1)."""

from __future__ import annotations

import time

from thursec.core.finding import Finding, Severity
from thursec.core.store import FindingStore


def _store(tmp_path):
    return FindingStore(tmp_path / "thursec.db")


def test_save_run_returns_id_and_persists_findings(tmp_path):
    store = _store(tmp_path)
    findings = [
        Finding("m", "t.example", "open port", Severity.HIGH),
        Finding("m", "t.example", "weak tls", Severity.MEDIUM),
    ]
    run_id = store.save_run("ad-hoc", "t.example", findings)
    assert isinstance(run_id, int) and run_id > 0

    stored = store.get_findings(run_id)
    assert len(stored) == 2
    titles = {f["title"] for f in stored}
    assert titles == {"open port", "weak tls"}
    # severity sort: HIGH before MEDIUM
    assert stored[0]["title"] == "open port"


def test_dedup_by_fingerprint_within_run(tmp_path):
    store = _store(tmp_path)
    findings = [
        Finding("m", "t", "dup", Severity.LOW, evidence="a"),
        Finding("m", "t", "dup", Severity.LOW, evidence="b"),  # same fingerprint
    ]
    run_id = store.save_run("e", "t", findings)
    assert len(store.get_findings(run_id)) == 1


def test_list_runs_orders_most_recent_first(tmp_path):
    store = _store(tmp_path)
    r1 = store.save_run("e", "t", [Finding("m", "t", "a", Severity.LOW)])
    r2 = store.save_run("e", "t", [Finding("m", "t", "b", Severity.LOW)])
    r3 = store.save_run("e", "t", [Finding("m", "t", "c", Severity.LOW)])
    runs = store.list_runs(target="t")
    assert [r["id"] for r in runs] == [r3, r2, r1]
    assert runs[0]["finding_count"] == 1


def test_list_runs_filters_by_target_and_engagement(tmp_path):
    store = _store(tmp_path)
    store.save_run("eng-a", "t1", [Finding("m", "t1", "x", Severity.LOW)])
    store.save_run("eng-b", "t2", [Finding("m", "t2", "y", Severity.LOW)])
    assert len(store.list_runs(target="t1")) == 1
    assert len(store.list_runs(engagement="eng-b")) == 1
    assert len(store.list_runs()) == 2


def test_first_seen_last_seen_tracking(tmp_path):
    store = _store(tmp_path)
    f = Finding("m", "t", "persistent", Severity.HIGH)
    r1 = store.save_run("e", "t", [f])
    time.sleep(0.01)
    r2 = store.save_run("e", "t", [Finding("m", "t", "persistent", Severity.HIGH)])

    fp = f.fingerprint
    a = next(x for x in store.get_findings(r1) if x["fingerprint"] == fp)
    b = next(x for x in store.get_findings(r2) if x["fingerprint"] == fp)

    # first_seen is carried forward from the first run to the second.
    assert b["first_seen"] == a["first_seen"]
    # last_seen advances to the newer run.
    assert b["last_seen"] > a["last_seen"]


def test_diff_detects_new_resolved_and_changed_severity(tmp_path):
    store = _store(tmp_path)
    # Run A baseline.
    run_a = store.save_run(
        "e",
        "t",
        [
            Finding("m", "t", "stays", Severity.LOW),
            Finding("m", "t", "goes away", Severity.MEDIUM),
            Finding("m", "t", "escalates", Severity.LOW),
        ],
    )
    # Run B: "goes away" resolved, "appears" new, "escalates" severity up.
    run_b = store.save_run(
        "e",
        "t",
        [
            Finding("m", "t", "stays", Severity.LOW),
            Finding("m", "t", "appears", Severity.HIGH),
            Finding("m", "t", "escalates", Severity.CRITICAL),
        ],
    )

    diff = store.diff_runs(run_a, run_b)

    new_titles = {f["title"] for f in diff["new"]}
    resolved_titles = {f["title"] for f in diff["resolved"]}
    # "appears" is genuinely new; "goes away" is genuinely resolved.
    assert "appears" in new_titles
    assert "goes away" in resolved_titles
    assert "stays" not in new_titles and "stays" not in resolved_titles
    # "escalates" only changed severity: it must NOT be double-counted as both
    # new and resolved — it belongs solely to changed_severity.
    assert "escalates" not in new_titles
    assert "escalates" not in resolved_titles

    changed = diff["changed_severity"]
    assert len(changed) == 1
    assert changed[0]["title"] == "escalates"
    assert changed[0]["from"] == "LOW"
    assert changed[0]["to"] == "CRITICAL"


def test_diff_latest_uses_two_most_recent_runs(tmp_path):
    store = _store(tmp_path)
    store.save_run("e", "t", [Finding("m", "t", "old", Severity.LOW)])
    run_a = store.save_run("e", "t", [Finding("m", "t", "base", Severity.LOW)])
    run_b = store.save_run("e", "t", [Finding("m", "t", "fresh", Severity.LOW)])

    result = store.diff_latest("t")
    assert result["run_a"] == run_a
    assert result["run_b"] == run_b
    assert {f["title"] for f in result["new"]} == {"fresh"}
    assert {f["title"] for f in result["resolved"]} == {"base"}


def test_diff_latest_with_insufficient_runs(tmp_path):
    store = _store(tmp_path)
    # No runs.
    empty = store.diff_latest("none")
    assert empty["run_a"] is None and empty["run_b"] is None
    assert empty["new"] == [] and empty["resolved"] == []

    # Single run: run_b set, run_a None, empty diff.
    store.save_run("e", "t", [Finding("m", "t", "x", Severity.LOW)])
    one = store.diff_latest("t")
    assert one["run_b"] is not None and one["run_a"] is None
    assert one["new"] == []


def test_metadata_roundtrip(tmp_path):
    store = _store(tmp_path)
    f = Finding("m", "t", "meta", Severity.INFO, metadata={"port": 443, "tags": ["a"]})
    run_id = store.save_run("e", "t", [f])
    stored = store.get_findings(run_id)[0]
    assert stored["metadata"] == {"port": 443, "tags": ["a"]}
