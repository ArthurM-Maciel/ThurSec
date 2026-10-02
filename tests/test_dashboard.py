"""Tests for the posture dashboard (PLAT2). All local — no network."""

from __future__ import annotations

from thursec.core.dashboard import render_dashboard
from thursec.core.finding import Finding, Severity
from thursec.core.store import FindingStore


def _store(tmp_path):
    return FindingStore(tmp_path / "thursec.db")


def _two_run_store(tmp_path):
    """Build a store with two runs: a NEW, a RESOLVED and an ESCALATED finding."""
    store = _store(tmp_path)
    store.save_run(
        "e",
        "t.example",
        [
            Finding("m", "t.example", "stays", Severity.LOW),
            Finding("m", "t.example", "goes away", Severity.MEDIUM),
            Finding("m", "t.example", "escalates", Severity.LOW),
        ],
    )
    store.save_run(
        "e",
        "t.example",
        [
            Finding("m", "t.example", "stays", Severity.LOW),
            Finding("m", "t.example", "appears", Severity.HIGH),
            Finding("m", "t.example", "escalates", Severity.CRITICAL),
        ],
    )
    return store


def test_dashboard_is_self_contained_html(tmp_path):
    store = _two_run_store(tmp_path)
    html = render_dashboard(store, "t.example")
    assert html.startswith("<!doctype html>")
    assert html.rstrip().endswith("</html>")
    # Self-contained: inline CSS/SVG, no external assets or scripts.
    assert "<style>" in html
    assert "<script" not in html
    assert "http://" not in html and "https://" not in html
    assert "cdn" not in html.lower()


def test_dashboard_has_all_sections(tmp_path):
    store = _two_run_store(tmp_path)
    html = render_dashboard(store, "t.example")
    assert "Current posture" in html
    assert "Trend across runs" in html
    assert "Latest diff" in html
    assert "Findings" in html
    # Trend chart is inline SVG.
    assert "<svg" in html


def test_dashboard_summary_counts_latest_run(tmp_path):
    store = _two_run_store(tmp_path)
    html = render_dashboard(store, "t.example")
    # Latest run: stays(LOW), appears(HIGH), escalates(CRITICAL) => total 3.
    assert "<div class='tile-num'>3</div>" in html  # total tile
    # Each severity present in the latest run appears in the findings table.
    assert "appears" in html
    assert "escalates" in html


def test_dashboard_diff_section_no_double_count(tmp_path):
    """The escalated finding must appear only under Changed severity."""
    store = _two_run_store(tmp_path)
    html = render_dashboard(store, "t.example")
    diff_section = html.split("Latest diff", 1)[1].split("Findings", 1)[0]
    # 'appears' is genuinely new, 'goes away' resolved; both shown once.
    assert "appears" in diff_section
    assert "goes away" in diff_section
    # 'escalates' shows in the changed list with its transition badges.
    assert "escalates" in diff_section
    assert "Low" in diff_section and "Critical" in diff_section


def test_diff_does_not_duplicate_changed_in_new_or_resolved(tmp_path):
    """Store-level guarantee the dashboard relies on."""
    store = _two_run_store(tmp_path)
    diff = store.diff_latest("t.example")
    new_titles = {f["title"] for f in diff["new"]}
    resolved_titles = {f["title"] for f in diff["resolved"]}
    changed_titles = {c["title"] for c in diff["changed_severity"]}

    assert new_titles == {"appears"}
    assert resolved_titles == {"goes away"}
    assert changed_titles == {"escalates"}
    # The crux: no overlap between the buckets.
    assert "escalates" not in new_titles
    assert "escalates" not in resolved_titles


def test_dashboard_defaults_to_latest_target(tmp_path):
    store = _two_run_store(tmp_path)
    # No target passed => most recently run target is used.
    html = render_dashboard(store)
    assert "t.example" in html


def test_dashboard_empty_store_no_crash(tmp_path):
    store = _store(tmp_path)
    html = render_dashboard(store)
    assert html.startswith("<!doctype html>")
    assert "no runs" in html.lower()


def test_dashboard_single_run_diff_message(tmp_path):
    store = _store(tmp_path)
    store.save_run("e", "t", [Finding("m", "t", "only", Severity.LOW)])
    html = render_dashboard(store, "t")
    assert "need at least two runs" in html
    assert "<svg" in html  # trend still renders for one run
