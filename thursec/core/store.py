"""Persistence — give ThurSec a memory.

Each ``run`` produces findings and, today, an ephemeral report. This module
adds a *historical store* (SQLite, stdlib-only) that records runs over time,
deduplicates by :attr:`Finding.fingerprint`, tracks ``first_seen``/``last_seen``
per fingerprint, and lets us **diff two scans** (what appeared, disappeared or
changed severity). It is the data layer the future dashboard (PLAT2) reads.

The store is strictly opt-in: nothing here runs unless a ``--store`` path is
given, so the existing ephemeral flow is untouched.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from .finding import Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement  TEXT NOT NULL,
    target      TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    fingerprint    TEXT NOT NULL,
    module         TEXT NOT NULL,
    target         TEXT NOT NULL,
    title          TEXT NOT NULL,
    severity       TEXT NOT NULL,
    severity_level INTEGER NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    recommendation TEXT NOT NULL DEFAULT '',
    evidence       TEXT NOT NULL DEFAULT '',
    metadata_json  TEXT NOT NULL DEFAULT '{}',
    discovered_at  TEXT NOT NULL,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    UNIQUE (run_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_runs_target ON runs(target);
"""


class StoreError(Exception):
    """Raised for store-level failures, with a message safe to surface.

    We never let a raw sqlite3 error (which may embed a filesystem path or
    other host detail) propagate out of the store.
    """


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class FindingStore:
    """A historical store of runs and findings, backed by a SQLite file.

    Usage::

        store = FindingStore("thursec.db")
        run_id = store.save_run("ad-hoc", "example.com", findings)
        diff = store.diff_latest("example.com")

    The connection is opened per operation and always closed (context
    manager), so the store holds no long-lived handles.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        try:
            with self._connect() as conn:
                conn.executescript(_SCHEMA)
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            raise StoreError(f"could not initialize store: {type(exc).__name__}") from exc

    # --- connection ------------------------------------------------------
    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            yield conn
            conn.commit()
        except sqlite3.Error:
            conn.rollback()
            raise
        finally:
            conn.close()

    # --- writes ----------------------------------------------------------
    def save_run(
        self,
        engagement: str,
        target: str,
        findings: Iterable[Finding],
    ) -> int:
        """Persist a run and its findings; return the new ``run_id``.

        Findings are deduplicated by fingerprint within the run (last one
        wins). ``first_seen`` is the earliest time this fingerprint was seen
        for the same engagement+target across any prior run; ``last_seen`` is
        this run's timestamp.
        """
        findings = list(findings)
        started_at = _utcnow_iso()
        # Dedup within this run by fingerprint (idempotent per run).
        unique: dict[str, Finding] = {}
        for f in findings:
            unique[f.fingerprint] = f

        try:
            with self._connect() as conn:
                finished_at = _utcnow_iso()
                cur = conn.execute(
                    "INSERT INTO runs (engagement, target, started_at, finished_at) "
                    "VALUES (?, ?, ?, ?)",
                    (engagement, target, started_at, finished_at),
                )
                run_id = int(cur.lastrowid)

                for f in unique.values():
                    d = f.to_dict()
                    prior = conn.execute(
                        "SELECT MIN(fn.first_seen) AS fs "
                        "FROM findings fn JOIN runs r ON fn.run_id = r.id "
                        "WHERE fn.fingerprint = ? AND r.engagement = ? AND r.target = ?",
                        (f.fingerprint, engagement, target),
                    ).fetchone()
                    first_seen = (prior["fs"] if prior else None) or finished_at

                    conn.execute(
                        "INSERT INTO findings ("
                        " run_id, fingerprint, module, target, title, severity,"
                        " severity_level, description, recommendation, evidence,"
                        " metadata_json, discovered_at, first_seen, last_seen"
                        ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                        "ON CONFLICT(run_id, fingerprint) DO UPDATE SET "
                        " module=excluded.module, target=excluded.target,"
                        " title=excluded.title, severity=excluded.severity,"
                        " severity_level=excluded.severity_level,"
                        " description=excluded.description,"
                        " recommendation=excluded.recommendation,"
                        " evidence=excluded.evidence,"
                        " metadata_json=excluded.metadata_json,"
                        " discovered_at=excluded.discovered_at,"
                        " last_seen=excluded.last_seen",
                        (
                            run_id,
                            d["fingerprint"],
                            d["module"],
                            d["target"],
                            d["title"],
                            d["severity"],
                            d["severity_level"],
                            d["description"],
                            d["recommendation"],
                            d["evidence"],
                            json.dumps(d["metadata"]),
                            d["discovered_at"],
                            first_seen,
                            finished_at,
                        ),
                    )
                return run_id
        except sqlite3.Error as exc:
            raise StoreError(f"could not save run: {type(exc).__name__}") from exc

    # --- reads -----------------------------------------------------------
    def list_runs(
        self,
        target: str | None = None,
        engagement: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return runs (most recent first), optionally filtered.

        Each row includes a ``finding_count`` for convenience.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if target is not None:
            clauses.append("r.target = ?")
            params.append(target)
        if engagement is not None:
            clauses.append("r.engagement = ?")
            params.append(engagement)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT r.id, r.engagement, r.target, r.started_at, r.finished_at, "
                    "       COUNT(f.id) AS finding_count "
                    "FROM runs r LEFT JOIN findings f ON f.run_id = r.id "
                    f"{where} "
                    "GROUP BY r.id "
                    "ORDER BY r.id DESC",
                    params,
                ).fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            raise StoreError(f"could not list runs: {type(exc).__name__}") from exc

    def get_findings(self, run_id: int) -> list[dict[str, Any]]:
        """Return the findings recorded for a given run."""
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM findings WHERE run_id = ? "
                    "ORDER BY severity_level DESC, module, title",
                    (run_id,),
                ).fetchall()
                return [self._row_to_finding(row) for row in rows]
        except sqlite3.Error as exc:
            raise StoreError(f"could not read findings: {type(exc).__name__}") from exc

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        try:
            d["metadata"] = json.loads(d.pop("metadata_json", "{}") or "{}")
        except (ValueError, TypeError):
            d["metadata"] = {}
        return d

    # --- diff ------------------------------------------------------------
    def diff_runs(self, run_a_id: int, run_b_id: int) -> dict[str, list[dict[str, Any]]]:
        """Compare run A (older/baseline) with run B (newer).

        Returns ``{"new", "resolved", "changed_severity"}``:

        - ``changed_severity``: same ``module+target+title`` present in both
          runs but with a different severity.
        - ``new``: fingerprints present in B but not in A, *excluding* those
          whose identity only changed severity (reported in ``changed_severity``).
        - ``resolved``: fingerprints present in A but not in B, with the same
          exclusion applied.

        Because the fingerprint embeds the severity, a finding that merely
        escalates/de-escalates gets a *different* fingerprint in each run. Left
        unchecked it would surface in all three buckets at once; we classify it
        as a severity change only, and keep it out of ``new``/``resolved``.
        """
        a = {f["fingerprint"]: f for f in self.get_findings(run_a_id)}
        b = {f["fingerprint"]: f for f in self.get_findings(run_b_id)}

        # Changed severity: match on the identity minus severity.
        def identity(f: dict[str, Any]) -> tuple[str, str, str]:
            return (f["module"], f["target"], f["title"])

        a_by_identity = {identity(f): f for f in a.values()}
        changed_severity: list[dict[str, Any]] = []
        changed_identities: set[tuple[str, str, str]] = set()
        for f in b.values():
            prev = a_by_identity.get(identity(f))
            if prev is not None and prev["severity_level"] != f["severity_level"]:
                changed_identities.add(identity(f))
                changed_severity.append(
                    {
                        "module": f["module"],
                        "target": f["target"],
                        "title": f["title"],
                        "from": prev["severity"],
                        "from_level": prev["severity_level"],
                        "to": f["severity"],
                        "to_level": f["severity_level"],
                    }
                )

        # A severity change is reported once (in changed_severity); keep both
        # its old and new fingerprints out of new/resolved.
        new = [
            b[fp]
            for fp in b
            if fp not in a and identity(b[fp]) not in changed_identities
        ]
        resolved = [
            a[fp]
            for fp in a
            if fp not in b and identity(a[fp]) not in changed_identities
        ]

        return {"new": new, "resolved": resolved, "changed_severity": changed_severity}

    def diff_latest(self, target: str) -> dict[str, Any]:
        """Diff the two most recent runs for ``target`` (previous vs latest).

        Returns the diff dict plus ``run_a``/``run_b`` ids for context. If
        fewer than two runs exist, the diff sets are empty and the missing
        run id is ``None``.
        """
        runs = self.list_runs(target=target)
        run_b = runs[0]["id"] if len(runs) >= 1 else None
        run_a = runs[1]["id"] if len(runs) >= 2 else None
        if run_a is None or run_b is None:
            empty: dict[str, list[dict[str, Any]]] = {
                "new": [],
                "resolved": [],
                "changed_severity": [],
            }
            return {"run_a": run_a, "run_b": run_b, **empty}
        diff = self.diff_runs(run_a, run_b)
        return {"run_a": run_a, "run_b": run_b, **diff}
