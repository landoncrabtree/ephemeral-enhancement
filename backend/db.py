"""
SQLite storage for the Ephemeral Enhancement run tracker.

A "run" is one execution of a pipeline against a ciphertext. Runs are keyed by
a *fingerprint* that encodes the entire searched parameter space, not just the
pipeline string — see `core/tracker.py:compute_fingerprint` on the client.

That distinction matters: when a stage's axis definition changes (for example
`beaufort>b64` grew from 24 to 120 combinations when extra alphabets were
added), the fingerprint changes too, so the older run no longer suppresses the
larger search. Keying on the pipeline string alone would silently hide the
newly reachable combinations.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

DB_PATH = Path(os.getenv("EE_DB_PATH", Path(__file__).parent / "runs.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    fingerprint       TEXT PRIMARY KEY,
    pipeline          TEXT NOT NULL,
    ciphertext        TEXT NOT NULL,
    ciphertext_sha    TEXT NOT NULL,
    ciphertext_label  TEXT,
    dictionary        TEXT,
    dictionary_sha    TEXT,
    n_keys            INTEGER,
    axes_json         TEXT,
    combos            INTEGER,
    hits              INTEGER,
    best_score        REAL,
    best_plaintext    TEXT,
    best_meta_json    TEXT,
    threshold         REAL,
    vary_case         INTEGER,
    status            TEXT NOT NULL DEFAULT 'complete',
    semantics_version INTEGER,
    git_commit        TEXT,
    runner            TEXT,
    duration_s        REAL,
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_runs_ct     ON runs(ciphertext_sha);
CREATE INDEX IF NOT EXISTS idx_runs_time   ON runs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_runs_hits   ON runs(hits DESC);
CREATE INDEX IF NOT EXISTS idx_runs_runner ON runs(runner);
"""


def connect() -> sqlite3.Connection:
    """Open a connection with row access by column name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Concurrent readers while a writer is active.
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    """Create tables if they do not exist."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        conn.executescript(SCHEMA)


def upsert_run(data: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    """
    Insert a run, or replace an existing one only when the new run is better.

    "Better" means it completed when the stored one did not, or it found more
    hits. This keeps an aborted or timed-out sweep from masking a later
    complete run of the same search space.

    Returns (created, stored_row).
    """
    existing = get_run(data["fingerprint"])
    if existing is not None:
        was_partial = existing["status"] != "complete"
        now_complete = data.get("status") == "complete"
        more_hits = (data.get("hits") or 0) > (existing["hits"] or 0)
        if not (was_partial and now_complete) and not more_hits:
            return False, existing

    cols = [
        "fingerprint", "pipeline", "ciphertext", "ciphertext_sha",
        "ciphertext_label", "dictionary", "dictionary_sha", "n_keys",
        "axes_json", "combos", "hits", "best_score", "best_plaintext",
        "best_meta_json", "threshold", "vary_case", "status",
        "semantics_version", "git_commit", "runner", "duration_s",
    ]
    values = [data.get(c) for c in cols]
    placeholders = ", ".join("?" for _ in cols)
    with connect() as conn:
        conn.execute(
            f"INSERT OR REPLACE INTO runs ({', '.join(cols)}) "
            f"VALUES ({placeholders})",
            values,
        )
    return True, get_run(data["fingerprint"])  # type: ignore[return-value]


def get_run(fingerprint: str) -> dict[str, Any] | None:
    """Look up a single run by fingerprint."""
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM runs WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
    return dict(row) if row else None


def list_runs(
    limit: int = 200,
    offset: int = 0,
    ciphertext_sha: str | None = None,
    only_hits: bool = False,
    search: str | None = None,
) -> list[dict[str, Any]]:
    """List runs, newest first, with optional filters."""
    clauses: list[str] = []
    params: list[Any] = []
    if ciphertext_sha:
        clauses.append("ciphertext_sha = ?")
        params.append(ciphertext_sha)
    if only_hits:
        clauses.append("hits > 0")
    if search:
        clauses.append("(pipeline LIKE ? OR ciphertext_label LIKE ? OR runner LIKE ?)")
        params += [f"%{search}%"] * 3
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params += [limit, offset]
    with connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM runs {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
    return [dict(r) for r in rows]


def stats() -> dict[str, Any]:
    """Aggregate counters for the dashboard header."""
    with connect() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*)                AS runs,
                   COALESCE(SUM(combos),0) AS combos,
                   COALESCE(SUM(hits),0)   AS hits,
                   COUNT(DISTINCT runner)  AS runners,
                   COUNT(DISTINCT ciphertext_sha) AS ciphertexts,
                   COALESCE(SUM(duration_s),0)    AS seconds
            FROM runs
            """
        ).fetchone()
    return dict(row)


def ciphertext_summary() -> list[dict[str, Any]]:
    """Per-ciphertext coverage, for the dashboard's target list."""
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT ciphertext_sha,
                   MAX(ciphertext_label)   AS label,
                   COUNT(*)                AS runs,
                   COALESCE(SUM(combos),0) AS combos,
                   COALESCE(SUM(hits),0)   AS hits,
                   MAX(best_score)         AS best_score
            FROM runs
            GROUP BY ciphertext_sha
            ORDER BY runs DESC
            """
        ).fetchall()
    return [dict(r) for r in rows]


def decode_axes(axes_json: str | None) -> list[tuple[str, int]]:
    """Parse the stored axes JSON back into (name, size) pairs."""
    if not axes_json:
        return []
    try:
        return [(a[0], a[1]) for a in json.loads(axes_json)]
    except (ValueError, TypeError, IndexError):
        return []
