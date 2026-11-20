"""Tiny SQLite persistence layer for scan history."""
from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any

from . import config

_lock = threading.Lock()


def _conn() -> sqlite3.Connection:
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init() -> None:
    with _lock, _conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                host TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                finished_at TEXT,
                score INTEGER,
                grade TEXT,
                counts TEXT,
                payload TEXT NOT NULL
            )""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC)")


def save(scan: dict[str, Any]) -> None:
    with _lock, _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?,?,?,?,?)",
            (scan["id"], scan["target"], scan.get("host"), scan["status"], scan["created_at"],
             scan.get("finished_at"), scan.get("score"), scan.get("grade"),
             json.dumps(scan.get("counts")), json.dumps(scan, default=str)))


def load(scan_id: str) -> dict[str, Any] | None:
    with _lock, _conn() as c:
        row = c.execute("SELECT payload FROM scans WHERE id=?", (scan_id,)).fetchone()
    return json.loads(row["payload"]) if row else None


def list_scans(limit: int = 50) -> list[dict[str, Any]]:
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT id,target,host,status,created_at,finished_at,score,grade,counts "
            "FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [{**dict(r), "counts": json.loads(r["counts"]) if r["counts"] else None} for r in rows]


def delete(scan_id: str) -> bool:
    with _lock, _conn() as c:
        return c.execute("DELETE FROM scans WHERE id=?", (scan_id,)).rowcount > 0


def stats() -> dict[str, Any]:
    with _lock, _conn() as c:
        rows = c.execute("SELECT score, counts, status FROM scans").fetchall()
    done = [r for r in rows if r["status"] == "completed"]
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in done:
        for k, v in (json.loads(r["counts"]) or {}).items():
            totals[k] = totals.get(k, 0) + v
    return {
        "total_scans": len(rows),
        "completed": len(done),
        "avg_score": round(sum(r["score"] for r in done) / len(done)) if done else None,
        "issues": totals,
    }
