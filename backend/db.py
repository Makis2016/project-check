from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

APP_NAME = "VulnLens"


def data_dir() -> Path:
    override = os.environ.get("VULNLENS_DATA_DIR")
    if override:
        path = Path(override).expanduser()
    elif sys.platform.startswith("win"):
        path = Path(os.environ.get("APPDATA", Path.home())) / APP_NAME
    elif sys.platform == "darwin":
        path = Path.home() / "Library" / "Application Support" / APP_NAME
    else:
        path = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


DB_PATH = data_dir() / "vulnlens.db"


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                preset TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                finished_at REAL,
                config_json TEXT NOT NULL,
                summary_json TEXT,
                assets_json TEXT,
                discovery_json TEXT,
                error TEXT
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                data_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
            """
        )


def create_scan(scan_id: str, config: dict[str, Any]) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO scans (id, target, preset, status, created_at, config_json) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, config["target"], config["preset"], "queued", time.time(), json.dumps(config, ensure_ascii=False)),
        )


def set_status(scan_id: str, status: str, error: str | None = None) -> None:
    with connect() as conn:
        if status in ("completed", "failed", "stopped"):
            conn.execute(
                "UPDATE scans SET status=?, error=?, finished_at=? WHERE id=?",
                (status, error, time.time(), scan_id),
            )
        else:
            conn.execute("UPDATE scans SET status=?, error=? WHERE id=?", (status, error, scan_id))


def save_results(
    scan_id: str,
    summary: dict[str, Any],
    assets: dict[str, Any],
    discovery: dict[str, Any],
    findings: list[dict[str, Any]],
) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE scans SET summary_json=?, assets_json=?, discovery_json=? WHERE id=?",
            (
                json.dumps(summary, ensure_ascii=False),
                json.dumps(assets, ensure_ascii=False),
                json.dumps(discovery, ensure_ascii=False),
                scan_id,
            ),
        )
        conn.executemany(
            "INSERT INTO findings (scan_id, data_json) VALUES (?, ?)",
            [(scan_id, json.dumps(f, ensure_ascii=False)) for f in findings],
        )


def add_findings(scan_id: str, findings: list[dict[str, Any]]) -> None:
    if not findings:
        return
    with connect() as conn:
        conn.executemany(
            "INSERT INTO findings (scan_id, data_json) VALUES (?, ?)",
            [(scan_id, json.dumps(f, ensure_ascii=False)) for f in findings],
        )


def _row_to_scan(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "target": row["target"],
        "preset": row["preset"],
        "status": row["status"],
        "created_at": row["created_at"],
        "finished_at": row["finished_at"],
        "error": row["error"],
        "config": json.loads(row["config_json"]),
        "summary": json.loads(row["summary_json"]) if row["summary_json"] else None,
        "assets": json.loads(row["assets_json"]) if row["assets_json"] else None,
    }


def get_scan(scan_id: str, include_findings: bool = True) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if row is None:
            return None
        scan = _row_to_scan(row)
        if include_findings:
            scan["discovery"] = json.loads(row["discovery_json"]) if row["discovery_json"] else None
            scan["findings"] = [
                json.loads(r["data_json"])
                for r in conn.execute("SELECT data_json FROM findings WHERE scan_id=? ORDER BY id", (scan_id,))
            ]
        return scan


def list_scans(limit: int = 100) -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [_row_to_scan(r) for r in rows]


def delete_scan(scan_id: str) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
