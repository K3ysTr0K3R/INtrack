"""
db.py — SQLite persistence for the INtrack dashboard.

Three tables:
  scans    — every scan run through the dashboard (history, for Past Results)
  targets  — saved host/subnet/file target lists (for the Targets tab)
  settings — key/value defaults (threads, timeout, proxychains, bar_style)

One file, no server, no setup — matches the same pattern used in
mk-password-bank. Safe for a local single-user tool; a `threading.Lock`
guards writes since Flask's dev server can handle requests on multiple
threads at once and SQLite doesn't love concurrent writers.
"""

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "intrack_dashboard.db")
_LOCK = threading.Lock()

DEFAULT_SETTINGS = {
    "threads": "50",
    "timeout": "10",
    "bar_style": "smooth",
    "proxychains": "0",
    "port": "80,443",
    "scan_type": "instance",
    "hostname": "0",
}


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with _LOCK, _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                command TEXT NOT NULL,
                config TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'running',
                started_at TEXT NOT NULL,
                finished_at TEXT,
                returncode INTEGER,
                found_count INTEGER NOT NULL DEFAULT 0,
                output_file TEXT,
                output TEXT NOT NULL DEFAULT ''
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,       -- 'host' (subnet/IP) or 'file' (path to a target list)
                value TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        for key, value in DEFAULT_SETTINGS.items():
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value)
            )
        conn.commit()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------- scans

def create_scan(scan_id: str, command: str, config: dict, output_file: str | None):
    with _LOCK, _connect() as conn:
        conn.execute(
            "INSERT INTO scans (id, command, config, status, started_at, output_file) "
            "VALUES (?, ?, ?, 'running', ?, ?)",
            (scan_id, command, json.dumps(config), now_iso(), output_file),
        )
        conn.commit()


def finish_scan(scan_id: str, status: str, returncode: int, found_count: int, output: str):
    with _LOCK, _connect() as conn:
        conn.execute(
            "UPDATE scans SET status=?, returncode=?, found_count=?, output=?, finished_at=? "
            "WHERE id=?",
            (status, returncode, found_count, output, now_iso(), scan_id),
        )
        conn.commit()


def mark_scan_stopped(scan_id: str):
    with _LOCK, _connect() as conn:
        conn.execute(
            "UPDATE scans SET status='stopped', finished_at=? WHERE id=? AND status='running'",
            (now_iso(), scan_id),
        )
        conn.commit()


def list_scans(limit: int = 100):
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, command, status, started_at, finished_at, returncode, found_count, output_file "
            "FROM scans ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_scan(scan_id: str):
    with _connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None


def delete_scan(scan_id: str):
    with _LOCK, _connect() as conn:
        conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        conn.commit()


def list_exports():
    """Scans that had an output_file set — these are what the Exports tab shows."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, command, output_file, status, started_at, finished_at, found_count "
            "FROM scans WHERE output_file IS NOT NULL AND output_file != '' "
            "ORDER BY started_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


# ------------------------------------------------------------------- targets

def create_target(name: str, kind: str, value: str):
    target_id = str(uuid.uuid4())
    with _LOCK, _connect() as conn:
        conn.execute(
            "INSERT INTO targets (id, name, kind, value, created_at) VALUES (?, ?, ?, ?, ?)",
            (target_id, name, kind, value, now_iso()),
        )
        conn.commit()
    return target_id


def list_targets():
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM targets ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]


def delete_target(target_id: str):
    with _LOCK, _connect() as conn:
        conn.execute("DELETE FROM targets WHERE id=?", (target_id,))
        conn.commit()


# ------------------------------------------------------------------ settings

def get_settings():
    with _connect() as conn:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
        return {r["key"]: r["value"] for r in rows}


def update_settings(values: dict):
    with _LOCK, _connect() as conn:
        for key, value in values.items():
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, str(value)),
            )
        conn.commit()
