"""
SQLite data access layer.

Tables:
  runs             - assessment run metadata + ASR/UR stats
  attacks          - per-attack results with full transcripts
  workflow_events  - SSE events + workflow pipeline state
"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional


def _db_path() -> str:
    return os.getenv("SENTINEL_DB_PATH", "./sentinel.db")


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    path = _db_path()
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Create tables if they don't exist."""
    with _conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY,
                mode TEXT NOT NULL,
                suite_type TEXT NOT NULL DEFAULT 'suite',
                started_at TEXT NOT NULL,
                completed_at TEXT,
                status TEXT NOT NULL DEFAULT 'running',
                total_attacks INTEGER DEFAULT 0,
                succeeded_count INTEGER DEFAULT 0,
                partial_count INTEGER DEFAULT 0,
                blocked_count INTEGER DEFAULT 0,
                asr REAL DEFAULT 0.0,
                ur REAL DEFAULT 0.0,
                defense_config_json TEXT DEFAULT '{}',
                notes TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                attack_id TEXT NOT NULL,
                category TEXT NOT NULL,
                result TEXT NOT NULL,
                severity TEXT NOT NULL,
                reason TEXT,
                transcript_json TEXT DEFAULT '{}',
                tool_calls_json TEXT DEFAULT '[]',
                node_trace_json TEXT DEFAULT '[]',
                elapsed_ms INTEGER DEFAULT 0,
                escalation_path_json TEXT DEFAULT '[]',
                FOREIGN KEY (run_id) REFERENCES runs(id)
            );

            CREATE TABLE IF NOT EXISTS workflow_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                type TEXT NOT NULL,
                payload_json TEXT DEFAULT '{}',
                delivered_at TEXT,
                FOREIGN KEY (run_id) REFERENCES runs(id)
            );

            CREATE TABLE IF NOT EXISTS workflow_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL UNIQUE,
                gate_status TEXT NOT NULL,
                gate_reasons_json TEXT DEFAULT '[]',
                slack_payload_json TEXT,
                jira_payload_json TEXT,
                regression_json TEXT DEFAULT '{}',
                created_at TEXT
            );
        """)


# ── Run CRUD ──────────────────────────────────────────────────────────────────

def create_run(run_id: str, mode: str, suite_type: str, defense_config: Dict) -> None:
    with _conn() as conn:
        conn.execute(
            """INSERT INTO runs (id, mode, suite_type, started_at, status, defense_config_json)
               VALUES (?, ?, ?, ?, 'running', ?)""",
            (run_id, mode, suite_type, datetime.now(timezone.utc).isoformat(),
             json.dumps(defense_config)),
        )


def update_run_stats(
    run_id: str,
    total: int, succeeded: int, partial: int, blocked: int,
    asr: float, ur: float,
) -> None:
    with _conn() as conn:
        conn.execute(
            """UPDATE runs SET
               total_attacks=?, succeeded_count=?, partial_count=?, blocked_count=?,
               asr=?, ur=?, completed_at=?, status='completed'
               WHERE id=?""",
            (total, succeeded, partial, blocked, asr, ur,
             datetime.now(timezone.utc).isoformat(), run_id),
        )


def get_run(run_id: str) -> Optional[Dict]:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    return dict(row) if row else None


def list_runs(limit: int = 50) -> List[Dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_last_completed_run(mode: str) -> Optional[Dict]:
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM runs WHERE mode=? AND status='completed' ORDER BY completed_at DESC LIMIT 1",
            (mode,)
        ).fetchone()
    return dict(row) if row else None


# ── Attack result CRUD ────────────────────────────────────────────────────────

def save_attack_result(
    run_id: str,
    attack_id: str,
    category: str,
    result: str,
    severity: str,
    reason: str,
    transcript: Dict,
    tool_calls: List,
    node_trace: List,
    elapsed_ms: int,
    escalation_path: Optional[List] = None,
) -> int:
    with _conn() as conn:
        cursor = conn.execute(
            """INSERT INTO attacks
               (run_id, attack_id, category, result, severity, reason,
                transcript_json, tool_calls_json, node_trace_json, elapsed_ms, escalation_path_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id, attack_id, category, result, severity, reason,
                json.dumps(transcript), json.dumps(tool_calls), json.dumps(node_trace),
                elapsed_ms, json.dumps(escalation_path or []),
            ),
        )
        return cursor.lastrowid


def get_run_attacks(run_id: str) -> List[Dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM attacks WHERE run_id=? ORDER BY id", (run_id,)
        ).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        for field in ("transcript_json", "tool_calls_json", "node_trace_json", "escalation_path_json"):
            try:
                d[field] = json.loads(d[field] or "null")
            except Exception:
                d[field] = None
        results.append(d)
    return results


def get_attack_detail(attack_db_id: int) -> Optional[Dict]:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM attacks WHERE id=?", (attack_db_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    for field in ("transcript_json", "tool_calls_json", "node_trace_json", "escalation_path_json"):
        try:
            d[field] = json.loads(d[field] or "null")
        except Exception:
            d[field] = None
    return d


# ── Workflow events ────────────────────────────────────────────────────────────

def save_workflow_event(run_id: str, event_type: str, payload: Dict) -> None:
    with _conn() as conn:
        conn.execute(
            "INSERT INTO workflow_events (run_id, type, payload_json, delivered_at) VALUES (?, ?, ?, ?)",
            (run_id, event_type, json.dumps(payload), datetime.now(timezone.utc).isoformat()),
        )


def get_workflow_events(run_id: str) -> List[Dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM workflow_events WHERE run_id=? ORDER BY id", (run_id,)
        ).fetchall()
    return [{**dict(r), "payload": json.loads(r["payload_json"] or "{}")} for r in rows]


def save_workflow_result(
    run_id: str,
    gate_status: str,
    gate_reasons: List[str],
    slack_payload: Optional[Dict],
    jira_payload: Optional[Dict],
    regression: Dict,
) -> None:
    with _conn() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO workflow_results
               (run_id, gate_status, gate_reasons_json, slack_payload_json, jira_payload_json, regression_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id, gate_status,
                json.dumps(gate_reasons),
                json.dumps(slack_payload) if slack_payload else None,
                json.dumps(jira_payload) if jira_payload else None,
                json.dumps(regression),
                datetime.now(timezone.utc).isoformat(),
            ),
        )


def get_workflow_result(run_id: str) -> Optional[Dict]:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM workflow_results WHERE run_id=?", (run_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    for field in ("gate_reasons_json", "slack_payload_json", "jira_payload_json", "regression_json"):
        try:
            d[field.replace("_json", "")] = json.loads(d[field] or "null")
        except Exception:
            d[field.replace("_json", "")] = None
    return d


def get_latest_workflow_result() -> Optional[Dict]:
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM workflow_results ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    for field in ("gate_reasons_json", "slack_payload_json", "jira_payload_json", "regression_json"):
        try:
            d[field.replace("_json", "")] = json.loads(d[field] or "null")
        except Exception:
            d[field.replace("_json", "")] = None
    return d
