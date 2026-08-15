"""Local SQLite store for scan history (v1b milestone).

Persists each scan (plus its rendered report) so the user can re-render the
last report with `offboard report --last` without re-scanning the tenant,
and later compare findings across runs.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import UTC, datetime
from typing import Any

from .scan import ScanResult

_STATE_DIR = os.path.join(os.path.expanduser("~"), ".ai-offboard")
DB_PATH = os.path.join(_STATE_DIR, "scans.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    principal_count INTEGER NOT NULL,
    app_count INTEGER NOT NULL,
    grant_count INTEGER NOT NULL,
    finding_count INTEGER NOT NULL,
    findings_json TEXT NOT NULL,
    report_md TEXT NOT NULL,
    report_html TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    added_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    schedule TEXT NOT NULL,
    last_run TEXT
);

CREATE TABLE IF NOT EXISTS executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    executed_at TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    detail TEXT
);
"""


def add_tenant(tenant_id: str, display_name: str = "") -> bool:
    """Register a tenant for multi-tenant audits. Returns True if added new."""
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT OR IGNORE INTO tenants (tenant_id, display_name, added_at) VALUES (?, ?, ?)",
            (tenant_id, display_name or tenant_id, datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def remove_tenant(tenant_id: str) -> bool:
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM tenants WHERE tenant_id = ?", (tenant_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def list_tenants() -> list[dict[str, str]]:
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT tenant_id, display_name, added_at FROM tenants ORDER BY display_name"
        ).fetchall()
        return [
            {"tenant_id": r[0], "display_name": r[1], "added_at": r[2]}
            for r in rows
        ]
    finally:
        conn.close()


def add_schedule(tenant_id: str, schedule: str) -> int:
    """Register a recurring audit job. Returns the new job id."""
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO schedules (tenant_id, schedule) VALUES (?, ?)",
            (tenant_id, schedule),
        )
        conn.commit()
        return cur.lastrowid or 0
    finally:
        conn.close()


def list_schedules() -> list[dict[str, Any]]:
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT id, tenant_id, schedule, last_run FROM schedules ORDER BY tenant_id"
        ).fetchall()
        return [
            {"id": r[0], "tenant_id": r[1], "schedule": r[2], "last_run": r[3]}
            for r in rows
        ]
    finally:
        conn.close()


def remove_schedule(schedule_id: int) -> bool:
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def touch_schedule(schedule_id: int) -> None:
    conn = _connect()
    try:
        conn.execute(
            "UPDATE schedules SET last_run = ? WHERE id = ?",
            (datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), schedule_id),
        )
        conn.commit()
    finally:
        conn.close()


def log_execution(tenant_id: str, action: str, target: str, status: str, detail: str | None = None) -> int:
    """Append a mutation to the audit log (irreversible record)."""
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO executions (executed_at, tenant_id, action, target, status, detail) VALUES (?, ?, ?, ?, ?, ?)",
            (datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), tenant_id, action, target, status, detail),
        )
        conn.commit()
        return cur.lastrowid or 0
    finally:
        conn.close()


def list_executions(limit: int = 20) -> list[dict[str, str | None]]:
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT executed_at, tenant_id, action, target, status, detail FROM executions ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {"executed_at": r[0], "tenant_id": r[1], "action": r[2], "target": r[3], "status": r[4], "detail": r[5]}
            for r in rows
        ]
    finally:
        conn.close()


def _connect() -> sqlite3.Connection:
    os.makedirs(_STATE_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(_SCHEMA)
    return conn


def save_scan(result: ScanResult) -> int:
    """Persist a scan. Returns the new scan row id."""
    findings_payload = [
        {
            "rule_id": f.rule_id,
            "severity": f.severity,
            "subject": f.subject,
            "evidence": f.evidence,
            "remediation": list(f.remediation),
        }
        for f in result.findings
    ]
    scanned_at = result.snapshot.scanned_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = _connect()
    try:
        cur = conn.execute(
            """
            INSERT INTO scans
              (tenant_id, scanned_at, principal_count, app_count, grant_count,
               finding_count, findings_json, report_md, report_html)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.snapshot.tenant_id,
                scanned_at,
                len(result.snapshot.principals),
                len(result.snapshot.app_assignments),
                len(result.snapshot.permission_grants),
                len(result.findings),
                json.dumps(findings_payload),
                result.report_md,
                result.report_html,
            ),
        )
        conn.commit()
        return cur.lastrowid or 0
    finally:
        conn.close()


def load_last_scan(tenant_id: str | None = None) -> dict[str, Any] | None:
    """Most recent scan (optionally filtered by tenant). Returns None if none."""
    conn = _connect()
    try:
        if tenant_id:
            row = conn.execute(
                "SELECT * FROM scans WHERE tenant_id = ? ORDER BY id DESC LIMIT 1",
                (tenant_id,),
            ).fetchone()
        else:
            row = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        if row is None:
            return None
        cols = [d[0] for d in conn.execute("SELECT * FROM scans LIMIT 0").description]
        return dict(zip(cols, row))
    finally:
        conn.close()


def list_scans(limit: int = 10) -> list[dict[str, Any]]:
    """Recent scans, newest first."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT id, tenant_id, scanned_at, finding_count FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {"id": r[0], "tenant_id": r[1], "scanned_at": r[2], "finding_count": r[3]}
            for r in rows
        ]
    finally:
        conn.close()


def load_scan_by_id(scan_id: int) -> dict[str, Any] | None:
    """Load a specific scan by id (None if missing)."""
    conn = _connect()
    try:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        cols = [d[0] for d in conn.execute("SELECT * FROM scans LIMIT 0").description]
        return dict(zip(cols, row))
    finally:
        conn.close()


def load_last_two_scans(tenant_id: str | None = None) -> list[dict[str, Any]]:
    """Return the two most recent scans (newest first), for trend comparison."""
    conn = _connect()
    try:
        if tenant_id:
            rows = conn.execute(
                "SELECT * FROM scans WHERE tenant_id = ? ORDER BY id DESC LIMIT 2",
                (tenant_id,),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 2").fetchall()
        if not rows:
            return []
        cols = [d[0] for d in conn.execute("SELECT * FROM scans LIMIT 0").description]
        return [dict(zip(cols, r)) for r in rows]
    finally:
        conn.close()


def findings_for_row(row: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse the stored findings JSON back into dicts for report rendering."""
    return json.loads(row.get("findings_json") or "[]")