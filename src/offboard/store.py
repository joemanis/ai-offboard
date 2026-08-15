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
"""


def _connect() -> sqlite3.Connection:
    os.makedirs(_STATE_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(_SCHEMA)
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
        return int(cur.lastrowid)
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


def findings_for_row(row: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse the stored findings JSON back into dicts for report rendering."""
    return json.loads(row.get("findings_json") or "[]")