from __future__ import annotations

from offboard.connectors.mock import MockConnector
from offboard.scan import run_scan


def test_save_and_load_roundtrip(tmp_path, monkeypatch):
    from offboard import store

    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "scans.db"))
    conn = MockConnector()
    result = run_scan(conn, "demo", save=True)

    row = store.load_last_scan("demo")
    assert row is not None
    assert row["tenant_id"] == "demo"
    assert row["finding_count"] == len(result.findings)
    assert "# ai-offboard" in row["report_md"].lower()
    assert row["principal_count"] == 3


def test_no_saved_scan_returns_none(tmp_path, monkeypatch):
    from offboard import store

    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "empty.db"))
    assert store.load_last_scan() is None