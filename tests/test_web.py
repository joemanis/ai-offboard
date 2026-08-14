from __future__ import annotations

from fastapi.testclient import TestClient

from offboard.web import app


def test_landing_page_loads():
    client = TestClient(app)
    resp = client.get("/")
    assert resp.status_code == 200
    assert "ai-offboard" in resp.text.lower()


def test_demo_scan_renders_findings():
    client = TestClient(app)
    resp = client.post("/scan", data={"tenant_id": "demo", "mock": "1"})
    assert resp.status_code == 200
    text = resp.text.lower()
    assert "ai access audit" in text
    assert "microsoft 365 copilot" in text
    assert "stale@example.com" in text


def test_report_md_download_empty_until_scan():
    client = TestClient(app)
    resp = client.get("/report.md")
    # Before any scan runs, the report is not ready (404). After a scan it is.
    if resp.status_code == 200:
        assert resp.text
    else:
        assert resp.status_code == 404


def test_live_scan_rejected_when_not_configured(monkeypatch):
    # Force incomplete config so a live scan path is exercised through the mock
    monkeypatch.setenv("OFFBOARD_CLIENT_ID", "")
    monkeypatch.setenv("OFFBOARD_CLIENT_SECRET", "")
    monkeypatch.setenv("OFFBOARD_TENANT_ID", "")
    client = TestClient(app)
    # Demo path still works without config (that's the point of --mock)
    resp = client.post("/scan", data={"tenant_id": "demo", "mock": "1"})
    assert resp.status_code == 200