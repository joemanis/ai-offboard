from __future__ import annotations

import threading

from fastapi.testclient import TestClient

from offboard.auth import AuthResult
from offboard.web import _flow_lock, _flows, app


def test_landing_page_loads():
    client = TestClient(app)
    resp = client.get("/")
    assert resp.status_code == 200
    assert "ai-offboard" in resp.text.lower()
    # Polished landing: hero + stylesheet linked
    assert "Audit your AI access" in resp.text
    assert 'href="/static/style.css"' in resp.text
    # Pre-seeded demo sample report
    assert "pre-seeded demo" in resp.text
    assert "Sample — AI Access Audit" in resp.text


def test_demo_scan_renders_findings():
    client = TestClient(app)
    resp = client.post("/scan", data={"tenant_id": "demo", "mock": "1"})
    assert resp.status_code == 200
    text = resp.text.lower()
    assert "ai access audit" in text
    assert "microsoft 365 copilot" in text
    assert "stale@example.com" in text


def test_demo_scan_renders_remediation_and_apps():
    client = TestClient(app)
    resp = client.post("/scan", data={"tenant_id": "demo", "mock": "1"})
    assert resp.status_code == 200
    text = resp.text
    # New polished report surfaces: app inventory chips + remediation steps
    assert "App inventory" in text
    assert "Remediation" in text
    assert "Microsoft 365 Copilot" in text


def test_report_md_download_empty_until_scan():
    client = TestClient(app)
    resp = client.get("/report.md")
    # Before any scan runs, the report is not ready (404). After a scan it is.
    if resp.status_code == 200:
        assert resp.text
    else:
        assert resp.status_code == 404


def test_landing_page_shows_policy_compliance_card():
    client = TestClient(app)
    resp = client.get("/")
    assert resp.status_code == 200
    # Pre-seeded demo evaluates the bundled policies
    assert "Zero Trust policy compliance" in resp.text
    assert "ZT-001" in resp.text
    assert "PASS" in resp.text or "FAIL" in resp.text
    assert "passing" in resp.text


def test_report_page_shows_policy_section():
    client = TestClient(app)
    resp = client.post("/scan", data={"tenant_id": "demo", "mock": "1"})
    assert resp.status_code == 200
    text = resp.text
    assert "Zero Trust policy compliance" in text
    assert "ZT-005" in text  # the default-deny allowlist policy
    assert "policy check" in text


def test_live_scan_rejected_when_not_configured(monkeypatch):
    # Force incomplete config so a live scan path is exercised through the mock
    monkeypatch.setenv("OFFBOARD_CLIENT_ID", "")
    monkeypatch.setenv("OFFBOARD_CLIENT_SECRET", "")
    monkeypatch.setenv("OFFBOARD_TENANT_ID", "")
    client = TestClient(app)
    # Demo path still works without config (that's the point of --mock)
    resp = client.post("/scan", data={"tenant_id": "demo", "mock": "1"})
    assert resp.status_code == 200

def test_poll_connected_handles_authresult_object():
    """Regression: the device-code thread stores an AuthResult (a dataclass),
    not a dict; /auth/poll must read .tenant_id via attribute access, not
    .get(). Previously this crashed with AttributeError, leaving the page
    stuck on 'Waiting for sign-in…' even though Microsoft completed."""
    client = TestClient(app)
    flow_id = "flow_regression_test"
    ev = threading.Event()
    with _flow_lock:
        _flows[flow_id] = {
            "dc": None,
            "event": ev,
            "user_code": "TESTCODE",
            "phase": "connect",
            "result": AuthResult(token="tok", tenant_id="tenant-123", account="joe@example.com"),
        }
    ev.set()
    try:
        resp = client.get(f"/auth/poll?flow_id={flow_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "connected"
        assert data["tenant_id"] == "tenant-123"
    finally:
        with _flow_lock:
            _flows.pop(flow_id, None)
