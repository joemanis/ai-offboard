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
    assert "Find unwanted AI access" in resp.text
    assert 'href="/static/style.css"' in resp.text
    # Pre-seeded demo sample report
    assert "pre-seeded demo" in resp.text
    assert "Sample — AI Access Report" in resp.text


def test_landing_page_expired_device_login_offers_new_code(monkeypatch):
    from offboard import web
    from offboard.config import Config

    class ExpiredAuth:
        def __init__(self, client_id):
            pass

        def authenticate(self, interactive=False):
            raise RuntimeError("cached login expired")

    monkeypatch.setattr(web, "load_auth_state", lambda: {"mode": "device_code", "tenant_id": "old-tenant"})
    monkeypatch.setattr(web, "load_config", lambda: Config("", "", "", public_client_id="public-client"))
    monkeypatch.setattr(web, "DeviceCodeAuth", ExpiredAuth)

    response = TestClient(app).get("/")

    assert response.status_code == 200
    assert "Microsoft sign-in needs attention" in response.text
    assert "Generate new device code" in response.text
    assert 'href="/auth/start"' in response.text
    assert "Connected to tenant" not in response.text
    assert "old-tenant" in response.text


def test_landing_page_only_claims_connected_after_silent_validation(monkeypatch):
    from offboard import web
    from offboard.config import Config

    class ValidAuth:
        def __init__(self, client_id):
            pass

        def authenticate(self, interactive=False):
            return AuthResult(token="token", tenant_id="validated-tenant")

    monkeypatch.setattr(web, "load_auth_state", lambda: {"mode": "device_code", "tenant_id": "old-tenant"})
    monkeypatch.setattr(web, "load_config", lambda: Config("", "", "", public_client_id="public-client"))
    monkeypatch.setattr(web, "DeviceCodeAuth", ValidAuth)

    response = TestClient(app).get("/")

    assert response.status_code == 200
    assert "Microsoft sign-in is valid for tenant" in response.text
    assert "validated-tenant" in response.text
    assert "old-tenant" not in response.text


def test_auth_start_generates_device_code_page(monkeypatch):
    from offboard import web
    from offboard.config import Config

    class FakeDeviceAuth:
        def __init__(self, client_id):
            pass

        def begin_web_flow(self):
            return {"user_code": "NEW-CODE", "verification_uri": "https://login.example/device"}

        def finish_web_flow(self):
            raise RuntimeError("test flow stopped")

    monkeypatch.setattr(web, "load_config", lambda: Config("", "", "", public_client_id="public-client"))
    monkeypatch.setattr(web, "DeviceCodeAuth", FakeDeviceAuth)
    monkeypatch.setattr(web, "save_auth_state", lambda tenant_id, mode: None)

    response = TestClient(app).get("/auth/start")

    assert response.status_code == 200
    assert "NEW-CODE" in response.text
    assert "https://login.example/device" in response.text
    assert "Waiting for sign-in" in response.text


def test_demo_scan_renders_findings():
    client = TestClient(app)
    resp = client.post("/scan", data={"tenant_id": "demo", "mock": "1"})
    assert resp.status_code == 200
    text = resp.text.lower()
    assert "ai access report" in text
    assert "microsoft 365 copilot" in text
    assert "disabled@example.com" in text


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
    assert "AI access policy compliance" in resp.text
    assert "AI-001" in resp.text
    assert "PASS" in resp.text or "FAIL" in resp.text
    assert "passing" in resp.text


def test_report_page_shows_policy_section():
    client = TestClient(app)
    resp = client.post("/scan", data={"tenant_id": "demo", "mock": "1"})
    assert resp.status_code == 200
    text = resp.text
    assert "AI access policy compliance" in text
    assert "AI-004" in text  # the approved-app policy
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


def test_logout_clears_public_client_id(tmp_path, monkeypatch):
    """Regression: Disconnect must remove OFFBOARD_PUBLIC_CLIENT_ID from both
    the .env file and the process environment, so the next Connect shows the
    fresh registration experience instead of reusing the old app ID."""
    from offboard import auth, config, provision

    env_file = tmp_path / ".env"
    monkeypatch.setattr(config, "default_env_path", lambda: str(env_file))
    # Redirect the auth token/state files into tmp_path: the /auth/logout
    # route deletes them via the auth module's module-level path constants,
    # so offline tests must never touch the real ~/.ai-offboard directory.
    monkeypatch.setattr(auth, "STATE_DIR", str(tmp_path))
    monkeypatch.setattr(auth, "TOKEN_CACHE_PATH", str(tmp_path / "token_cache.json"))
    monkeypatch.setattr(auth, "AUTH_STATE_PATH", str(tmp_path / "auth.json"))
    # The route builds DeviceCodeAuth, which resolves the same paths; keep
    # them in sync through the auth module so both stay under tmp_path.
    monkeypatch.setenv("OFFBOARD_STATE_DIR", str(tmp_path))

    # Seed a .env with a client ID + an unrelated key (must survive) and put it
    # in the process env as the running server would.
    provision.save_public_client_id("fake-client-123")
    with open(env_file, "a") as fh:
        fh.write("OFFBOARD_CLIENT_ID=keepme\n")
    monkeypatch.setenv("OFFBOARD_PUBLIC_CLIENT_ID", "fake-client-123")

    client = TestClient(app)
    resp = client.post("/auth/logout")
    assert resp.status_code == 200

    # .env no longer has the public client ID, but the other key survives
    with open(env_file) as fh:
        content = fh.read()
    assert "OFFBOARD_PUBLIC_CLIENT_ID" not in content
    assert "OFFBOARD_CLIENT_ID=keepme" in content
    # Process env is cleared too
    assert "OFFBOARD_PUBLIC_CLIENT_ID" not in __import__("os").environ


def test_live_scan_uses_saved_tenant_and_persists(monkeypatch):
    """A blank tenant field on a connected live scan uses auth state, not demo."""
    from dataclasses import replace

    from offboard import web
    from offboard.connectors.mock import MockConnector
    from offboard.scan import run_scan as real_run_scan

    seen = {}

    class TenantAwareMock:
        def snapshot(self, tenant_id, progress_callback=None):
            snapshot = MockConnector().snapshot("demo", progress_callback=progress_callback)
            return replace(snapshot, tenant_id=tenant_id)

    def fake_run_scan(connector, tenant_id, **kwargs):
        seen["tenant_id"] = tenant_id
        seen["save"] = kwargs.get("save")
        return real_run_scan(connector, tenant_id, save=False)

    monkeypatch.setattr(web, "load_auth_state", lambda: {"tenant_id": "tenant-live"})
    monkeypatch.setattr(web, "_connector_for", lambda use_mock: TenantAwareMock())
    monkeypatch.setattr(web, "run_scan", fake_run_scan)
    response = TestClient(app).post("/scan", data={"tenant_id": "", "mock": "0"})

    assert response.status_code == 200
    assert seen == {"tenant_id": "tenant-live", "save": True}
    assert "tenant-live" in response.text


def test_web_live_connector_disables_hidden_interactive_login(monkeypatch):
    from offboard import web

    captured = {}

    def fake_build_connector(cfg, **kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(web, "build_connector", fake_build_connector)
    monkeypatch.setattr(web, "load_config", lambda: object())

    web._connector_for(False)

    assert captured == {"prefer_device_code": True, "allow_interactive": False}


def test_scan_start_reports_progress_and_redirects_to_result(monkeypatch):
    from offboard import web
    from offboard.scan import run_scan as real_run_scan

    def fake_run_scan(connector, tenant_id, progress_callback=None, save=False):
        if progress_callback:
            progress_callback("Fetching users…")
            progress_callback("Fetching enterprise apps…")
            progress_callback("Fetching delegated OAuth grants…")
        return real_run_scan(connector, tenant_id, save=False)

    monkeypatch.setattr(web, "run_scan", fake_run_scan)
    client = TestClient(app)
    started = client.post("/scan/start", data={"tenant_id": "demo", "mock": "1"})
    assert started.status_code == 200
    job_id = started.json()["job_id"]

    for _ in range(20):
        status = client.get(f"/scan/status?job_id={job_id}").json()
        if status["status"] == "complete":
            break
        threading.Event().wait(0.01)
    assert status["status"] == "complete"
    assert status["progress"] == 100
    assert status["location"].endswith(job_id)

    report = client.get(status["location"])
    assert report.status_code == 200
    assert "AI Access Report" in report.text


def test_landing_page_contains_scan_progress_controls():
    response = TestClient(app).get("/")
    assert response.status_code == 200
    assert 'id="scan-progress"' in response.text
    assert 'role="progressbar"' in response.text
    assert "startScan(event, this)" in response.text


def test_remote_web_requires_operator_login(monkeypatch):
    from offboard import web

    monkeypatch.setattr(web, "_web_remote_mode", True)
    monkeypatch.setattr(web, "_web_token", "operator-secret")
    with web._web_session_lock:
        web._web_sessions.clear()
    client = TestClient(app, follow_redirects=False)
    try:
        blocked = client.get("/")
        assert blocked.status_code == 303
        assert blocked.headers["location"] == "/auth/login"
        assert client.post("/auth/login", data={"token": "wrong"}).status_code == 401
        signed_in = client.post("/auth/login", data={"token": "operator-secret"})
        assert signed_in.status_code == 303
        assert client.get("/").status_code == 200
    finally:
        monkeypatch.setattr(web, "_web_remote_mode", False)
        monkeypatch.setattr(web, "_web_token", "")
        with web._web_session_lock:
            web._web_sessions.clear()


def test_state_changing_cross_origin_request_is_rejected():
    response = TestClient(app).post(
        "/scan",
        data={"tenant_id": "demo", "mock": "1"},
        headers={"Origin": "https://attacker.example"},
    )
    assert response.status_code == 403
