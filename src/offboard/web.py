"""Local web UI (option A).

A single-process FastAPI app that wraps the same `run_scan` pipeline the CLI
uses. Adds a device-code auth flow so users can connect their M365 tenant
with a single browser login.  Binds to localhost only.
"""
from __future__ import annotations

import os
import threading
import webbrowser

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import __version__
from .auth import DeviceCodeAuth, load_auth_state, save_auth_state
from .catalog.matcher import load_catalog, match_app
from .config import load_config
from .connectors.factory import build_connector
from .connectors.mock import MockConnector
from .scan import run_scan

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_TEMPLATES_DIR = os.path.join(_BASE_DIR, "templates")
_STATIC_DIR = os.path.join(_BASE_DIR, "static")
_REPO = "joemanis/ai-offboard"

templates = Jinja2Templates(directory=_TEMPLATES_DIR)

app = FastAPI(title="ai-offboard", version=__version__)
app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

_state: dict = {"result": None, "mode": None}
# Active device-code flows: {thread_id: {user_code, verification_uri, event, result}}
_flows: dict = {}
_flow_lock = threading.Lock()


def _pre_seed_demo() -> None:
    """Run a mock scan on import so the landing page shows sample results
    immediately on first load without requiring any clicks."""
    from .connectors.mock import MockConnector

    conn = MockConnector()
    result = run_scan(conn, "demo")
    _state["result"] = result
    _state["mode"] = "demo"


_pre_seed_demo()


def _connector_for(mock: bool):
    if mock:
        return MockConnector()
    cfg = load_config()
    return build_connector(cfg, prefer_device_code=True)


def _catalog_matches(snapshot) -> list[dict]:
    apps = load_catalog()
    seen: dict[str, str] = {}
    for assignment in snapshot.app_assignments:
        entry = match_app(assignment.app_display_name, apps)
        tier = entry.dlp_tier if entry else "unknown"
        if entry and entry.name not in seen:
            seen[entry.name] = tier
    return [{"name": name, "tier": tier} for name, tier in seen.items()]


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    cfg = load_config()
    auth_state = load_auth_state()
    result = _state.get("result")
    demo_findings = len(result.findings) if result else 0
    demo_principals = len(result.snapshot.principals) if result else 0
    demo_apps_count = len(result.snapshot.app_assignments) if result else 0
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "request": request,
            "configured": cfg.is_complete,
            "mode": _state["mode"],
            "tenant_id": cfg.tenant_id,
            "auth_connected": auth_state.get("mode") == "device_code",
            "auth_tenant": auth_state.get("tenant_id", ""),
            "demo_findings": demo_findings,
            "demo_principals": demo_principals,
            "demo_apps": demo_apps_count,
            "report_md": result.report_md if result else "",
            "version": __version__,
            "repo": _REPO,
        },
    )


@app.get("/auth/start")
async def auth_start(request: Request):
    """Initiate the device-code login flow. Returns a page with the code displayed."""
    cfg = load_config()
    client_id = cfg.public_client_id or "1950a258-227b-4e31-a9cf-717495945fc2"
    dc = DeviceCodeAuth(client_id=client_id)
    flow_info = dc.begin_web_flow()

    # Store the flow + a threading.Event for polling

    import threading as _th

    event = _th.Event()
    flow_id = f"flow_{id(dc)}_{_th.active_count()}"
    with _flow_lock:
        _flows[flow_id] = {"dc": dc, "event": event, "user_code": flow_info["user_code"]}

    # Background thread: wait for the user to complete at microsoft.com/devicelogin
    def _wait() -> None:
        try:
            result = dc.finish_web_flow()
            save_auth_state(result.tenant_id, "device_code")
            with _flow_lock:
                _flows[flow_id]["result"] = result
        except Exception as exc:  # noqa: BLE001
            with _flow_lock:
                _flows[flow_id]["error"] = str(exc)
        finally:
            event.set()

    thread = threading.Thread(target=_wait, daemon=True)
    thread.start()

    return templates.TemplateResponse(
        request,
        "auth_flow.html",
        {
            "request": request,
            "user_code": flow_info["user_code"],
            "verification_uri": flow_info["verification_uri"],
            "flow_id": flow_id,
            "version": __version__,
            "repo": _REPO,
        },
    )


@app.get("/auth/poll")
async def auth_poll(flow_id: str = ""):
    """Check whether the device-code flow completed. Returns JSON."""
    with _flow_lock:
        flow = _flows.get(flow_id)
        if flow is None:
            return {"status": "unknown", "error": "no such flow"}
        done = flow["event"].is_set()
        if done:
            error = flow.get("error")
            if error:
                return {"status": "error", "error": error}
            return {"status": "connected", "tenant_id": flow.get("result", {}).get("tenant_id", "")}
        return {"status": "pending", "user_code": flow["user_code"]}


@app.post("/scan", response_class=HTMLResponse)
async def scan(request: Request, tenant_id: str = Form(""), mock: str = Form("0")):
    use_mock = mock in ("1", "true", "on")
    tid = tenant_id or "demo"
    try:
        connector = _connector_for(use_mock)
        result = run_scan(connector, tid)
        _state["result"] = result
        _state["mode"] = "demo" if use_mock else "live"
        auth_state = load_auth_state()
        return templates.TemplateResponse(
            request,
            "report.html",
            {
                "request": request,
                "findings": result.findings,
                "principal_count": len(result.snapshot.principals),
                "app_count": len(result.snapshot.app_assignments),
                "apps": _catalog_matches(result.snapshot),
                "tenant_id": result.snapshot.tenant_id,
                "scanned_at": result.snapshot.scanned_at,
                "report_md": result.report_md,
                "mode": _state["mode"],
                "version": __version__,
                "repo": _REPO,
            },
        )
    except Exception as exc:  # noqa: BLE001 - surface scan/auth errors in the UI
        auth_state = load_auth_state()
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "request": request,
                "configured": load_config().is_complete,
                "mode": _state["mode"],
                "tenant_id": tenant_id or "",
                "auth_connected": auth_state.get("mode") == "device_code",
                "auth_tenant": auth_state.get("tenant_id", ""),
                "error": f"Scan failed: {exc}",
                "version": __version__,
                "repo": _REPO,
            },
        )


@app.get("/report.md")
async def report_md():
    if _state.get("result") is None:
        return PlainTextResponse("No scan run yet. POST /scan first.", status_code=404)
    return PlainTextResponse(_state["result"].report_md)


@app.get("/report.html")
async def report_html():
    if _state.get("result") is None:
        return PlainTextResponse("No scan run yet. POST /scan first.", status_code=404)
    return HTMLResponse(_state["result"].report_html)


@app.get("/auth/logout")
async def auth_logout():
    cfg = load_config()
    client_id = cfg.public_client_id or "1950a258-227b-4e31-a9cf-717495945fc2"
    DeviceCodeAuth(client_id=client_id).logout()
    return HTMLResponse(
        '<meta http-equiv="refresh" content="2;url=/"><p>Signed out. Redirecting...</p>'
    )


def run_server(port: int = 8600, open_browser: bool = True) -> None:
    """Start the local server in a thread and open the browser."""
    import uvicorn

    def _open() -> None:
        import time

        time.sleep(1.0)
        if open_browser:
            webbrowser.open(f"http://127.0.0.1:{port}/")

    threading.Thread(target=_open, daemon=True).start()
    print(f"ai-offboard web UI: http://127.0.0.1:{port}/  (Ctrl+C to stop)")
    uvicorn.run(app, host="127.0.0.1", port=port)