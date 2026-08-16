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


def _load_env_into_process() -> None:
    """Merge the .env file into os.environ so the running server sees config
    written after start (e.g. the client ID saved by /auth/register)."""
    from .config import default_env_path, parse_env_file

    path = default_env_path()
    for key, value in parse_env_file(path).items():
        if key not in os.environ:
            os.environ[key] = value


_load_env_into_process()


def _pre_seed_demo() -> None:
    """Run a mock scan on import so the landing page shows sample results
    immediately on first load without requiring any clicks."""
    conn = MockConnector()
    result = run_scan(conn, "demo")
    _state["result"] = result
    _state["mode"] = "demo"
    _state["policy"] = _policy_view(result)


# NOTE: _pre_seed_demo() is invoked AFTER _policy_view is defined (see below).


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


def _policy_view(result) -> tuple[dict, list[dict]]:
    """Evaluate policies over a scan result for the web UI.

    Returns (summary, evaluations-as-dicts). Safe on any result object.
    """
    from . import policy

    snapshot = result.snapshot
    evaluations = policy.evaluate(snapshot, result.findings)
    summary = policy.summarize(evaluations)
    evals = [
        {
            "id": e.policy.id,
            "name": e.policy.name,
            "severity": e.policy.severity,
            "compliant": e.compliant,
            "evidence": e.evidence,
        }
        for e in evaluations
    ]
    return summary, evals

_pre_seed_demo()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    cfg = load_config()
    auth_state = load_auth_state()
    result = _state.get("result")
    demo_findings = len(result.findings) if result else 0
    demo_principals = len(result.snapshot.principals) if result else 0
    demo_apps_count = len(result.snapshot.app_assignments) if result else 0
    policy_tuple = _state.get("policy", ({}, []))
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
            "policy_summary": policy_tuple[0],
            "policy_evals": policy_tuple[1],
            "report_md": result.report_md if result else "",
            "version": __version__,
            "repo": _REPO,
        },
    )


@app.get("/auth/start")
async def auth_start(request: Request, provision: str = "0"):
    """Initiate the device-code login flow.

    Requires a registered public-client app. If none is configured
    (OFFBOARD_PUBLIC_CLIENT_ID unset), the user is sent to /auth/register
    for the one-time Azure app registration first.
    """
    cfg = load_config()
    if not cfg.public_client_id and provision not in ("1", "true", "on", "0"):
        pass  # explicit provision flag still honored by callers
    if not cfg.public_client_id:
        # No registered app yet: guide registration (Microsoft blocks first-party
        # bootstrap clients with AADSTS65002, so a tenant-owned app is required).
        return HTMLResponse('<meta http-equiv="refresh" content="0;url=/auth/register"><p>Redirecting to app registration…</p>')

    dc = DeviceCodeAuth(client_id=cfg.public_client_id)
    flow_info = dc.begin_web_flow()

    import threading as _th

    event = _th.Event()
    flow_id = f"flow_{id(dc)}_{_th.active_count()}"
    with _flow_lock:
        _flows[flow_id] = {"dc": dc, "event": event, "user_code": flow_info["user_code"], "phase": "connect"}

    def _wait() -> None:
        try:
            result = dc.finish_web_flow()
            save_auth_state(result.tenant_id, "device_code")
            with _flow_lock:
                _flows[flow_id]["result"] = result
                _flows[flow_id]["phase"] = "connected"
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
            "phase": "connect",
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
        _state["policy"] = _policy_view(result)
        policy_summary, policy_evals = _state["policy"]
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
                "policy_summary": policy_summary,
                "policy_evals": policy_evals,
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


@app.get("/auth/register")
async def auth_register(request: Request):
    """Page that guides the user through the one-time Azure app registration."""
    from .provision import env_path_hint

    return templates.TemplateResponse(
        request,
        "auth_register.html",
        {
            "request": request,
            "env_path": env_path_hint(),
            "version": __version__,
            "repo": _REPO,
        },
    )


@app.post("/auth/register")
async def auth_register_save(request: Request, client_id: str = Form("")):
    """Save the user-provided Application (client) ID and continue to sign-in."""
    client_id = client_id.strip()
    if not client_id or len(client_id) < 8:
        return templates.TemplateResponse(
            request,
            "auth_register.html",
            {
                "request": request,
                "error": "Please paste the Application (client) ID from the Azure portal.",
                "env_path": None,
                "version": __version__,
                "repo": _REPO,
            },
        )

    from .provision import save_public_client_id

    try:
        save_public_client_id(client_id)
        # Make the running process see it immediately (no restart needed)
        os.environ["OFFBOARD_PUBLIC_CLIENT_ID"] = client_id
    except Exception as exc:  # noqa: BLE001
            return templates.TemplateResponse(
                request,
                "auth_register.html",
                {
                    "request": request,
                    "error": f"Could not save config: {exc}",
                    "env_path": None,
                    "version": __version__,
                    "repo": _REPO,
                },
            )
    # Saved; continue to the normal device-code sign-in with this app.
    return HTMLResponse('<meta http-equiv="refresh" content="1;url=/auth/start?provision=0"><p>Client ID saved. Redirecting to sign-in...</p>')


@app.get("/auth/logout")
async def auth_logout():
    cfg = load_config()
    if not cfg.public_client_id:
        return HTMLResponse('<meta http-equiv="refresh" content="2;url=/"><p>Nothing to sign out. Redirecting...</p>')
    DeviceCodeAuth(client_id=cfg.public_client_id).logout()
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