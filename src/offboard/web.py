"""Local web UI (option A).

A single-process FastAPI app that wraps the same `run_scan` pipeline the CLI
uses. It serves the audit report in the browser. No multi-tenant auth, no
hosting, no external security surface: it binds to localhost only and is meant
to run on the admin's own machine.

Pages:
  GET  /            - landing: pick demo scan or run a live scan
  POST /scan        - run a scan (mock or live) and render the report
  GET  /report.md   - raw markdown report (for download)
  GET  /report.html - html report (for download)
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
from .catalog.matcher import load_catalog, match_app
from .config import load_config
from .connectors.entra import EntraConnector
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


def _connector_for(mock: bool):
    if mock:
        return MockConnector()
    cfg = load_config()
    return EntraConnector(cfg.client_id, cfg.client_secret, cfg.authority)


def _catalog_matches(snapshot) -> list[dict]:
    """Return the set of AI apps matched from the snapshot's assignments."""
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
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "request": request,
            "configured": cfg.is_complete,
            "mode": _state["mode"],
            "tenant_id": cfg.tenant_id,
            "version": __version__,
            "repo": _REPO,
        },
    )


@app.post("/scan", response_class=HTMLResponse)
async def scan(request: Request, tenant_id: str = Form(""), mock: str = Form("0")):
    use_mock = mock in ("1", "true", "on")
    tid = tenant_id or "demo"
    try:
        connector = _connector_for(use_mock)
        result = run_scan(connector, tid)
        _state["result"] = result
        _state["mode"] = "demo" if use_mock else "live"
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
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "request": request,
                "configured": load_config().is_complete,
                "mode": _state["mode"],
                "tenant_id": tenant_id or "",
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
