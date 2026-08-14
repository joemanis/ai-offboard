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
from fastapi.templating import Jinja2Templates

from .config import load_config
from .connectors.entra import EntraConnector
from .connectors.mock import MockConnector
from .scan import run_scan

_TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")

app = FastAPI(title="ai-offboard", version="0.1.0")
templates = Jinja2Templates(directory=_TEMPLATES_DIR)

_state: dict = {"result": None, "mode": None}


def _connector_for(mock: bool):
    if mock:
        return MockConnector()
    cfg = load_config()
    return EntraConnector(cfg.client_id, cfg.client_secret, cfg.authority)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    cfg = load_config()
    return templates.TemplateResponse(
        request,
        "index.html",
        {"request": request, "configured": cfg.is_complete, "mode": _state["mode"]},
    )


@app.post("/scan", response_class=HTMLResponse)
async def scan(request: Request, tenant_id: str = Form(""), mock: str = Form("0")):
    use_mock = mock in ("1", "true", "on")
    tid = tenant_id or "demo"
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
            "tenant_id": result.snapshot.tenant_id,
            "scanned_at": result.snapshot.scanned_at,
            "report_md": result.report_md,
            "mode": _state["mode"],
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