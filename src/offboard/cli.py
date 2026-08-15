"""ai-offboard command-line interface.

Commands:
  setup   one-time interactive connector setup (writes .env)
  auth    manage interactive device-code authentication (login / status / logout)
  audit   scan a tenant and emit a report (terminal summary + optional file)
  plan    dry-run revocation plan (executes nothing)
  doctor  pre-flight health check
  web     local web UI
"""
from __future__ import annotations

from typing import Annotated

import typer

from .auth import (
    DeviceCodeAuth,
    load_auth_state,
)
from .config import default_env_path, load_config, parse_env_file
from .connectors.factory import build_connector
from .connectors.mock import MockConnector
from .scan import run_scan, write_report
from .setup import run_setup

app = typer.Typer(no_args_is_help=True)


def _version_callback(value: bool) -> None:
    if value:
        from . import __version__

        typer.echo(f"ai-offboard {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", "-V", help="Show version and exit", callback=_version_callback),
    ] = None,
) -> None:
    """Read-only AI tool audit + offboarding report for M365 tenants."""


def _pick_connector(
    mock: bool, cfg, prefer_device_code: bool = False
) -> MockConnector | typer.models.CommandInfo:
    if mock:
        return MockConnector()
    return build_connector(cfg, prefer_device_code=prefer_device_code)


def _resolve_tenant_id(cfg, audit: bool = False) -> str:
    """Resolve the tenant ID from flags, auth state, or config (in order)."""
    state = load_auth_state()
    return cfg.tenant_id or state.get("tenant_id", "")


def _load_env() -> None:
    """Merge a repo-root .env into the environment if present (no override)."""
    path = default_env_path()
    for key, value in parse_env_file(path).items():
        if key not in __import__("os").environ:
            __import__("os").environ[key] = value


# ---- auth sub-commands ----

_auth_app = typer.Typer()
app.add_typer(_auth_app, name="auth", help="Manage interactive device-code authentication.")


@_auth_app.command("login")
def auth_login() -> None:
    """Sign in as a Microsoft 365 Global Admin via device code flow.

    Opens a one-time code; paste it at https://microsoft.com/devicelogin.
    No client secret or tenant ID required — the tenant is auto-detected.
    """
    _load_env()
    cfg = load_config()
    client_id = cfg.public_client_id or "1950a258-227b-4e31-a9cf-717495945fc2"
    auth = DeviceCodeAuth(client_id=client_id)
    result = auth.authenticate()

    from .auth import save_auth_state

    save_auth_state(result.tenant_id, "device_code")
    typer.secho(f"Authenticated as {result.account or 'unknown'}", fg=typer.colors.GREEN)
    typer.secho(f"Tenant: {result.tenant_id}", fg=typer.colors.GREEN)
    typer.echo("Next: run `offboard audit` or `offboard web` to scan.")


@_auth_app.command("status")
def auth_status() -> None:
    """Show current authentication state."""
    state = load_auth_state()
    cfg = load_config()
    has_creds = cfg.is_complete

    typer.secho("ai-offboard auth status", bold=True)
    if state.get("mode") == "device_code":
        typer.secho(f"  Device code login: active (tenant {state.get('tenant_id', '?')})", fg=typer.colors.GREEN)
    elif has_creds:
        typer.secho(f"  Client credentials: configured (tenant {cfg.tenant_id})", fg=typer.colors.GREEN)
    else:
        typer.secho("  No auth configured. Run `offboard auth login` or `offboard setup`.", fg=typer.colors.RED)
        raise typer.Exit(1)


@_auth_app.command("logout")
def auth_logout() -> None:
    """Clear cached tokens and sign out."""
    from .auth import DeviceCodeAuth

    cfg = load_config()
    client_id = cfg.public_client_id or "1950a258-227b-4e31-a9cf-717495945fc2"
    DeviceCodeAuth(client_id=client_id).logout()
    typer.echo("Cached tokens removed.")


# ---- core commands ----

@app.command()
def setup(
    force: Annotated[bool, typer.Option("--force", help="Re-prompt all values, ignore existing")] = False,
    env_path: Annotated[str | None, typer.Option("--env", help="Custom .env path")] = None,
    skip_validate: Annotated[bool, typer.Option("--skip-validate", help="Skip the connection test")] = False,
) -> None:
    """One-time connector setup: guide, validate, write .env."""
    run_setup(env_path=env_path, force=force, skip_validate=skip_validate)


@app.command()
def audit(
    tenant_id: Annotated[
        str | None, typer.Option("--tenant", help="Tenant ID (defaults to auth session or config)")
    ] = None,
    report: Annotated[bool, typer.Option("--report", help="Write report.md + report.html")] = False,
    out_dir: Annotated[str, typer.Option("--out", help="Report output directory")] = ".",
    mock: Annotated[bool, typer.Option("--mock", help="Use a demo snapshot (no Azure needed)")] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit findings as JSON (stdout)")] = False,
) -> None:
    """Scan a tenant (read-only) and produce an audit report."""
    _load_env()
    cfg = load_config()
    try:
        connector = _pick_connector(mock, cfg, prefer_device_code=True)
    except RuntimeError as exc:
        typer.secho(str(exc), fg=typer.colors.RED)
        raise typer.Exit(1) from exc

    if mock:
        tid = tenant_id or "demo"
    else:
        tid = tenant_id or _resolve_tenant_id(cfg)

    # Live scanner progress
    import sys as _sys

    def _progress(msg: str) -> None:
        typer.secho(f"  ⟳ {msg}", fg=typer.colors.CYAN, nl=False)
        _sys.stdout.flush()

    typer.secho(f"Scanning tenant {tid}…", fg=typer.colors.CYAN)
    result = run_scan(connector, tid, progress_callback=_progress)
    typer.secho("[done]", fg=typer.colors.GREEN)

    if json_output:
        import json as _json

        output = _json.dumps(
            {
                "scan_timestamp": result.snapshot.scanned_at,
                "tenant_id": result.snapshot.tenant_id,
                "principals_found": len(result.snapshot.principals),
                "app_assignments": len(result.snapshot.app_assignments),
                "findings": [
                    {"rule_id": f.rule_id, "severity": f.severity, "subject": f.subject, "evidence": f.evidence}
                    for f in result.findings
                ],
            },
            indent=2,
        )
        typer.echo(output)
    elif report:
        md_path, html_path = write_report(result, out_dir)
        typer.secho("Report written:", fg=typer.colors.GREEN)
        typer.echo(f"  {md_path}")
        typer.echo(f"  {html_path}")
    else:
        typer.echo(result.report_md)


@app.command()
def plan(
    user: Annotated[str | None, typer.Option("--user", help="UPN to dry-run plan for")] = None,
    tenant_id: Annotated[str | None, typer.Option("--tenant", help="Tenant ID (defaults to auth)")] = None,
    mock: Annotated[bool, typer.Option("--mock", help="Use a demo snapshot (no Azure needed)")] = False,
) -> None:
    """Run a scan and list the dry-run revocation steps (executes nothing)."""
    _load_env()
    cfg = load_config()
    try:
        connector = _pick_connector(mock, cfg, prefer_device_code=True)
    except RuntimeError as exc:
        typer.secho(str(exc), fg=typer.colors.RED)
        raise typer.Exit(1) from exc

    tid = tenant_id or _resolve_tenant_id(cfg) if not mock else "demo"
    result = run_scan(connector, tid)
    typer.echo(f"Scanned {tid}: {len(result.snapshot.principals)} principals, {len(result.findings)} findings.")
    typer.echo("Dry-run revocation steps:")
    for finding in result.findings:
        typer.echo(f"  - [{finding.severity}] {finding.subject} ({finding.rule_id})")


@app.command()
def web(
    port: Annotated[int, typer.Option("--port", help="Port to serve on")] = 8600,
) -> None:
    """Open the local web UI (option A)."""
    from .web import run_server  # import here so setup/audit don't need deps

    run_server(port=port)


@app.command()
def doctor(
    tenant_id: Annotated[str | None, typer.Option("--tenant", help="Tenant ID (defaults to auth)")] = None,
) -> None:
    """Pre-flight checks: .env, auth state, config, and Graph connectivity."""
    from .auth import DeviceCodeAuth

    _load_env()
    cfg = load_config()
    checks: list[tuple[str, bool, str]] = []

    # 1) Device code auth
    dc = DeviceCodeAuth(client_id=cfg.public_client_id or "1950a258-227b-4e31-a9cf-717495945fc2")
    if dc.has_cached_account:
        checks.append(("device_code", True, "cached account present"))
    else:
        checks.append(("device_code", False, "no cached login — run `offboard auth login`"))

    # 2) Config file
    env_path = default_env_path()
    has_env = __import__("os").path.exists(env_path)
    checks.append(("env_file", has_env, f".env at {env_path}" + (" present" if has_env else " missing (run `offboard setup`)")))

    # 3) Client credentials (backup)
    missing = [k for k, v in [("client_id", cfg.client_id), ("client_secret", cfg.client_secret), ("tenant_id", cfg.tenant_id)] if not v]
    checks.append(("client_creds", not missing, "all set" if not missing else f"missing: {', '.join(missing)}"))

    # 4) Auth reachability (try to get a token)
    auth_ok = False
    auth_msg = "skipped"
    if dc.has_cached_account or cfg.is_complete:
        try:
            conn = _pick_connector(False, cfg, prefer_device_code=True)
            r = conn._auth()
            auth_ok = bool(r)
            auth_msg = "token acquired"
        except Exception as exc:  # noqa: BLE001 - surface any auth failure
            auth_msg = f"auth failed: {exc}"
    checks.append(("graph_auth", auth_ok, auth_msg))

    typer.secho("AI-Offboard pre-flight", fg=typer.colors.CYAN, bold=True)
    all_ok = True
    for name, ok, msg in checks:
        all_ok = all_ok and ok
        icon = "[OK]" if ok else "[FAIL]"
        color = typer.colors.GREEN if ok else typer.colors.RED
        typer.secho(f"  {icon} {name}: {msg}", fg=color)
    if all_ok:
        typer.secho("All checks passed.", fg=typer.colors.GREEN)
    else:
        typer.secho("Fix the failures above, then re-run.", fg=typer.colors.RED)
        raise typer.Exit(1)


if __name__ == "__main__":
    app()