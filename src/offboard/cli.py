"""ai-offboard command-line interface.

Commands:
  setup   one-time interactive connector setup (writes .env)
  audit   scan a tenant and emit a report (terminal summary + optional file)
  plan    dry-run revocation plan (executes nothing)
  web     local web UI (option A) -- via `offboard.web` module
"""
from __future__ import annotations

from typing import Annotated

import typer

from .config import default_env_path, load_config, parse_env_file
from .connectors.entra import EntraConnector
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


def _pick_connector(mock: bool, cfg) -> EntraConnector | MockConnector:
    if mock:
        return MockConnector()
    return EntraConnector(cfg.client_id, cfg.client_secret, cfg.authority)


def _load_env() -> None:
    """Merge a repo-root .env into the environment if present (no override)."""
    path = default_env_path()
    for key, value in parse_env_file(path).items():
        if key not in __import__("os").environ:
            __import__("os").environ[key] = value


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
    tenant_id: Annotated[str | None, typer.Option("--tenant", help="Entra tenant ID (defaults to env)")] = None,
    report: Annotated[bool, typer.Option("--report", help="Write report.md + report.html")] = False,
    out_dir: Annotated[str, typer.Option("--out", help="Report output directory")] = ".",
    mock: Annotated[bool, typer.Option("--mock", help="Use a demo snapshot (no Azure needed)")] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit findings as JSON (stdout)")] = False,
) -> None:
    """Scan a tenant (read-only) and produce an audit report."""
    _load_env()
    cfg = load_config()
    if not mock and not cfg.is_complete:
        typer.secho("Config incomplete. Run `offboard setup` first.", fg=typer.colors.RED)
        raise typer.Exit(1)
    tid = tenant_id or cfg.tenant_id
    connector = _pick_connector(mock, cfg)
    result = run_scan(connector, tid)

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
    tenant_id: Annotated[str | None, typer.Option("--tenant", help="Entra tenant ID")] = None,
    mock: Annotated[bool, typer.Option("--mock", help="Use a demo snapshot (no Azure needed)")] = False,
) -> None:
    """Run a scan and list the dry-run revocation steps (executes nothing)."""
    _load_env()
    cfg = load_config()
    if not mock and not cfg.is_complete:
        typer.secho("Config incomplete. Run `offboard setup` first.", fg=typer.colors.RED)
        raise typer.Exit(1)
    tid = tenant_id or cfg.tenant_id
    connector = _pick_connector(mock, cfg)
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
    tenant_id: Annotated[str | None, typer.Option("--tenant", help="Entra tenant ID (defaults to env)")] = None,
) -> None:
    """Pre-flight checks: .env, config, auth, and tenant reachability."""
    _load_env()
    cfg = load_config()
    checks: list[tuple[str, bool, str]] = []

    env_path = default_env_path()
    has_env = __import__("os").path.exists(env_path)
    checks.append(("env_file", has_env, f".env at {env_path}" + (" present" if has_env else " missing (run `offboard setup`)")))

    missing = [k for k, v in [("client_id", cfg.client_id), ("client_secret", cfg.client_secret), ("tenant_id", cfg.tenant_id)] if not v]
    config_ok = not missing
    checks.append(("config", config_ok, "all key fields set" if config_ok else f"missing: {', '.join(missing)}"))

    auth_ok = False
    auth_msg = "skipped (mock or no config)"
    if config_ok:
        try:
            connector = EntraConnector(cfg.client_id, cfg.client_secret, cfg.authority)
            token = connector._auth()
            auth_ok = bool(token)
            auth_msg = "token acquired"
        except Exception as exc:  # noqa: BLE001 - surface any auth failure
            auth_msg = f"auth failed: {exc}"

    checks.append(("auth", auth_ok, auth_msg))

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