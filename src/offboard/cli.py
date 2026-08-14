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

    if report:
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


if __name__ == "__main__":
    app()