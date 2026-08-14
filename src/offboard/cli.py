from __future__ import annotations

from typing import Annotated

import typer

from .audit.report import render_markdown  # noqa: F401  (wired next)
from .connectors.entra import EntraConnector

app = typer.Typer()


@app.command()
def audit(tenant_id: Annotated[str, typer.Option(help="Entra tenant ID")]) -> None:
    """Scan a tenant (read-only) and print a summary."""
    connector = EntraConnector.from_env()
    snapshot = connector.snapshot(tenant_id)
    typer.echo(f"Scanned tenant {tenant_id}: {len(snapshot.principals)} principals.")


@app.command()
def plan(user: Annotated[str | None, typer.Option(help="UPN to dry-run plan")] = None) -> None:
    """Emit a dry-run revocation plan. Executes nothing."""
    typer.echo("Dry-run planning (no writes). Wire to audit findings next.")


if __name__ == "__main__":
    app()
