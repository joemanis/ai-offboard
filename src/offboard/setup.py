"""Interactive setup wizard for the Entra connector.

`offboard setup` walks the user through the one-time App Registration, prompts
for the values, validates the connection, and writes a ready-to-use .env file.
This removes the biggest onboarding barrier (see docs/connectors.md).

The wizard is optimistic in intent: it segments the steps so a user who has
already registered an app can skip ahead and only fill in values.
"""
from __future__ import annotations

from getpass import getpass

import typer

from .config import Config, default_env_path, parse_env_file, write_env_file
from .connectors.entra import EntraConnector

# No-beacon: validation uses the connector, which never writes.
AUTHORITY_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}"


def _prompt_config(existing: Config, force: bool) -> Config:
    """Prompt for each value, pre-filling existing values when not forcing."""
    def _ask(label: str, current: str, secret: bool = False) -> str:
        show = "" if (force or not current) else f" [{current}]"
        if secret:
            return getpass(f"{label}{show}: ") or current
        return typer.prompt(f"{label}{show}", default="" if force else current, show_default=False) or current

    client_id = _ask("Application (client) ID", existing.client_id)
    tenant_id = _ask("Directory (tenant) ID", existing.tenant_id)
    if not existing.authority or force or "common" in existing.authority:
        authority = AUTHORITY_TEMPLATE.format(tenant_id=tenant_id)
    else:
        authority = existing.authority
    client_secret = _ask("Client secret value", existing.client_secret, secret=True)
    return Config(client_id=client_id, client_secret=client_secret, tenant_id=tenant_id, authority=authority)


def _validate(config: Config) -> None:
    """Try to acquire a token. Prints result; does not throw to the caller."""
    typer.echo("\n[setup] Validating connection to Microsoft Graph...")
    try:
        conn = EntraConnector(config.client_id, config.client_secret, config.authority)
        conn.test_auth()
        typer.secho("[setup] OK: authenticated. The token flow works.", fg=typer.colors.GREEN)
    except Exception as exc:  # noqa: BLE001 - report any auth error clearly
        typer.secho(f"[setup] FAILED: {exc}", fg=typer.colors.RED)
        typer.secho(
            "Common causes: admin consent not granted, wrong client/tenant ID, "
            "or an expired/mistyped secret. See docs/connectors.md.",
            fg=typer.colors.YELLOW,
        )


def run_setup(env_path: str | None = None, force: bool = False, skip_validate: bool = False) -> None:
    """Execute the interactive setup wizard."""
    env_path = env_path or default_env_path()
    existing_env = parse_env_file(env_path)
    existing = Config(
        client_id=existing_env.get("OFFBOARD_CLIENT_ID", ""),
        client_secret=existing_env.get("OFFBOARD_CLIENT_SECRET", ""),
        tenant_id=existing_env.get("OFFBOARD_TENANT_ID", ""),
        authority=existing_env.get(
            "OFFBOARD_AUTHORITY", "https://login.microsoftonline.com/common"
        ),
    )

    typer.secho("ai-offboard setup — Microsoft Entra scanner (read-only)", bold=True)
    typer.echo("Step-by-step App Registration guide: docs/connectors.md")
    typer.echo("You can re-run this anytime; existing values are pre-filled.\n")

    config = _prompt_config(existing, force)
    if not config.is_complete:
        typer.secho("Aborted: all three values (client ID, tenant ID, secret) are required.", fg=typer.colors.RED)
        raise typer.Exit(1)

    if not skip_validate:
        _validate(config)

    write_env_file(env_path, config)
    typer.secho(f"Saved config to {env_path}", fg=typer.colors.GREEN)
    typer.echo("Next: run `offboard audit --tenant <id>` or `offboard web` to scan.")