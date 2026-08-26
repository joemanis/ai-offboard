"""ai-offboard command-line interface.

Commands:
  setup   one-time interactive connector setup (writes .env)
  auth    manage interactive device-code authentication (login / status / logout)
  audit   scan a tenant and emit a report (terminal summary + optional file)
  plan    dry-run AI access cleanup plan (executes nothing)
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
from .connectors.entra import EntraConnector
from .connectors.factory import build_connector
from .connectors.mock import MockConnector
from .scan import run_scan, write_evidence_bundle, write_report
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
    mock: bool, cfg, prefer_device_code: bool = False, allow_interactive: bool = True
) -> MockConnector | EntraConnector:
    if mock:
        return MockConnector()
    return build_connector(
        cfg,
        prefer_device_code=prefer_device_code,
        allow_interactive=allow_interactive,
    )


def _resolve_tenant_id(cfg, audit: bool = False) -> str:
    """Resolve the tenant ID from flags, auth state, or config (in order)."""
    state = load_auth_state()
    return cfg.tenant_id or state.get("tenant_id", "")


def _render_matrix(matrix: list[dict]) -> None:
    """Render the multi-tenant sweep results as a table."""
    typer.echo("")
    typer.secho("Multi-tenant audit matrix", bold=True, fg=typer.colors.CYAN)
    typer.echo(f"  {'Tenant':<40} {'Findings':>10} {'High/Critical':>16}")
    typer.echo("  " + "-" * 68)
    for row in matrix:
        typer.echo(f"  {row['tenant']:<40} {row['findings']!s:>10} {row['high']!s:>16}")


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

    Opens a one-time code; paste it at the Microsoft login URL.
    No client secret or tenant ID required — the tenant is auto-detected.
    Requires OFFBOARD_PUBLIC_CLIENT_ID (see `offboard auth register`).
    """
    _load_env()
    cfg = load_config()
    if not cfg.public_client_id:
        typer.secho(
            "No public client app configured. Register one first:\n"
            "  offboard auth register\n"
            "(4 clicks in the Azure portal: App registrations -> New -> Authentication ->\n"
            " allow public client flows. Paste the Application (client) ID.)",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)
    auth = DeviceCodeAuth(client_id=cfg.public_client_id)
    result = auth.authenticate()

    from .auth import save_auth_state

    save_auth_state(result.tenant_id, "device_code")
    typer.secho(f"Authenticated as {result.account or 'unknown'}", fg=typer.colors.GREEN)
    typer.secho(f"Tenant: {result.tenant_id}", fg=typer.colors.GREEN)
    typer.echo("Next: run `offboard audit` or `offboard web` to scan.")


@_auth_app.command("provision")
def auth_provision() -> None:
    """Legacy: auto-register a dedicated app via a bootstrap sign-in.

    NOTE: Microsoft blocks first-party bootstrap clients (AADSTS65002), so
    the default path is `offboard auth register` (tenant-owned app, 2 min).
    This command is kept for tenants whose signed-in token already carries
    Application.ReadWrite.All and can provision themselves.
    """
    from .auth import DeviceCodeAuth, save_auth_state
    from .provision import (
        BOOTSTRAP_CLIENT_ID,
        BOOTSTRAP_SCOPES,
        provision_public_client,
        save_public_client_id,
    )

    _load_env()
    cfg = load_config()

    if cfg.public_client_id:
        typer.secho(f"Already provisioned: OFFBOARD_PUBLIC_CLIENT_ID={cfg.public_client_id}", fg=typer.colors.YELLOW)
        typer.echo("Run `offboard auth login` to sign in with it.")
        return

    typer.secho("The quick path is `offboard auth register` (no bootstrap, 2 min).", fg=typer.colors.YELLOW)
    typer.secho("Attempting bootstrap provisioning...", fg=typer.colors.CYAN)
    bootstrap = DeviceCodeAuth(client_id=BOOTSTRAP_CLIENT_ID)
    bootstrap_result = bootstrap.authenticate(scopes=BOOTSTRAP_SCOPES)
    typer.secho("  Bootstrap authenticated.", fg=typer.colors.GREEN)

    typer.secho("Creating dedicated 'ai-offboard' app registration...", fg=typer.colors.CYAN)
    try:
        app_id = provision_public_client(bootstrap_result.token)
    except Exception as exc:
        typer.secho(f"Provisioning failed: {exc}", fg=typer.colors.RED)
        typer.secho(
            "Fall back to `offboard auth register` (tenant-owned app): it avoids "
            "the first-party bootstrap block entirely.",
            fg=typer.colors.YELLOW,
        )
        raise typer.Exit(1) from exc

    env_path = save_public_client_id(app_id)
    typer.secho(f"  Dedicated app registered (client ID {app_id[:8]}...)", fg=typer.colors.GREEN)
    typer.echo(f"  Saved OFFBOARD_PUBLIC_CLIENT_ID to {env_path}")

    typer.secho("Authorizing read access with the dedicated app...", fg=typer.colors.CYAN)
    auth = DeviceCodeAuth(client_id=app_id)
    result = auth.authenticate()
    save_auth_state(result.tenant_id, "device_code")
    typer.secho(f"Authenticated as {result.account or 'unknown'}", fg=typer.colors.GREEN)
    typer.secho(f"Tenant: {result.tenant_id}", fg=typer.colors.GREEN)
    typer.echo("Done. Run `offboard audit` or `offboard web` to scan.")



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


@_auth_app.command("register")
def auth_register(
    client_id: Annotated[str | None, typer.Option("--client-id", help="Application (client) ID from the Azure portal")] = None,
) -> None:
    """Register the tenant's public-client app (one-time, ~2 min).

    Guides you through the 4 Azure portal clicks, then saves the
    Application (client) ID as OFFBOARD_PUBLIC_CLIENT_ID in .env.
    """
    from .provision import save_public_client_id

    if client_id and len(client_id) < 8:
        typer.secho("That doesn't look like a client ID.", fg=typer.colors.RED)
        raise typer.Exit(1)

    if not client_id:
        typer.secho("Register the app (2 minutes):", fg=typer.colors.CYAN, bold=True)
        typer.echo("  1. portal.azure.com -> Microsoft Entra ID -> App registrations -> New registration")
        typer.echo("  2. Name: ai-offboard; Supported account types: MULTIPLE Entra ID tenants (2nd option; single-tenant will fail with AADSTS50059)")
        typer.echo("     then select Allow all tenants when it expands; Register")
        typer.echo("  3. Authentication (Preview) -> Settings -> Allow public client flows = set to Enabled -> Save")
        typer.echo("  4. Copy the Application (client) ID from the overview page")
        client_id = typer.prompt("Paste the Application (client) ID", default="")

    if not client_id or len(client_id) < 8:
        typer.secho("No valid client ID provided.", fg=typer.colors.RED)
        raise typer.Exit(1)

    env_path = save_public_client_id(client_id)
    typer.secho(f"Saved OFFBOARD_PUBLIC_CLIENT_ID to {env_path}", fg=typer.colors.GREEN)
    typer.echo("Next: run `offboard auth login` to sign in, then `offboard audit`.")


@_auth_app.command("logout")
def auth_logout() -> None:
    """Clear cached tokens and sign out."""
    from .auth import DeviceCodeAuth

    cfg = load_config()
    if not cfg.public_client_id:
        typer.secho("Nothing to sign out: no public client app configured.", fg=typer.colors.YELLOW)
        return
    DeviceCodeAuth(client_id=cfg.public_client_id).logout()
    typer.echo("Cached tokens removed.")




# ---- tenant sub-commands ----

_tenant_app = typer.Typer()
app.add_typer(_tenant_app, name="tenant", help="Manage multi-tenant audit targets (MSP mode).")


@_tenant_app.command("add")
def tenant_add(
    tenant_id: Annotated[str, typer.Argument(help="Entra tenant ID to register")],
    name: Annotated[str | None, typer.Option("--name", help="Display name (defaults to tenant ID)")] = None,
) -> None:
    """Register a customer tenant for multi-tenant audits."""
    from .store import add_tenant

    added = add_tenant(tenant_id, name or "")
    typer.secho(f"{'Added' if added else 'Already registered'} tenant {tenant_id}", fg=typer.colors.GREEN)


@_tenant_app.command("remove")
def tenant_remove(
    tenant_id: Annotated[str, typer.Argument(help="Entra tenant ID to unregister")],
) -> None:
    """Unregister a customer tenant."""
    from .store import remove_tenant

    if remove_tenant(tenant_id):
        typer.secho(f"Removed tenant {tenant_id}", fg=typer.colors.GREEN)
    else:
        typer.secho(f"Tenant {tenant_id} not found", fg=typer.colors.RED)
        raise typer.Exit(1)


@_tenant_app.command("list")
def tenant_list() -> None:
    """List registered customer tenants."""
    from .store import list_tenants, load_last_scan

    tenants = list_tenants()
    if not tenants:
        typer.echo("No tenants registered. Run `offboard tenant add <id>` first.")
        return
    for t in tenants:
        last = load_last_scan(t["tenant_id"])
        count = last["finding_count"] if last else "—"
        typer.echo(f"  {t['display_name']:<40} {t['tenant_id']:<40} last findings: {count}")


# ---- schedule sub-commands ----

_schedule_app = typer.Typer()
app.add_typer(_schedule_app, name="schedule", help="Recurring audits + report delivery.")


@_schedule_app.command("add")
def schedule_add(
    tenant_id: Annotated[str, typer.Argument(help="Tenant ID to audit on a schedule")],
    interval: Annotated[str, typer.Option("--interval", help="daily | weekly | monthly")] = "daily",
) -> None:
    """Register a recurring audit job."""
    from .store import add_schedule

    if interval not in ("daily", "weekly", "monthly"):
        typer.secho("Interval must be daily, weekly, or monthly.", fg=typer.colors.RED)
        raise typer.Exit(1)
    job_id = add_schedule(tenant_id, interval)
    typer.secho(f"Scheduled {interval} audit for {tenant_id} (job #{job_id})", fg=typer.colors.GREEN)
    typer.echo("Drive it with an OS scheduler calling: offboard schedule run-due")


@_schedule_app.command("remove")
def schedule_remove(
    job_id: Annotated[int, typer.Argument(help="Job ID from `offboard schedule list`")],
) -> None:
    """Remove a scheduled audit job."""
    from .store import remove_schedule

    if remove_schedule(job_id):
        typer.secho(f"Removed schedule job {job_id}", fg=typer.colors.GREEN)
    else:
        typer.secho(f"Job {job_id} not found", fg=typer.colors.RED)
        raise typer.Exit(1)


@_schedule_app.command("list")
def schedule_list() -> None:
    """List scheduled audit jobs."""
    from .store import list_schedules

    jobs = list_schedules()
    if not jobs:
        typer.echo("No scheduled audits. Run `offboard schedule add <tenant> --interval daily`.")
        return
    for j in jobs:
        last = j["last_run"] or "never"
        typer.echo(f"  #{j['id']} {j['tenant_id']:<40} {j['schedule']:<10} last run: {last}")


@_schedule_app.command("run-due")
def schedule_run_due(
    report_dir: Annotated[str, typer.Option("--out", help="Report directory for local delivery")] = "reports",
    mock: Annotated[bool, typer.Option("--mock", help="Use demo snapshots (no Azure needed)")] = False,
) -> None:
    """Run all due scheduled audits. Call from cron / Task Scheduler."""
    _load_env()
    cfg = load_config()
    connector = _pick_connector(mock, cfg, prefer_device_code=True)

    from .schedule import run_due

    results = run_due(cfg, connector, report_dir=report_dir)
    if not results:
        typer.echo("No scheduled audits due.")
    for r in results:
        status = "✅" if r.get("delivered") else "⚠️"
        color = typer.colors.GREEN if r.get("delivered") else typer.colors.RED
        typer.secho(f"  {status} {r['tenant']}: {r.get('findings', '?')} findings", fg=color)


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
    bundle: Annotated[str | None, typer.Option("--bundle", help="Write a complete evidence ZIP to this path")] = None,
    mock: Annotated[bool, typer.Option("--mock", help="Use a demo snapshot (no Azure needed)")] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit findings as JSON (stdout)")] = False,
    csv_output: Annotated[bool, typer.Option("--csv", help="Write findings to CSV (MSP tooling friendly)")] = False,
    audit_all: Annotated[bool, typer.Option("--all", help="Scan every registered tenant (MSP mode)")] = False,
    workspace: Annotated[bool, typer.Option("--workspace", help="Scan a Google Workspace tenant instead of Entra")] = False,
    sign_in_context: Annotated[bool, typer.Option("--sign-in-context", help="Collect optional sign-in activity; not used by core AI-access findings")] = False,
) -> None:
    """Scan a tenant for connected AI access and produce an audit report."""
    _load_env()
    cfg = load_config()
    if workspace:
        from .connectors.factory import build_workspace_connector

        ws_connector = build_workspace_connector(cfg)
        tid = tenant_id or "workspace"
        typer.secho("Scanning Google Workspace…", fg=typer.colors.CYAN)
        result = run_scan(ws_connector, tid, save=True, sign_in_context=sign_in_context)
        typer.secho("[done]", fg=typer.colors.GREEN)
        _emit_audit_output(result, json_output, csv_output, report, out_dir, bundle)
        return


    if audit_all:
        from .store import list_tenants

        tenants = list_tenants()
        if not tenants:
            typer.secho("No tenants registered. Run `offboard tenant add <id>` first.", fg=typer.colors.RED)
            raise typer.Exit(1)
        from .auth import DeviceCodeAuth, load_auth_state

        auth_state = load_auth_state()
        device_auth = DeviceCodeAuth(client_id=cfg.public_client_id or "1950a258-227b-4e31-a9cf-717495945fc2")
        if auth_state.get("mode") == "device_code" or device_auth.has_cached_account:
            typer.secho(
                "Refusing multi-tenant sweep with an interactive device-code session. "
                "Configure client credentials or authenticate each tenant separately.",
                fg=typer.colors.RED,
            )
            raise typer.Exit(1)
        if not cfg.is_complete:
            typer.secho(
                "Multi-tenant sweep requires client-credentials configuration; run `offboard setup` first.",
                fg=typer.colors.RED,
            )
            raise typer.Exit(1)
        typer.secho(f"Scanning {len(tenants)} tenants…", fg=typer.colors.CYAN)
        matrix: list[dict] = []
        for t in tenants:
            try:
                connector = _pick_connector(False, cfg, prefer_device_code=False)
                result = run_scan(connector, t["tenant_id"], save=True, sign_in_context=sign_in_context)
                matrix.append(
                    {
                        "tenant": t["display_name"],
                        "tenant_id": t["tenant_id"],
                        "findings": len(result.findings),
                        "high": sum(1 for f in result.findings if f.severity in ("high", "critical")),
                    }
                )
                typer.secho(f"  ✅ {t['display_name']}: {len(result.findings)} findings", fg=typer.colors.GREEN)
            except Exception as exc:  # noqa: BLE001 - one tenant failing shouldn't kill the sweep
                matrix.append({"tenant": t["display_name"], "tenant_id": t["tenant_id"], "findings": "ERR", "high": "—"})
                typer.secho(f"  ⚠️  {t['display_name']}: {exc}", fg=typer.colors.RED)
        _render_matrix(matrix)
        return

    try:
        connector = _pick_connector(
            mock,
            cfg,
            prefer_device_code=True,
            allow_interactive=not (json_output or bundle),
        )
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

    if not json_output:
        typer.secho(f"Scanning tenant {tid}…", fg=typer.colors.CYAN)
    try:
        result = run_scan(
            connector,
            tid,
            progress_callback=None if json_output else _progress,
            save=True,
            sign_in_context=sign_in_context,
        )
    except RuntimeError as exc:
        typer.secho(str(exc), fg=typer.colors.RED)
        raise typer.Exit(1) from exc
    if not json_output:
        typer.secho("[done]", fg=typer.colors.GREEN)
    _emit_audit_output(result, json_output, csv_output, report, out_dir, bundle)


def _emit_audit_output(
    result,
    json_output: bool,
    csv_output: bool,
    report: bool,
    out_dir: str,
    bundle: str | None = None,
) -> None:
    """Print or write the audit result in the requested format."""
    if bundle:
        bundle_path = write_evidence_bundle(result, bundle)
        if not json_output:
            typer.secho(f"Evidence bundle written: {bundle_path}", fg=typer.colors.GREEN)
    if json_output:
        import json as _json

        output = _json.dumps(
            {
                "scan_timestamp": result.snapshot.scanned_at,
                "tenant_id": result.snapshot.tenant_id,
                "principals_found": len(result.snapshot.principals),
                "enterprise_apps": result.snapshot.enterprise_app_count if result.snapshot.enterprise_app_count is not None else len(result.snapshot.app_assignments),
                "app_role_assignments": len(result.snapshot.app_assignments),
                "findings": [
                    {"rule_id": f.rule_id, "severity": f.severity, "subject": f.subject, "evidence": f.evidence}
                    for f in result.findings
                ],
            },
            indent=2,
        )
        typer.echo(output)
    elif csv_output:
        import os as _os

        _os.makedirs(out_dir, exist_ok=True)
        csv_path = _os.path.join(out_dir, "ai-offboard-findings.csv")
        from .scan import write_findings_csv

        write_findings_csv(result, csv_path)
        typer.secho(f"Findings CSV written: {csv_path}", fg=typer.colors.GREEN)
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
    """Run a scan and list the dry-run AI access cleanup steps (executes nothing)."""
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
    typer.echo("Dry-run AI access cleanup steps:")
    for finding in result.findings:
        typer.echo(f"  - [{finding.severity}] {finding.subject} ({finding.rule_id})")


@app.command()
def execute(
    tenant_id: Annotated[str | None, typer.Option("--tenant", help="Tenant ID (defaults to auth)")] = None,
    target: Annotated[str | None, typer.Option("--target", help="Limit execution to one subject (UPN or app name)")] = None,
    auto_approve: Annotated[bool, typer.Option("--yes", help="Skip the interactive confirmation prompt")] = False,
    mock: Annotated[bool, typer.Option("--mock", help="Use a demo snapshot (no Azure needed)")] = False,
) -> None:
    """Apply the AI access cleanup plan (WRITES to the tenant).

    WARNING: this performs real mutations. You must confirm the plan when
    prompted (unless --yes). Every mutation is logged to the audit log.
    """
    _load_env()
    cfg = load_config()
    try:
        connector = _pick_connector(mock, cfg, prefer_device_code=True)
    except RuntimeError as exc:
        typer.secho(str(exc), fg=typer.colors.RED)
        raise typer.Exit(1) from exc

    tid = tenant_id or _resolve_tenant_id(cfg) if not mock else "demo"
    result = run_scan(connector, tid)
    findings = result.findings
    if target:
        findings = [f for f in findings if f.subject.lower() in target.lower() or target.lower() in f.subject.lower()]
    if not findings:
        typer.secho("No findings to execute against.", fg=typer.colors.YELLOW)
        raise typer.Exit(0)

    # Build the plan from the risk module's remediation steps
    steps: list[tuple[str, str, str]] = []
    for f in findings:
        for step in f.remediation:
            action = _remediation_to_action(step)
            if action:
                steps.append((action, f.subject, step))

    if not steps:
        typer.secho("No actionable steps for the current findings.", fg=typer.colors.YELLOW)
        raise typer.Exit(0)

    typer.secho("Dry-run AI access cleanup steps:", fg=typer.colors.CYAN, bold=True)
    for action, target_name, step in steps:
        typer.echo(f"  - [{action}] {target_name}: {step}")

    if not auto_approve:
        typer.secho("This WILL make real changes to the tenant.", fg=typer.colors.RED, bold=True)
        confirmation = typer.prompt('Type "execute" to confirm', default="")
        if confirmation.strip().lower() != "execute":
            typer.secho("Aborted. No changes were made.", fg=typer.colors.RED)
            raise typer.Exit(1)
    else:
        typer.secho("--yes: proceeding without interactive confirmation.", fg=typer.colors.YELLOW)

    from .execute import Executor
    from .store import log_execution

    executor = Executor(connector)
    ok = 0
    failed = 0
    for action, target_name, step in steps:
        typer.echo(f"  - [{action}] {target_name}…", nl=False)
        try:
            outcome = executor.execute(action, target_name)
            log_execution(tid, action, target_name, outcome.get("status", "unknown"), outcome.get("detail"))
            if outcome.get("status") == "ok":
                ok += 1
                typer.secho(" ok", fg=typer.colors.GREEN)
            else:
                failed += 1
                typer.secho(f" {outcome.get('status')}", fg=typer.colors.RED)
                if outcome.get("detail"):
                    typer.echo(f"      {outcome['detail']}")
        except Exception as exc:  # noqa: BLE001 - log every mutation even on failure
            failed += 1
            log_execution(tid, action, target_name, "error", str(exc))
            typer.secho(f" error: {exc}", fg=typer.colors.RED)

    typer.secho(f"Done: {ok} applied, {failed} failed. Audit log updated.", fg=typer.colors.GREEN if failed == 0 else typer.colors.RED)


def _remediation_to_action(step: str) -> str | None:
    """Map a remediation sentence to an executable action."""
    s = step.lower()
    if "sign-in" in s or "sign in" in s or "disable" in s or "block" in s:
        return "block_signin"
    if "revoke" in s and ("token" in s or "session" in s or "grant" in s):
        return "revoke_token"
    if "assignment" in s or "remove" in s or "revoke consent" in s:
        return "remove_assignment"
    if "review" in s or "confirm" in s or "enforce" in s or "rotate" in s or "restrict" in s:
        return None  # paperwork steps: not executed, logged as manual
    return None


@app.command()
def report(
    last: Annotated[bool, typer.Option("--last", help="Re-render the last saved scan (no re-scan)")] = False,
    compare: Annotated[bool, typer.Option("--compare", help="Show trend between last two scans")] = False,
    tenant_id: Annotated[str | None, typer.Option("--tenant", help="Tenant ID to filter saved scans by")] = None,
    out_dir: Annotated[str, typer.Option("--out", help="Report output directory")] = ".",
) -> None:
    """Re-render a previously saved scan without re-scanning the tenant."""
    from .store import load_last_scan, load_last_two_scans

    if compare:
        from .compare import compare_scans, render_trend_table

        rows = load_last_two_scans(tenant_id)
        if len(rows) < 2:
            typer.secho("Need at least two saved scans to compare. Run `offboard audit` twice.", fg=typer.colors.RED)
            raise typer.Exit(1)
        past, present = rows[1], rows[0]
        deltas = compare_scans(past, present)
        typer.echo(render_trend_table(past, present, deltas))
        return

    if not last:
        typer.echo("Usage: offboard report --last | --compare")
        raise typer.Exit(1)

    row = load_last_scan(tenant_id)
    if row is None:
        typer.secho("No saved scans found. Run `offboard audit` first.", fg=typer.colors.RED)
        raise typer.Exit(1)

    from .audit.risk import Finding
    from .connectors.base import TenantSnapshot

    findings = [
        Finding(
            rule_id=f["rule_id"],
            severity=f["severity"],
            subject=f["subject"],
            evidence=f["evidence"],
            remediation=list(f.get("remediation", [])),
        )
        for f in __import__("json").loads(row["findings_json"])
    ]
    snapshot = TenantSnapshot(
        tenant_id=row["tenant_id"],
        scanned_at=row["scanned_at"],
    )
    md_path, html_path = write_report(
        __import__("types").SimpleNamespace(
            snapshot=snapshot,
            findings=findings,
            report_md=row["report_md"],
            report_html=row["report_html"],
        ),
        out_dir,
    )
    typer.echo(f"  {md_path}")
    typer.echo(f"  {html_path}")


# ---- AI access policy sub-commands ----

_policy_app = typer.Typer()
app.add_typer(_policy_app, name="policy", help="AI access policy engine: evaluate connected AI access against policy.")


@_policy_app.command("list")
def policy_list() -> None:
    """List the available checks and the bundled default policies."""
    from . import policy

    typer.secho("Available policy checks:", fg=typer.colors.CYAN, bold=True)
    for check in policy.list_checks():
        typer.echo(f"  - {check}")
    typer.secho("Bundled default policies:", fg=typer.colors.CYAN, bold=True)
    for p in policy.load_policies():
        default = " (default)" if p.default else ""
        typer.echo(f"  [{p.id}] {p.name} - severity: {p.severity}{default}")


@_policy_app.command("check")
def policy_check(
    tenant_id: Annotated[str | None, typer.Option("--tenant", help="Tenant ID (defaults to auth)")] = None,
    mock: Annotated[bool, typer.Option("--mock", help="Use a demo snapshot (no Azure needed)")] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit results as JSON (stdout)")] = False,
) -> None:
    """Scan the tenant, evaluate the policy set, and report compliance."""
    _load_env()
    cfg = load_config()
    try:
        connector = _pick_connector(mock, cfg, prefer_device_code=True)
    except RuntimeError as exc:
        typer.secho(str(exc), fg=typer.colors.RED)
        raise typer.Exit(1) from exc

    tid = tenant_id or _resolve_tenant_id(cfg) if not mock else "demo"
    result = run_scan(connector, tid, save=True)

    from . import policy

    evaluations = policy.evaluate(result.snapshot, result.findings)
    summary = policy.summarize(evaluations)

    if json_output:
        import json as _json

        typer.echo(
            _json.dumps(
                {
                    "tenant_id": tid,
                    "scanned_at": result.snapshot.scanned_at,
                    "summary": summary,
                    "evaluations": [e.to_dict() for e in evaluations],
                },
                indent=2,
            )
        )
        raise typer.Exit(0 if summary["overall"] == "PASS" else 2)

    color = typer.colors.GREEN if summary["overall"] == "PASS" else typer.colors.RED
    typer.secho(f"Policy compliance: {summary['overall']} ({summary['compliant']}/{summary['total']} passing)", fg=color, bold=True)
    for e in evaluations:
        mark = "[PASS]" if e.compliant else "[FAIL]"
        c = typer.colors.GREEN if e.compliant else typer.colors.RED
        typer.secho(f"  {mark} {e.policy.id} {e.policy.name} ({e.policy.severity})", fg=c)
        for line in e.evidence:
            typer.echo(f"        {line}")
    raise typer.Exit(0 if summary["overall"] == "PASS" else 2)


@app.command()
def web(
    port: Annotated[int, typer.Option("--port", help="Port to serve on")] = 8600,
    host: Annotated[str, typer.Option("--host", help="Bind address; loopback is the safe default")] = "127.0.0.1",
) -> None:
    """Open the web UI. Remote binding requires OFFBOARD_WEB_TOKEN."""
    from .web import run_server  # import here so setup/audit don't need deps

    try:
        run_server(port=port, host=host)
    except RuntimeError as exc:
        typer.secho(str(exc), fg=typer.colors.RED)
        raise typer.Exit(1) from exc


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
            if not hasattr(conn, "_auth"):  # mock: nothing to verify
                auth_ok = True
                auth_msg = "mock connector"
            else:
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