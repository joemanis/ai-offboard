"""Risk rules -> findings.

Each rule inspects a TenantSnapshot (plus catalog matches) and yields Findings
with severity + remediation steps. Read-only, pure functions for testability.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..catalog.matcher import CatalogEntry, match_app
from ..connectors.base import AppAssignment, PermissionGrant, Principal, TenantSnapshot


@dataclass
class Finding:
    rule_id: str
    severity: str  # low | medium | high | critical
    subject: str
    evidence: str
    remediation: list[str]


def disabled_stale_user(finding: Finding) -> None:
    ...


# Scopes that, when granted, let an app reach broad tenant data.
# Both Graph-style short names and Google OAuth URL forms are matched
# (see _normalize_scope).
HIGH_PRIVILEGE_SCOPES = frozenset(
    {
        "mail.read",
        "mail.send",
        "mail",
        "mail.readonly",
        "files.read.all",
        "files.readwrite.all",
        "files",
        "drive",
        "docs",
        "directory.readwrite.all",
        "directory.readonly",
        "user.read.all",
        "group.read.all",
        "subscribedskus.read.all",
        "channel.read.all",
        "admin.directory.user.readonly",
        "admin.directory.group.readonly",
    }
)

# The scanner necessarily grants itself read-only Graph access to inventory
# the tenant. Keep that grant in the raw snapshot, but never turn it into a
# customer-facing broad-grant finding.
SELF_APP_DISPLAY_NAMES = frozenset({"ai-offboard"})


def _normalize_scope(scope: str) -> str:
    """Reduce a scope to a comparable key.

    Google OAuth URLs like
    https://www.googleapis.com/auth/mail.readonly become "mail.readonly";
    Graph short names like "Mail.Read" become "mail.read".
    """
    key = scope.strip().lower()
    if "googleapis.com/auth/" in key:
        key = key.rsplit("/auth/", 1)[1]
    key = key.rstrip("/")
    return key


def rule_stale_access(principal: Principal, assignments: list[AppAssignment]) -> Finding | None:
    """Rule 1: a disabled account retains a connected AI app assignment."""
    retained = [assignment for assignment in assignments if assignment.principal_id == principal.id]
    if not principal.enabled and retained:
        app_names = sorted({assignment.app_display_name for assignment in retained})
        return Finding(
            rule_id="R1",
            severity="medium",
            subject=principal.name,
            evidence=(
                f"Account '{principal.name}' is disabled in directory and retains connected AI app assignments: "
                f"{', '.join(app_names)}."
            ),
            remediation=[
                "Review and remove the listed AI app assignments.",
                "Revoke connected-app tokens or sessions where supported.",
            ],
        )
    return None


def rule_high_privilege_app(
    assignment: AppAssignment, catalog_entry: CatalogEntry | None
) -> Finding | None:
    """Rule 4: catalog-matched AI app with a real active assignment."""
    if assignment.is_high_privilege or (catalog_entry and catalog_entry.dlp_tier == "high"):
        app_name = catalog_entry.name if catalog_entry else assignment.app_display_name
        principal = assignment.principal_display_name or assignment.principal_id or "unknown principal"
        role = f" role '{assignment.role_display_name}'" if assignment.role_display_name else ""
        return Finding(
            rule_id="R4",
            severity="high",
            subject=assignment.app_display_name,
            evidence=f"AI app '{app_name}' is assigned to '{principal}'{role}.",
            remediation=[
                "Review the assigned role scope.",
                "Remove assignment for departed/durable principals.",
                "Confirm least-privilege on the service principal.",
            ],
        )
    return None


def rule_high_privilege_grant(
    grant: PermissionGrant, catalog_entry: CatalogEntry | None
) -> Finding | None:
    """Rule 5: a catalog-matched AI app requests sensitive scopes."""
    if (grant.app_display_name or "").strip().casefold() in SELF_APP_DISPLAY_NAMES:
        return None
    # Sensitive scopes are not proof that the client is an AI application.
    # Keep all grants in the raw snapshot, but only emit the AI-specific risk
    # finding when the client is recognized by the reviewed AI catalog.
    if catalog_entry is None:
        return None
    granted = {_normalize_scope(s) for s in grant.scope.split(" ") if s.strip()}
    hits = sorted(granted & HIGH_PRIVILEGE_SCOPES)
    if hits:
        app_name = grant.app_display_name or f"Unknown app (Graph identifier {grant.app_id[:8]})"
        resource_name = grant.resource_display_name or grant.resource or "unknown resource"
        kind = "Application permission" if grant.grant_type == "application" else "Delegated grant"
        consent = f" ({grant.consent_type} consent)" if grant.consent_type else ""
        return Finding(
            rule_id="R5",
            severity="high",
            subject=app_name,
            evidence=f"{kind} for '{app_name}' against '{resource_name}'{consent} requests sensitive scopes: {', '.join(hits)}.",
            remediation=[
                "Review the consent from the tenant admin perspective.",
                "Restrict to least-privilege scopes.",
                "Revoke consent / block the app if not business-required.",
            ],
        )
    return None


def run_rules(snapshot: TenantSnapshot, apps: list[dict] | None = None) -> list[Finding]:
    """Evaluate all rules over a snapshot. Pure; no I/O beyond catalog read."""
    findings: list[Finding] = []
    for p in snapshot.principals:
        f = rule_stale_access(p, snapshot.app_assignments)
        if f:
            findings.append(f)
    for a in snapshot.app_assignments:
        catalog_entry = match_app(a.app_display_name, apps)
        f = rule_high_privilege_app(a, catalog_entry)
        if f:
            findings.append(f)
    seen_grants: set[tuple[str, str, str, str]] = set()
    for g in snapshot.permission_grants:
        key = (g.app_id, g.resource, " ".join(sorted(g.scope.lower().split())), g.grant_type)
        if key in seen_grants:
            continue
        seen_grants.add(key)
        catalog_entry = match_app(g.app_display_name, apps)
        f = rule_high_privilege_grant(g, catalog_entry)
        if f:
            findings.append(f)
    return findings
