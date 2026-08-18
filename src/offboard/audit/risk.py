"""Risk rules -> findings.

Each rule inspects a TenantSnapshot (plus catalog matches) and yields Findings
with severity + remediation steps. Read-only, pure functions for testability.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC

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


def rule_stale_access(principal: Principal, no_signin_days: int = 90) -> Finding | None:
    """Rule 1: disabled accounts, or enabled accounts with no recent sign-in."""
    from datetime import datetime

    if not principal.enabled:
        return Finding(
            rule_id="R1",
            severity="medium",
            subject=principal.name,
            evidence=f"Account '{principal.name}' is disabled in directory.",
            remediation=["Confirm no durable app assignments remain.", "Revoke tokens/SSO sessions."],
        )
    if principal.sign_in_last_seen:
        try:
            last = datetime.fromisoformat(principal.sign_in_last_seen)
            now = datetime.now(UTC)
            days = (now - last).days
            if days >= no_signin_days:
                return Finding(
                    rule_id="R1",
                    severity="medium",
                    subject=principal.name,
                    evidence=f"Account '{principal.name}' has not signed in for {days} days (>= {no_signin_days}).",
                    remediation=[
                        "Review whether the account is still needed.",
                        "Consider license removal / access revocation.",
                    ],
                )
        except ValueError:
            pass  # unparseable date: skip heuristic
    return None


def rule_mfa_gap(principal: Principal) -> Finding | None:
    """Rule 2: account enabled and explicitly reported as not MFA-registered.

    ``None`` means the connector did not collect MFA state. Unknown is not the
    same thing as a confirmed MFA gap, so missing telemetry is skipped here.
    """
    if principal.enabled and principal.mfa_state == "not_registered":
        return Finding(
            rule_id="R2",
            severity="high",
            subject=principal.name,
            evidence=f"Account '{principal.name}' lacks enforced MFA registration.",
            remediation=["Enforce MFA for the account.", "Rotate credentials if a breach is suspected."],
        )
    return None


def rule_high_privilege_app(
    assignment: AppAssignment, catalog_entry: CatalogEntry | None
) -> Finding | None:
    """Rule 4: high-tier app with broad/privileged assignment."""
    if assignment.is_high_privilege or (catalog_entry and catalog_entry.dlp_tier == "high"):
        app_name = catalog_entry.name if catalog_entry else assignment.app_display_name
        return Finding(
            rule_id="R4",
            severity="high",
            subject=f"{assignment.app_display_name}",
            evidence=f"High-privilege app '{app_name}' has an active assignment.",
            remediation=[
                "Review the assigned role scope.",
                "Remove assignment for departed/durable principals.",
                "Confirm least-privilege on the service principal.",
            ],
        )
    return None


def rule_high_privilege_grant(grant: PermissionGrant) -> Finding | None:
    """Rule 5: OAuth grant requesting sensitive delegated scopes."""
    granted = {_normalize_scope(s) for s in grant.scope.split(" ") if s.strip()}
    hits = sorted(granted & HIGH_PRIVILEGE_SCOPES)
    if hits:
        return Finding(
            rule_id="R5",
            severity="high",
            subject=f"app {grant.app_id[:8]}",
            evidence=f"Delegated grant requests sensitive scopes: {', '.join(hits)}.",
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
        for f in (rule_stale_access(p), rule_mfa_gap(p)):
            if f:
                findings.append(f)
    for a in snapshot.app_assignments:
        catalog_entry = match_app(a.app_display_name, apps)
        f = rule_high_privilege_app(a, catalog_entry)
        if f:
            findings.append(f)
    for g in snapshot.permission_grants:
        f = rule_high_privilege_grant(g)
        if f:
            findings.append(f)
    return findings
