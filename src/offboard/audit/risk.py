"""Risk rules -> findings.

Each rule inspects a TenantSnapshot (plus catalog matches) and yields Findings
with severity + remediation steps. Read-only, pure functions for testability.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..catalog.matcher import CatalogEntry, match_app
from ..connectors.base import AppAssignment, Principal, TenantSnapshot


@dataclass
class Finding:
    rule_id: str
    severity: str  # low | medium | high | critical
    subject: str
    evidence: str
    remediation: list[str]


def disabled_stale_user(finding: Finding) -> None:
    ...


def rule_stale_access(principal: Principal) -> Finding | None:
    """Rule 1: disabled/inactive-looking users flagged (enriched by scanner)."""
    # v1: mark disabled accounts still referenced; full sign-in heuristics
    # require the signInActivity enrichment wired in scanner.
    if not principal.enabled:
        return Finding(
            rule_id="R1",
            severity="medium",
            subject=principal.name,
            evidence=f"Account '{principal.name}' is disabled in directory.",
            remediation=["Confirm no durable app assignments remain.", "Revoke tokens/SSO sessions."],
        )
    return None


def rule_mfa_gap(principal: Principal) -> Finding | None:
    """Rule 2: account enabled but MFA not enforced."""
    if principal.enabled and principal.mfa_state in (None, "not_registered"):
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
    return findings
