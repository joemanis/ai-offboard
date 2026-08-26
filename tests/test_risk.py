from __future__ import annotations

from offboard.audit.risk import (
    Finding,
    rule_high_privilege_app,
    rule_high_privilege_grant,
    rule_stale_access,
    run_rules,
)
from offboard.catalog.matcher import CatalogEntry, match_app
from offboard.connectors.base import AppAssignment, PermissionGrant, Principal, TenantSnapshot
from offboard.connectors.entra import EntraConnector
from offboard.plan.planner import plan_for_finding


def test_match_app_high_tier():
    entry = match_app("Microsoft 365 Copilot Service", [{"name": "MSFT Copilot", "matches": ["copilot"], "dlp_tier": "high", "notes": ""}])
    assert entry is not None
    assert entry.dlp_tier == "high"


def test_match_app_none_when_unmatched():
    assert match_app("Totally Unknown Tool", []) is None


def test_match_app_none_name_is_unmatched():
    assert match_app(None, [{"name": "Copilot", "matches": ["copilot"], "dlp_tier": "high", "notes": ""}]) is None


def test_stale_disabled_finding():
    f = rule_stale_access(
        Principal(id="1", name="old@x.com", type="user", enabled=False),
        [AppAssignment(principal_id="1", app_display_name="ChatGPT Enterprise")],
    )
    assert f is not None and f.rule_id == "R1"
    assert "ChatGPT Enterprise" in f.evidence


def test_disabled_user_without_ai_assignment_is_not_stale_access():
    principal = Principal(id="1", name="old@x.com", type="user", enabled=False)

    assert rule_stale_access(principal, []) is None


def test_disabled_user_with_another_users_assignment_is_not_stale_access():
    principal = Principal(id="1", name="old@x.com", type="user", enabled=False)
    assignments = [AppAssignment(principal_id="2", app_display_name="ChatGPT Enterprise")]

    assert rule_stale_access(principal, assignments) is None


def test_high_priv_app_finding():
    f = rule_high_privilege_app(AppAssignment(principal_id="1", app_display_name="Copilot", is_high_privilege=True), CatalogEntry("Copilot", "high", ""))
    assert f is not None


def test_broad_grant_fallback_labels_unresolved_graph_identifier():
    grant = PermissionGrant(
        app_id="26300ba6-full-identifier",
        resource="graph",
        scope="Mail.Read",
        grant_type="delegated",
    )

    finding = rule_high_privilege_grant(grant, CatalogEntry("Unknown app", "medium", ""))

    assert finding is not None
    assert finding.subject == "Unknown app (Graph identifier 26300ba6)"


def test_scanner_own_broad_grant_is_not_a_finding():
    grant = PermissionGrant(
        app_id="self-client",
        app_display_name="AI-Offboard",
        resource="Microsoft Graph",
        scope="Group.Read.All User.Read.All",
        grant_type="delegated",
    )

    assert rule_high_privilege_grant(grant, CatalogEntry("AI-Offboard", "high", "")) is None


def test_broad_grant_for_known_ai_app_is_a_finding():
    grant = PermissionGrant(
        app_id="copilot-client",
        app_display_name="Microsoft 365 Copilot",
        resource="Microsoft Graph",
        scope="Mail.Read Files.Read.All",
        grant_type="delegated",
    )

    finding = rule_high_privilege_grant(grant, match_app(grant.app_display_name))

    assert finding is not None
    assert finding.subject == "Microsoft 365 Copilot"


def test_broad_grant_for_non_ai_business_app_is_not_a_finding():
    grant = PermissionGrant(
        app_id="sharepoint-client",
        app_display_name="SharePoint Online Web Client Extensibility",
        resource="Microsoft Graph",
        scope="Mail.Read Files.Read.All",
        grant_type="delegated",
    )

    assert rule_high_privilege_grant(grant, match_app(grant.app_display_name)) is None


def test_broad_grant_for_unknown_app_is_not_an_ai_finding():
    grant = PermissionGrant(
        app_id="unknown-client",
        app_display_name="Unrecognized Business Integration",
        resource="Microsoft Graph",
        scope="Mail.Read Files.Read.All",
        grant_type="delegated",
    )

    assert rule_high_privilege_grant(grant, match_app(grant.app_display_name)) is None


def test_plan_is_dry_run_no_risky_unescaped():
    f = Finding(rule_id="R1", severity="medium", subject="u@x.com", evidence="", remediation=[])
    steps = plan_for_finding(f)
    assert steps and all(s.risky for s in steps)


def test_unknown_app_is_not_high_privilege_by_default():
    assignment = AppAssignment(principal_id="1", app_display_name="Microsoft Intune")
    assert rule_high_privilege_app(assignment, None) is None


def test_entra_application_service_principal_is_not_privileged_by_type():
    assignment = EntraConnector._to_assignments(
        [{"id": "sp1", "appDisplayName": "Microsoft Intune", "servicePrincipalType": "Application"}],
        {"sp1": [{"principalId": "user1", "principalDisplayName": "u@x.com", "principalType": "User", "appRoleId": "role1"}]},
    )[0]
    assert assignment.is_high_privilege is False


def test_run_rules_end_to_end():
    snap = TenantSnapshot(
        tenant_id="t",
        scanned_at="",
        principals=[Principal(id="1", name="a", type="user", enabled=True)],
        app_assignments=[AppAssignment(principal_id="1", app_display_name="Copilot", is_high_privilege=True)],
    )
    findings = run_rules(snap)
    assert all(f.rule_id != "R2" for f in findings)
    assert any(f.rule_id == "R4" for f in findings)
