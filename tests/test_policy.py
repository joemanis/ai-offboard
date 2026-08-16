from __future__ import annotations

from offboard import policy
from offboard.audit.risk import run_rules
from offboard.connectors.base import AppAssignment, PermissionGrant, Principal, TenantSnapshot
from offboard.connectors.mock import MockConnector


def test_default_policies_load():
    policies = policy.load_policies()
    assert len(policies) >= 5
    ids = {p.id for p in policies}
    assert "ZT-001" in ids and "ZT-005" in ids


def test_registry_has_named_checks_only():
    checks = policy.list_checks()
    assert set(checks) >= {"stale_access", "mfa_enforced", "no_high_privilege_apps", "no_broad_grants", "unapproved_apps"}


def test_demo_tenant_fails_all():
    snap = MockConnector().snapshot("demo")
    findings = run_rules(snap)
    results = policy.evaluate(snap, findings)
    summary = policy.summarize(results)
    assert summary["overall"] == "FAIL"
    assert summary["violations"] == 5
    assert summary["by_severity"]["critical"] == 1  # ZT-005 allowlist


def test_clean_tenant_passes():
    """A tenant with no stale access, enforced MFA, no broad grants, and no
    AI app assignments should PASS every bundled policy (the allowlist is
    default-deny, so a tenant with zero assigned apps is fully compliant)."""
    snap = TenantSnapshot(
        tenant_id="clean",
        scanned_at="2026-08-01T00:00:00Z",
        principals=[
            Principal(id="p1", name="alice@clean.test", type="user", enabled=True, mfa_state="enforced"),
        ],
        permission_grants=[
            PermissionGrant(app_id="a1", resource="graph", scope="user.read", grant_type="delegated"),
        ],
    )
    results = policy.evaluate(snap)
    summary = policy.summarize(results)
    assert summary["overall"] == "PASS"
    assert summary["violations"] == 0


def test_unapproved_app_fails_allowlist(tmp_path):
    """ZT-005 is a default-deny: an app not on the approved list fails even
    if it's otherwise low-risk."""
    snap = TenantSnapshot(
        tenant_id="t",
        scanned_at="2026-08-01T00:00:00Z",
        principals=[Principal(id="p1", name="u@t.test", type="user", enabled=True, mfa_state="enforced")],
        app_assignments=[AppAssignment(principal_id="p1", app_display_name="Fireflies.ai")],
    )
    results = policy.evaluate(snap)
    allowlist = [r for r in results if r.policy.id == "ZT-005"]
    assert len(allowlist) == 1
    assert allowlist[0].compliant is False
    assert "Fireflies.ai" in allowlist[0].subjects


def test_unknown_check_reported_not_crashed(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("policies:\n  - id: ZT-999\n    name: Broken\n    check: does_not_exist\n", encoding="utf-8")
    snap = MockConnector().snapshot("demo")
    results = policy.evaluate(snap, policies=policy.load_policies(bad))
    assert results[0].compliant is False
    assert "Unknown check" in results[0].evidence[0]