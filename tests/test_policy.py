from __future__ import annotations

from offboard import policy
from offboard.audit.risk import run_rules
from offboard.connectors.base import AppAssignment, PermissionGrant, Principal, TenantSnapshot
from offboard.connectors.mock import MockConnector


def test_default_policies_load():
    policies = policy.load_policies()
    assert len(policies) == 4
    ids = {p.id for p in policies}
    assert ids == {"AI-001", "AI-002", "AI-003", "AI-004"}


def test_registry_has_named_checks_only():
    checks = policy.list_checks()
    assert set(checks) >= {"stale_access", "no_high_privilege_apps", "no_broad_grants", "unapproved_apps"}


def test_demo_tenant_fails_all():
    snap = MockConnector().snapshot("demo")
    findings = run_rules(snap)
    results = policy.evaluate(snap, findings)
    summary = policy.summarize(results)
    assert summary["overall"] == "FAIL"
    assert summary["violations"] == 4
    assert summary["not_assessed"] == 0
    assert summary["by_severity"]["critical"] == 1  # AI-004 allowlist


def test_clean_tenant_passes():
    """A tenant with no disabled accounts, no broad grants, and no AI app assignments passes."""
    snap = TenantSnapshot(
        tenant_id="clean",
        scanned_at="2026-08-01T00:00:00Z",
        principals=[Principal(id="p1", name="alice@clean.test", type="user", enabled=True)],
        permission_grants=[
            PermissionGrant(app_id="a1", resource="graph", scope="user.read", grant_type="delegated"),
        ],
    )
    results = policy.evaluate(snap)
    summary = policy.summarize(results)
    assert summary["overall"] == "PASS"
    assert summary["violations"] == 0


def test_ai003_excludes_ai_offboard_but_not_other_broad_grants():
    """The scanner's own required grant is absent from findings, while customer apps still fail."""
    snap = TenantSnapshot(
        tenant_id="t",
        scanned_at="2026-08-01T00:00:00Z",
        permission_grants=[
            PermissionGrant(
                app_id="self-client",
                app_display_name="ai-offboard",
                resource="https://graph.microsoft.com",
                scope="Mail.Read Files.Read.All",
                grant_type="delegated",
            ),
            PermissionGrant(
                app_id="other-client",
                app_display_name="ChatGPT Enterprise",
                resource="https://graph.microsoft.com",
                scope="Mail.Read Files.Read.All",
                grant_type="delegated",
            ),
        ],
    )

    findings = run_rules(snap)
    assert [finding.subject for finding in findings if finding.rule_id == "R5"] == ["ChatGPT Enterprise"]
    ai003 = next(result for result in policy.evaluate(snap, findings) if result.policy.id == "AI-003")

    assert ai003.compliant is False
    assert ai003.subjects == ["ChatGPT Enterprise"]
    assert "ai-offboard" not in " ".join(ai003.subjects)


def test_ai003_passes_with_only_ai_offboard_broad_grant():
    snap = TenantSnapshot(
        tenant_id="t",
        scanned_at="2026-08-01T00:00:00Z",
        permission_grants=[
            PermissionGrant(
                app_id="self-client",
                app_display_name="AI-Offboard",
                resource="https://graph.microsoft.com",
                scope="Mail.Read Files.Read.All",
                grant_type="delegated",
            ),
        ],
    )

    findings = run_rules(snap)
    ai003 = next(result for result in policy.evaluate(snap, findings) if result.policy.id == "AI-003")

    assert ai003.compliant is True
    assert not any(finding.rule_id == "R5" for finding in findings)


def test_ai003_ignores_non_ai_business_grant():
    snap = TenantSnapshot(
        tenant_id="t",
        scanned_at="2026-08-01T00:00:00Z",
        permission_grants=[
            PermissionGrant(
                app_id="business-client",
                app_display_name="SharePoint Online Web Client Extensibility",
                resource="https://graph.microsoft.com",
                scope="Mail.Read Files.Read.All",
                grant_type="delegated",
            ),
        ],
    )

    findings = run_rules(snap)
    ai003 = next(result for result in policy.evaluate(snap, findings) if result.policy.id == "AI-003")

    assert ai003.compliant is True
    assert not any(finding.rule_id == "R5" for finding in findings)


def test_unapproved_app_fails_allowlist(tmp_path):
    # AI-004 is a default-deny allowlist: an app not on the approved list fails even
    # if it's otherwise low-risk.
    snap = TenantSnapshot(
        tenant_id="t",
        scanned_at="2026-08-01T00:00:00Z",
        principals=[Principal(id="p1", name="u@t.test", type="user", enabled=True)],
        app_assignments=[AppAssignment(principal_id="p1", app_display_name="Fireflies.ai")],
    )
    results = policy.evaluate(snap)
    allowlist = [r for r in results if r.policy.id == "AI-004"]
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