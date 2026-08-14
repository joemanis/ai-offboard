from __future__ import annotations

from offboard.audit.risk import (
    Finding,
    rule_high_privilege_app,
    rule_mfa_gap,
    rule_stale_access,
    run_rules,
)
from offboard.catalog.matcher import CatalogEntry, match_app
from offboard.connectors.base import AppAssignment, Principal, TenantSnapshot
from offboard.plan.planner import plan_for_finding


def test_match_app_high_tier():
    entry = match_app("Microsoft 365 Copilot Service", [{"name": "MSFT Copilot", "matches": ["copilot"], "dlp_tier": "high", "notes": ""}])
    assert entry is not None
    assert entry.dlp_tier == "high"


def test_match_app_none_when_unmatched():
    assert match_app("Totally Unknown Tool", []) is None


def test_stale_disabled_finding():
    f = rule_stale_access(Principal(id="1", name="old@x.com", type="user", enabled=False))
    assert f is not None and f.rule_id == "R1"


def test_mfa_gap_finding():
    f = rule_mfa_gap(Principal(id="2", name="u@x.com", type="user", enabled=True, mfa_state="not_registered"))
    assert f is not None and f.severity == "high"


def test_high_priv_app_finding():
    f = rule_high_privilege_app(AppAssignment(principal_id="1", app_display_name="Copilot", is_high_privilege=True), CatalogEntry("Copilot", "high", ""))
    assert f is not None


def test_plan_is_dry_run_no_risky_unescaped():
    f = Finding(rule_id="R1", severity="medium", subject="u@x.com", evidence="", remediation=[])
    steps = plan_for_finding(f)
    assert steps and all(s.risky for s in steps)


def test_run_rules_end_to_end():
    snap = TenantSnapshot(
        tenant_id="t",
        scanned_at="",
        principals=[Principal(id="1", name="a", type="user", enabled=True, mfa_state=None)],
        app_assignments=[AppAssignment(principal_id="1", app_display_name="Copilot", is_high_privilege=True)],
    )
    findings = run_rules(snap)
    assert any(f.rule_id == "R2" for f in findings)
    assert any(f.rule_id == "R4" for f in findings)
