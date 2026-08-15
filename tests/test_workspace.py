from __future__ import annotations

from offboard.connectors.mock_workspace import MockWorkspaceConnector
from offboard.scan import run_scan


def test_workspace_snapshot_mapping():
    conn = MockWorkspaceConnector()
    snap = conn.snapshot("acme.test")
    assert len(snap.principals) == 3
    assert snap.principals[0].name == "alice@acme.test"
    assert snap.principals[0].enabled is True
    # Carol has no 2SV fields -> mfa_state None
    assert snap.principals[2].mfa_state is None
    # 2+1+2 grants = 5 app assignments + 5 grants
    assert len(snap.app_assignments) == 5
    assert len(snap.permission_grants) == 5
    display_names = {a.app_display_name for a in snap.app_assignments}
    assert "ChatGPT Enterprise" in display_names
    assert "Zapier AI" in display_names


def test_workspace_scan_produces_findings():
    """Full pipeline: Workspace snapshot -> catalog match -> risk rules."""
    conn = MockWorkspaceConnector()
    result = run_scan(conn, "acme.test")
    rule_ids = {f.rule_id for f in result.findings}
    # R1 stale sign-in: carol last logged in Jan 2025
    assert "R1" in rule_ids
    # R2 MFA gap: bob has no 2FA
    assert "R2" in rule_ids
    # R4: ChatGPT Enterprise / Fireflies are high-reach AI grants
    assert "R4" in rule_ids
    # R5: Zapier grant requests mail + drive scopes (broad)
    assert "R5" in rule_ids
    assert len(result.findings) >= 4


def test_workspace_progress_callback():
    conn = MockWorkspaceConnector()
    seen: list[str] = []
    conn.snapshot("acme.test", progress_callback=seen.append)
    assert any("Fetching Workspace users" in s for s in seen)