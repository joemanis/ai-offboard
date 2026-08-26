from __future__ import annotations

from offboard.connectors.mock_workspace import MockWorkspaceConnector
from offboard.scan import run_scan


def test_workspace_snapshot_mapping():
    conn = MockWorkspaceConnector()
    snap = conn.snapshot("acme.test")
    assert len(snap.principals) == 3
    assert snap.principals[0].name == "alice@acme.test"
    assert snap.principals[0].enabled is True
    # Identity posture is outside the core snapshot.
    # 2+1+2 grants = 5 app assignments + 5 grants
    assert len(snap.app_assignments) == 5
    assert len(snap.permission_grants) == 5
    display_names = {a.app_display_name for a in snap.app_assignments}
    assert "ChatGPT Enterprise" in display_names
    assert "Zapier AI" in display_names
    grant_names = {g.app_display_name for g in snap.permission_grants}
    assert "Zapier AI" in grant_names


def test_workspace_scan_produces_findings():
    """Full pipeline: Workspace snapshot -> catalog match -> risk rules."""
    conn = MockWorkspaceConnector()
    result = run_scan(conn, "acme.test")
    rule_ids = {f.rule_id for f in result.findings}
    # Disabled-account access remains core; last-login heuristics do not.
    assert "R1" not in rule_ids
    # R4: ChatGPT Enterprise / Fireflies are high-reach AI grants
    assert "R4" in rule_ids
    # R5: Zapier AI grant requests mail + drive scopes (broad)
    assert "R5" in rule_ids
    assert len(result.findings) >= 3


def test_workspace_non_ai_broad_grant_stays_inventory_only():
    class BusinessAppWorkspaceConnector(MockWorkspaceConnector):
        def _fetch_user_tokens(self, user_key: str) -> list[dict]:
            tokens = super()._fetch_user_tokens(user_key)
            if user_key == "alice@acme.test":
                tokens.append(
                    {
                        "clientId": "business-client",
                        "displayText": "SharePoint Online Web Client Extensibility",
                        "scopes": ["https://www.googleapis.com/auth/mail", "https://www.googleapis.com/auth/drive"],
                        "nativeApp": False,
                    }
                )
            return tokens

    result = run_scan(BusinessAppWorkspaceConnector(), "acme.test")

    assert any(g.app_display_name == "SharePoint Online Web Client Extensibility" for g in result.snapshot.permission_grants)
    assert not any(
        finding.rule_id == "R5" and finding.subject == "SharePoint Online Web Client Extensibility"
        for finding in result.findings
    )


def test_workspace_progress_callback():
    conn = MockWorkspaceConnector()
    seen: list[str] = []
    conn.snapshot("acme.test", progress_callback=seen.append)
    assert any("Fetching Workspace users" in s for s in seen)