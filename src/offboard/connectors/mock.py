"""In-memory connector for tests and the local web UI demo.

Returns a deterministic TenantSnapshot without any network access.
Includes users, service principals (enterprise AI apps), and OAuth
permission grants so the full scan pipeline exercises all risk rules.
"""
from __future__ import annotations

from .base import AppAssignment, Connector, PermissionGrant, Principal, TenantSnapshot


class MockConnector(Connector):
    """A fixed, deterministic snapshot used for tests and demos."""

    def __init__(self, tenants: dict[str, TenantSnapshot] | None = None) -> None:
        self._tenants = tenants or {"demo": self._demo_snapshot()}

    @staticmethod
    def _demo_snapshot() -> TenantSnapshot:
        return TenantSnapshot(
            tenant_id="demo",
            scanned_at="2026-01-01T00:00:00Z",
            principals=[
                Principal(id="u1", name="active@example.com", type="user", enabled=True, mfa_state="registered"),
                Principal(id="u2", name="stale@example.com", type="user", enabled=False, mfa_state=None, sign_in_last_seen="2025-06-15T00:00:00Z"),
                Principal(id="u3", name="nomfa@example.com", type="user", enabled=True, mfa_state="not_registered"),
            ],
            # Service Principals are mapped as AppAssignments (enterprise apps).
            # The catalog matcher in scan.py will pick up Copilot and ChatGPT
            # as AI tools, while Some Internal App goes unmatched.
            app_assignments=[
                AppAssignment(principal_id="u1", app_display_name="Microsoft 365 Copilot", is_high_privilege=True),
                AppAssignment(principal_id="u3", app_display_name="ChatGPT Enterprise", is_high_privilege=False),
                AppAssignment(principal_id="u1", app_display_name="SomeInternalApp", is_high_privilege=False),
            ],
            # OAuth permission grants — delegated scopes consented to apps
            permission_grants=[
                PermissionGrant(app_id="copilot-guid", resource="https://graph.microsoft.com", scope="Mail.Read Mail.Send Files.Read.All", grant_type="delegated"),
                PermissionGrant(app_id="salesforce-guid", resource="https://api.salesforce.com", scope="user_impersonation", grant_type="delegated"),
            ],
        )

    def snapshot(self, tenant_id: str) -> TenantSnapshot:
        return self._tenants[tenant_id]