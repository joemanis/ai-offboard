"""In-memory connector for tests and the local web UI demo.

Returns a deterministic TenantSnapshot without any network access.
"""
from __future__ import annotations

from .base import AppAssignment, Connector, Principal, TenantSnapshot


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
                Principal(id="u2", name="stale@example.com", type="user", enabled=False, mfa_state=None),
                Principal(id="u3", name="nomfa@example.com", type="user", enabled=True, mfa_state="not_registered"),
            ],
            app_assignments=[
                AppAssignment(principal_id="u1", app_display_name="Microsoft 365 Copilot", is_high_privilege=True),
                AppAssignment(principal_id="u3", app_display_name="SomeMarketingTool", is_high_privilege=False),
            ],
        )

    def snapshot(self, tenant_id: str) -> TenantSnapshot:
        return self._tenants[tenant_id]
