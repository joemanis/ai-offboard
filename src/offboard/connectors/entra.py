"""Microsoft Entra ID connector (read-only, v1).

The connector is auth-agnostic: it takes any AuthProvider (client credentials
for CI/service accounts, or device-code for interactive Global Admin login)
and issues GET-only Graph calls. See docs/connectors.md for setup.
"""
from __future__ import annotations

import requests

from ..auth import GRAPH_ROOT, AuthProvider
from .base import Connector, Principal, TenantSnapshot


class EntraConnector(Connector):
    """Scan a Microsoft 365 / Entra tenant."""

    def __init__(self, auth: AuthProvider) -> None:
        self._auth_provider = auth
        self._access_token: str | None = None

    def _auth(self) -> str:
        """Return a valid access token (cached per-instance)."""
        if not self._access_token:
            self._access_token = self._auth_provider.authenticate().token
        return self._access_token

    def test_auth(self) -> bool:
        """Acquire a token to validate credentials. Returns True on success.

        Raises on failure so callers (setup wizard) can surface the cause.
        """
        self._auth()
        return True

    def get_tenant_id(self) -> str:
        """Resolve the tenant id from the current auth (no user input needed)."""
        if self._access_token:
            from ..auth import _tenant_from_token

            tid = _tenant_from_token(self._access_token)
            if tid:
                return tid
        result = self._auth_provider.authenticate()
        return result.tenant_id

    def _get(self, path: str, params: dict | None = None) -> dict:
        url = f"{GRAPH_ROOT}{path}"
        headers = {"Authorization": f"Bearer {self._auth()}"}
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def snapshot(self, tenant_id: str | None = None) -> TenantSnapshot:
        """Scan the tenant. If tenant_id is omitted, resolve it from auth."""
        # Resolve tenant from the *access token itself* when not provided.
        tid = tenant_id or self.get_tenant_id()
        principals = self._users()
        return TenantSnapshot(tenant_id=tid or "", scanned_at="", principals=principals)

    def _users(self) -> list[Principal]:
        data = self._get("/users", {"$select": "id,displayName,userPrincipalName,accountEnabled"})
        out = []
        for u in data.get("value", []):
            out.append(
                Principal(
                    id=u["id"],
                    name=u.get("userPrincipalName", u.get("displayName", "")),
                    type="user",
                    enabled=bool(u.get("accountEnabled", True)),
                )
            )
        return out