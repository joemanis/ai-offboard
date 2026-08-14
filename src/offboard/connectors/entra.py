"""Microsoft Entra ID connector (read-only, v1).

Authentication uses MSAL confidential-client flow. Reads are GET-only Graph
calls. See docs/connectors.md for required app registration and scopes.
"""
from __future__ import annotations

import os

import requests
from msal import ConfidentialClientApplication

from .base import Connector, Principal, TenantSnapshot

GRAPH_ROOT = "https://graph.microsoft.com/v1.0"


class EntraConnector(Connector):
    """Scan a Microsoft 365 / Entra tenant."""

    def __init__(self, client_id: str, client_secret: str, authority: str) -> None:
        self._app = ConfidentialClientApplication(
            client_id,
            client_secret=client_secret,
            authority=authority,
        )
        self._token: str | None = None

    @classmethod
    def from_env(cls) -> EntraConnector:
        """Build from OFFBOARD_* env vars (see docs/connectors.md)."""
        return cls(
            client_id=os.environ["OFFBOARD_CLIENT_ID"],
            client_secret=os.environ["OFFBOARD_CLIENT_SECRET"],
            authority=os.environ.get(
                "OFFBOARD_AUTHORITY", "https://login.microsoftonline.com/common"
            ),
        )

    def _auth(self) -> str:
        if self._token:
            return self._token
        scope = ["https://graph.microsoft.com/.default"]
        result = self._app.acquire_token_for_client(scopes=scope)
        if "access_token" not in result:
            raise RuntimeError(f"Auth failed: {result.get('error_description')}")
        self._token = result["access_token"]
        return self._token

    def test_auth(self) -> bool:
        """Acquire a token to validate credentials. Returns True on success.

        Raises on failure so callers (setup wizard) can surface the cause.
        """
        self._auth()
        return True

    def _get(self, path: str, params: dict | None = None) -> dict:
        url = f"{GRAPH_ROOT}{path}"
        headers = {"Authorization": f"Bearer {self._auth()}"}
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def snapshot(self, tenant_id: str) -> TenantSnapshot:
        principals = self._users()
        # v1 reads core user + assignment data; app grants wiring is in
        # scanner. Keep this connector GET-only and additive.
        return TenantSnapshot(tenant_id=tenant_id, scanned_at="", principals=principals)

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
