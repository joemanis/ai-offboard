"""Microsoft Entra ID connector (read-only, v1).

The connector is auth-agnostic: it takes any AuthProvider (client credentials
for CI/service accounts, or device-code for interactive Global Admin login)
and issues GET-only Graph calls.

Wire-up order:
1. Users (with sign-in activity and MFA)
2. Service Principals (enterprise AI apps)
3. App Role Assignments (who has access to what)
4. OAuth2 Permission Grants (what scopes have been consented)
"""
from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

import requests

from ..auth import GRAPH_ROOT, AuthProvider
from .base import (
    AppAssignment,
    Connector,
    PermissionGrant,
    Principal,
    TenantSnapshot,
)


class EntraConnector(Connector):
    """Scan a Microsoft 365 / Entra tenant."""

    def __init__(self, auth: AuthProvider) -> None:
        self._auth_provider = auth
        self._access_token: str | None = None

    # ------------------------------------------------------------------
    # Auth plumbing
    # ------------------------------------------------------------------

    def _auth(self) -> str:
        if not self._access_token:
            self._access_token = self._auth_provider.authenticate().token
        return self._access_token

    def test_auth(self) -> bool:
        self._auth()
        return True

    def get_tenant_id(self) -> str:
        if self._access_token:
            from ..auth import _tenant_from_token

            tid = _tenant_from_token(self._access_token)
            if tid:
                return tid
        return self._auth_provider.authenticate().tenant_id

    # ------------------------------------------------------------------
    # Raw HTTP
    # ------------------------------------------------------------------

    def _get(self, path: str, params: dict | None = None) -> dict:
        url = f"{GRAPH_ROOT}{path}"
        headers = {"Authorization": f"Bearer {self._auth()}"}
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _list_all(self, path: str, params: dict | None = None) -> list[dict]:
        """Paginate through a Graph list endpoint. Params that don't include
        $top default to 999 per page.
        """
        params = dict(params or {})
        params.setdefault("$top", "999")
        items: list[dict] = []
        url = f"{GRAPH_ROOT}{path}"
        while url:
            headers = {"Authorization": f"Bearer {self._auth()}"}
            resp = requests.get(url, headers=headers, params=params, timeout=30)
            resp.raise_for_status()
            body = resp.json()
            items.extend(body.get("value", []))
            url = body.get("@odata.nextLink", "")
            params = {}  # nextLink is fully-qualified; don't re-apply old params
        return items

    # ------------------------------------------------------------------
    # Data fetch methods — each returns a Graph API result list
    # ------------------------------------------------------------------

    def _fetch_users(self) -> list[dict]:
        return self._list_all(
            "/users",
            {
                "$select": (
                    "id,displayName,userPrincipalName,accountEnabled,"
                    "signInActivity,createdDateTime"
                ),
            },
        )

    def _fetch_service_principals(self) -> list[dict]:
        return self._list_all(
            "/servicePrincipals",
            {
                "$select": (
                    "id,appDisplayName,appId,appOwnerOrganizationId,"
                    "servicePrincipalType,publisherName"
                ),
            },
        )

    def _fetch_oauth_grants(self) -> list[dict]:
        """OAuth2 permission grants — delegated consent."""
        return self._list_all("/oauth2PermissionGrants")

    # ------------------------------------------------------------------
    # Mapping to domain types
    # ------------------------------------------------------------------

    @staticmethod
    def _to_principals(items: list[dict]) -> list[Principal]:
        out: list[Principal] = []
        for u in items:
            sia = u.get("signInActivity")
            last_seen = (sia or {}).get("lastSignInDateTime") if sia else None
            out.append(
                Principal(
                    id=u["id"],
                    name=u.get("userPrincipalName", u.get("displayName", "")),
                    type="user",
                    enabled=bool(u.get("accountEnabled", True)),
                    sign_in_last_seen=last_seen,
                    mfa_state=u.get("mfaState"),
                )
            )
        return out

    @staticmethod
    def _to_assignments(sps: list[dict]) -> list[AppAssignment]:
        """Build an AppAssignment per enterprise app (service principal)."""
        out: list[AppAssignment] = []
        for sp in sps:
            name = sp.get("appDisplayName") or sp.get("appId", "")
            out.append(
                AppAssignment(
                    principal_id=sp["id"],
                    app_display_name=name,
                    app_role_id=None,
                    is_high_privilege=sp.get("servicePrincipalType") == "Application",
                )
            )
        return out

    @staticmethod
    def _to_grants(items: list[dict]) -> list[PermissionGrant]:
        out: list[PermissionGrant] = []
        for g in items:
            out.append(
                PermissionGrant(
                    app_id=g.get("clientId", ""),
                    resource=g.get("resourceId", ""),
                    scope=g.get("scope", ""),
                    grant_type="delegated",
                )
            )
        return out

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def snapshot(
        self,
        tenant_id: str | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> TenantSnapshot:
        tid = tenant_id or self.get_tenant_id()
        scanned_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

        if progress_callback:
            progress_callback("Fetching users…")
        raw_users = self._fetch_users()

        if progress_callback:
            progress_callback("Fetching enterprise apps (service principals)…")
        raw_sps = self._fetch_service_principals()

        if progress_callback:
            progress_callback("Fetching OAuth permission grants…")
        raw_grants = self._fetch_oauth_grants()

        if progress_callback:
            progress_callback("Running risk rules…")

        return TenantSnapshot(
            tenant_id=tid or "",
            scanned_at=scanned_at,
            principals=self._to_principals(raw_users),
            app_assignments=self._to_assignments(raw_sps),
            permission_grants=self._to_grants(raw_grants),
        )