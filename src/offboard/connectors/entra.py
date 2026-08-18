"""Microsoft Entra ID connector (read-only).

The connector inventories enterprise applications, then resolves actual
principal-to-app-role assignments for catalog-matched AI applications. It also
collects delegated OAuth grants and application permissions with readable app
and resource attribution where Graph provides it.
"""
from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from typing import Any

import requests

from ..auth import GRAPH_ROOT, AuthProvider
from ..catalog.matcher import load_catalog, match_app
from .base import (
    AppAssignment,
    Connector,
    PermissionGrant,
    Principal,
    TenantSnapshot,
)


class EntraConnector(Connector):
    """Scan a Microsoft 365 / Entra tenant using GET-only Graph calls."""

    def __init__(self, auth: AuthProvider) -> None:
        self._auth_provider = auth
        self._access_token: str | None = None
        self._signin_activity_unavailable = False

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

    def _list_all(self, path: str, params: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """Paginate through a Graph list endpoint."""
        params = dict(params or {})
        params.setdefault("$top", "999")
        items: list[dict[str, Any]] = []
        url = f"{GRAPH_ROOT}{path}"
        while url:
            headers = {"Authorization": f"Bearer {self._auth()}"}
            resp = requests.get(url, headers=headers, params=params, timeout=30)
            resp.raise_for_status()
            body = resp.json()
            items.extend(body.get("value", []))
            url = body.get("@odata.nextLink", "")
            params = {}
        return items

    # ------------------------------------------------------------------
    # Data fetch methods
    # ------------------------------------------------------------------

    def _fetch_users(self) -> list[dict[str, Any]]:
        """Fetch users, degrading when sign-in activity is not permitted."""
        base = "id,displayName,userPrincipalName,accountEnabled,createdDateTime"
        try:
            return self._list_all("/users", {"$select": f"{base},signInActivity"})
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 403:
                self._signin_activity_unavailable = True
                return self._list_all("/users", {"$select": base})
            raise

    def _fetch_mfa_registration(self) -> list[dict[str, Any]]:
        """Fetch explicit MFA registration state from Graph reports."""
        return self._list_all(
            "/reports/authenticationMethods/userRegistrationDetails",
            {"$select": "id,userPrincipalName,isMfaRegistered,isMfaCapable"},
        )

    def _fetch_service_principals(self) -> list[dict[str, Any]]:
        return self._list_all(
            "/servicePrincipals",
            {
                "$select": (
                    "id,appDisplayName,appId,appOwnerOrganizationId,"
                    "servicePrincipalType,publisherName,appRoles"
                )
            },
        )

    def _fetch_app_role_assignments(self, service_principal_id: str) -> list[dict[str, Any]]:
        return self._list_all(
            f"/servicePrincipals/{service_principal_id}/appRoleAssignedTo",
            {
                "$select": (
                    "id,appRoleId,principalId,principalDisplayName,principalType,"
                    "resourceDisplayName"
                )
            },
        )

    def _fetch_application_permissions(self, service_principal_id: str) -> list[dict[str, Any]]:
        """Fetch app-only permissions granted by this client service principal."""
        return self._list_all(
            f"/servicePrincipals/{service_principal_id}/appRoleAssignments",
            {"$select": "id,appRoleId,principalId,resourceId"},
        )

    def _fetch_oauth_grants(self) -> list[dict[str, Any]]:
        return self._list_all(
            "/oauth2PermissionGrants",
            {"$select": "id,clientId,resourceId,scope,consentType,principalId"},
        )

    def _fetch_ai_access(
        self,
        service_principals: list[dict[str, Any]],
        progress_callback: Callable[[str], None] | None = None,
    ) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]], bool]:
        """Resolve real assignments and app permissions for catalog-matched AI apps.

        We deliberately avoid an N+1 call for every Microsoft-managed service
        principal. Only potential AI applications need assignment attribution.
        """
        catalog = load_catalog()
        assignments: dict[str, list[dict[str, Any]]] = {}
        app_permissions: dict[str, list[dict[str, Any]]] = {}
        access_complete = True
        candidates = [
            sp for sp in service_principals if match_app(sp.get("appDisplayName", ""), catalog)
        ]
        def resolve(sp: dict[str, Any]) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]], bool]:
            sp_id = str(sp.get("id", ""))
            try:
                return (
                    sp_id,
                    self._fetch_app_role_assignments(sp_id),
                    self._fetch_application_permissions(sp_id),
                    True,
                )
            except requests.HTTPError as exc:
                if exc.response is not None and exc.response.status_code == 403:
                    return sp_id, [], [], False
                raise

        if not candidates:
            return assignments, app_permissions, True
        worker_count = min(6, len(candidates))
        with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="entra-access") as pool:
            futures = [pool.submit(resolve, sp) for sp in candidates]
            for index, future in enumerate(as_completed(futures), start=1):
                sp_id, assignment_rows, permission_rows, resolved_complete = future.result()
                assignments[sp_id] = assignment_rows
                app_permissions[sp_id] = permission_rows
                if not resolved_complete:
                    access_complete = False
                if progress_callback:
                    progress_callback(f"Resolved AI app assignments {index}/{len(candidates)}…")
        return assignments, app_permissions, access_complete

    # ------------------------------------------------------------------
    # Mapping to domain types
    # ------------------------------------------------------------------

    @staticmethod
    def _to_principals(
        items: list[dict[str, Any]],
        mfa_by_id: dict[str, dict[str, Any]] | None = None,
    ) -> list[Principal]:
        mfa_by_id = mfa_by_id or {}
        out: list[Principal] = []
        for user in items:
            sign_in = user.get("signInActivity") or {}
            mfa = mfa_by_id.get(str(user.get("id", "")), {})
            mfa_state = None
            if "isMfaRegistered" in mfa:
                mfa_state = "registered" if mfa["isMfaRegistered"] else "not_registered"
            out.append(
                Principal(
                    id=str(user["id"]),
                    name=user.get("userPrincipalName", user.get("displayName", "")),
                    type="user",
                    enabled=bool(user.get("accountEnabled", True)),
                    sign_in_last_seen=sign_in.get("lastSignInDateTime"),
                    mfa_state=mfa_state,
                )
            )
        return out

    @staticmethod
    def _role_names(service_principal: dict[str, Any]) -> dict[str, str]:
        return {
            str(role.get("id")): role.get("displayName") or role.get("value") or str(role.get("id"))
            for role in service_principal.get("appRoles", [])
            if role.get("id")
        }

    @classmethod
    def _to_assignments(
        cls,
        service_principals: list[dict[str, Any]],
        assignments_by_sp: dict[str, list[dict[str, Any]]] | None = None,
    ) -> list[AppAssignment]:
        """Map actual appRoleAssignedTo records, never service principals alone."""
        assignments_by_sp = assignments_by_sp or {}
        out: list[AppAssignment] = []
        for sp in service_principals:
            sp_id = str(sp.get("id", ""))
            role_names = cls._role_names(sp)
            for assignment in assignments_by_sp.get(sp_id, []):
                role_id = str(assignment.get("appRoleId", ""))
                out.append(
                    AppAssignment(
                        principal_id=str(assignment.get("principalId", "")),
                        app_display_name=sp.get("appDisplayName") or sp.get("appId", ""),
                        app_role_id=role_id or None,
                        principal_display_name=assignment.get("principalDisplayName"),
                        principal_type=assignment.get("principalType"),
                        role_display_name=role_names.get(role_id, "default" if not role_id else role_id),
                        app_id=sp.get("appId"),
                    )
                )
        return out

    @classmethod
    def _to_grants(
        cls,
        items: list[dict[str, Any]],
        service_principals: list[dict[str, Any]],
    ) -> list[PermissionGrant]:
        by_object_id = {str(sp.get("id")): sp for sp in service_principals}
        by_app_id = {str(sp.get("appId")): sp for sp in service_principals}
        out: list[PermissionGrant] = []
        for grant in items:
            client = by_app_id.get(str(grant.get("clientId", "")), {})
            resource = by_object_id.get(str(grant.get("resourceId", "")), {})
            out.append(
                PermissionGrant(
                    app_id=grant.get("clientId", ""),
                    resource=grant.get("resourceId", ""),
                    scope=grant.get("scope", ""),
                    grant_type="delegated",
                    app_display_name=client.get("appDisplayName"),
                    resource_display_name=resource.get("appDisplayName"),
                    consent_type=grant.get("consentType"),
                    principal_id=grant.get("principalId"),
                )
            )
        return out

    @classmethod
    def _to_application_grants(
        cls,
        service_principals: list[dict[str, Any]],
        permissions_by_sp: dict[str, list[dict[str, Any]]],
    ) -> list[PermissionGrant]:
        by_object_id = {str(sp.get("id")): sp for sp in service_principals}
        out: list[PermissionGrant] = []
        for client in service_principals:
            client_id = str(client.get("id", ""))
            for permission in permissions_by_sp.get(client_id, []):
                resource = by_object_id.get(str(permission.get("resourceId", "")), {})
                role_names = cls._role_names(resource)
                role_id = str(permission.get("appRoleId", ""))
                out.append(
                    PermissionGrant(
                        app_id=client.get("appId", client_id),
                        resource=permission.get("resourceId", ""),
                        scope=role_names.get(role_id, role_id),
                        grant_type="application",
                        app_display_name=client.get("appDisplayName"),
                        resource_display_name=resource.get("appDisplayName"),
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
        coverage: dict[str, str] = {}

        if progress_callback:
            progress_callback("Fetching users…")
        raw_users = self._fetch_users()
        coverage["sign_in_activity"] = "not_assessed" if self._signin_activity_unavailable else "assessed"

        if progress_callback:
            progress_callback("Fetching MFA registration details…")
        try:
            mfa_rows = self._fetch_mfa_registration()
            mfa_by_id = {str(row.get("id")): row for row in mfa_rows}
            coverage["mfa"] = "assessed"
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 403:
                mfa_by_id = {}
                coverage["mfa"] = "not_assessed"
            else:
                raise

        if progress_callback:
            progress_callback("Fetching enterprise apps…")
        raw_sps = self._fetch_service_principals()
        assignments_by_sp, permissions_by_sp, access_complete = self._fetch_ai_access(
            raw_sps, progress_callback
        )
        coverage["app_assignments"] = "assessed" if access_complete else "not_assessed"
        coverage["application_permissions"] = "assessed" if access_complete else "not_assessed"

        if progress_callback:
            progress_callback("Fetching delegated OAuth grants…")
        raw_grants = self._fetch_oauth_grants()
        coverage["delegated_grants"] = "assessed"

        assignments = self._to_assignments(raw_sps, assignments_by_sp)
        grants = self._to_grants(raw_grants, raw_sps)
        grants.extend(self._to_application_grants(raw_sps, permissions_by_sp))
        return TenantSnapshot(
            tenant_id=tid or "",
            scanned_at=scanned_at,
            principals=self._to_principals(raw_users, mfa_by_id),
            app_assignments=assignments,
            permission_grants=grants,
            enterprise_app_count=len(raw_sps),
            coverage=coverage,
        )
