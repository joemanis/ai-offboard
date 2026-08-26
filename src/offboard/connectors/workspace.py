"""Google Workspace connector (v1b, read-only).

Implements the same Connector interface as the Entra connector, using the
Admin SDK Directory API:

- users:      Directory API `/users` (customer-scoped)
- app grants: per-user OAuth tokens `/users/{key}/tokens` — these are the
              third-party apps (ChatGPT, Notion, Fireflies, etc.) the user
              granted access to, which is exactly the "shadow AI" signal
              ai-offboard is built around.

Auth is injected as a token-provider callable so this module stays testable:
pass a real Google OAuth token source (e.g. a service account with domain-wide
delegation) for production use, or a fake token for mocks/tests.

NOTE: this module never writes. Snapshots are read-only, matching the contract
in connectors/base.py.
"""
from __future__ import annotations

from collections.abc import Callable

import requests

from .base import AppAssignment, Connector, PermissionGrant, Principal, TenantSnapshot

_DIRECTORY_ROOT = "https://admin.googleapis.com/admin/directory/v1"


class WorkspaceConnector(Connector):
    """Read-only Google Workspace tenant scanner."""

    def __init__(
        self,
        token_provider: Callable[[], str],
        customer: str = "my_customer",
        timeout: int = 30,
    ) -> None:
        self._token = token_provider
        self._customer = customer
        self.timeout = timeout

    # -- auth / HTTP -------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token()}",
            "Content-Type": "application/json",
        }

    def _list_all(self, url: str, params: dict[str, str]) -> list[dict]:
        """GET a paginated Directory API collection; auto-follow nextPageToken."""
        items: list[dict] = []
        next_token = ""
        while True:
            merged: dict[str, str] = dict(params)
            if next_token:
                merged["pageToken"] = next_token
            resp = requests.get(url, headers=self._headers(), params=merged, timeout=self.timeout)
            if resp.status_code != 200:
                raise RuntimeError(f"Workspace API error {resp.status_code}: {resp.text}")
            body = resp.json()
            # Different endpoints put payloads under different keys.
            page = body.get("users") or body.get("tokens") or body.get("items") or []
            if page:
                items.extend(page)
            next_token = body.get("nextPageToken", "")
            if not next_token:
                break
        return items

    # -- data fetching (overridable for mocks) ------------------------------

    def _fetch_users(self) -> list[dict]:
        url = f"{_DIRECTORY_ROOT}/users"
        return self._list_all(url, {"customer": self._customer, "maxResults": "500", "orderBy": "email"})

    def _fetch_user_tokens(self, user_key: str) -> list[dict]:
        url = f"{_DIRECTORY_ROOT}/users/{user_key}/tokens"
        return self._list_all(url, {"maxResults": "100"})

    # -- mapping to domain types --------------------------------------------

    def _to_principal(self, raw: dict, sign_in_context: bool = False) -> Principal:
        return Principal(
            id=raw.get("id", ""),
            name=raw.get("primaryEmail", raw.get("name", {}).get("fullName", "unknown")),
            type="user",
            enabled=not bool(raw.get("suspended", False)),
            sign_in_last_seen=(raw.get("lastLoginTime") or raw.get("creationTime") or None) if sign_in_context else None,
        )

    def _to_assignment_and_grant(self, user: Principal, token_raw: dict) -> tuple[AppAssignment, PermissionGrant] | None:
        display = token_raw.get("displayText") or token_raw.get("clientId") or "unknown app"
        if not display or display == "unknown app":
            return None
        assignment = AppAssignment(
            principal_id=user.id,
            app_display_name=display,
            app_role_id=token_raw.get("clientId"),
            is_high_privilege=bool(token_raw.get("nativeApp", False)),
        )
        scopes = token_raw.get("scopes", [])
        grant = PermissionGrant(
            app_id=token_raw.get("clientId", ""),
            resource="google",
            scope=" ".join(scopes) if isinstance(scopes, list) else str(scopes),
            grant_type="delegated",
            app_display_name=display,
            resource_display_name="Google Workspace",
            principal_id=user.id,
            principal_display_name=user.name,
        )
        return assignment, grant

    # -- public entry point -------------------------------------------------

    def snapshot(
        self,
        tenant_id: str,
        progress_callback: Callable[[str], None] | None = None,
        sign_in_context: bool = False,
    ) -> TenantSnapshot:
        """Fetch users + their OAuth tokens and map to a TenantSnapshot."""
        from datetime import UTC, datetime

        if progress_callback:
            progress_callback("Fetching Workspace users…")
        users_raw = self._fetch_users()

        principals: list[Principal] = []
        assignments: list[AppAssignment] = []
        grants: list[PermissionGrant] = []
        for idx, raw_user in enumerate(users_raw):
            user = self._to_principal(raw_user, sign_in_context=sign_in_context)
            principals.append(user)
            if idx % 50 == 0 and len(users_raw) > 50 and progress_callback:
                progress_callback(f"Grants for {idx}/{len(users_raw)} users…")
            try:
                tokens = self._fetch_user_tokens(user.name)
            except RuntimeError:
                continue  # one user's token fetch failing shouldn't abort the scan
            for token_raw in tokens:
                mapped = self._to_assignment_and_grant(user, token_raw)
                if mapped:
                    assignments.append(mapped[0])
                    grants.append(mapped[1])
        if progress_callback:
            progress_callback("Mapping principals and grants…")

        return TenantSnapshot(
            tenant_id=tenant_id or "workspace",
            scanned_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            principals=principals,
            app_assignments=assignments,
            permission_grants=grants,
        )