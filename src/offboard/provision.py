"""One-click app provisioning for the device-code flow.

The "polished" connect flow provisions a DEDICATED Azure AD app for the tenant
instead of leaning on a shared default client ID:

1. Bootstrap sign-in: DeviceCodeAuth with a well-known public client
   (Azure CLI's) requesting `Application.ReadWrite.All`. The Global Admin
   consents to app provisioning on Microsoft's own consent screen.
2. provision_public_client(): uses that legitimately-acquired token to
   create (or find) a dedicated "ai-offboard" public-client app registration
   with ONLY the read scopes the scanner needs. The app ID is written to
   `.env` as OFFBOARD_PUBLIC_CLIENT_ID.
3. The real sign-in then uses the dedicated app (DeviceCodeAuth picks it up
   via config), so consent is scoped to a tenant-owned, least-privilege app.

Everything here uses Microsoft Graph v1.0 against the signed-in tenant.
No credentials are stored beyond the .env app ID (public, not a secret).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import requests

from .auth import GRAPH_ROOT

# Well-known public client that allows device-code + app provisioning consent.
# The Azure CLI client is broadly consented and supports Application.ReadWrite.All.
BOOTSTRAP_CLIENT_ID = "1950a258-227b-4e31-a9cf-717495945fc2"
BOOTSTRAP_SCOPES = [
    "https://graph.microsoft.com/User.Read.All",
    "https://graph.microsoft.com/Application.ReadWrite.All",
    "https://graph.microsoft.com/Directory.Read.All",
]

# Read-only delegated scopes granted to the provisioned app.
# The scanner NEVER needs write scopes.
PROVISION_SCOPES = [
    "https://graph.microsoft.com/User.Read.All",
    "https://graph.microsoft.com/Group.Read.All",
    "https://graph.microsoft.com/Application.Read.All",
    "https://graph.microsoft.com/Directory.Read.All",
]

# Microsoft Graph resource app id + the delegated permission ids for the
# scopes above (stable across tenants).
GRAPH_RESOURCE_APP_ID = "00000003-0000-0000-c000-000000000000"
_SCOPE_IDS = {
    "https://graph.microsoft.com/User.Read.All": "a154be20-db9c-4678-8ab7-66f6cc099a59",
    "https://graph.microsoft.com/Group.Read.All": "5b567255-7709-4cf8-902c-1a72a8d5e1e7",
    "https://graph.microsoft.com/Application.Read.All": "9a5d68dd-3bda-4839-b97b-5c8a6abd51e2",
    "https://graph.microsoft.com/Directory.Read.All": "7ab1d382-f21e-4acd-a863-ba3e13f7da61",
}

APP_DISPLAY_NAME = "ai-offboard"


class ProvisioningError(RuntimeError):
    """Raised when app registration via Graph fails."""


def provision_public_client(access_token: str) -> str:
    """Create (or find) the dedicated 'ai-offboard' public client app.

    Returns the application (client) ID. Idempotent: if an app with the
    display name already exists, its ID is returned instead of creating a
    duplicate.

    Requires the access token to carry Application.ReadWrite.All (delegated).
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    base = f"{GRAPH_ROOT}/applications"

    # 1) Find an existing registration (idempotent reconnect).
    found = requests.get(
        base,
        headers=headers,
        params={"$filter": f"displayName eq '{APP_DISPLAY_NAME}'", "$select": "id,appId,displayName"},
        timeout=30,
    )
    if found.status_code == 200:
        existing = found.json().get("value", [])
        if existing:
            return existing[0]["appId"]

    # 2) Create the dedicated public client registration.
    payload: dict[str, Any] = {
        "displayName": APP_DISPLAY_NAME,
        "signInAudience": "AzureADMyOrg",
        "isFallbackPublicClient": True,
        "publicClient": {"redirectUris": []},
        "requiredResourceAccess": [
            {
                "resourceAppId": GRAPH_RESOURCE_APP_ID,
                "resourceAccess": [
                    {"id": _SCOPE_IDS[scope], "type": "Scope"}
                    for scope in PROVISION_SCOPES
                    if scope in _SCOPE_IDS
                ],
            }
        ],
    }
    created = requests.post(base, headers=headers, json=payload, timeout=30)
    if created.status_code not in (200, 201):
        raise ProvisioningError(
            f"App registration failed ({created.status_code}): {created.text[:300]}"
        )
    app_id = created.json().get("appId", "")
    if not app_id:
        raise ProvisioningError("App registration returned no appId.")
    return app_id


def save_public_client_id(client_id: str, env_path: str | None = None) -> str:
    """Write OFFBOARD_PUBLIC_CLIENT_ID into the .env file.

    Returns the env path written.
    """
    from .config import Config, default_env_path, write_env_file

    path = env_path or default_env_path()
    existing = {}
    if os.path.exists(path):
        from .config import parse_env_file

        existing = parse_env_file(path)
    cfg = Config(
        client_id=existing.get("OFFBOARD_CLIENT_ID", ""),
        client_secret=existing.get("OFFBOARD_CLIENT_SECRET", ""),
        tenant_id=existing.get("OFFBOARD_TENANT_ID", ""),
        authority=existing.get("OFFBOARD_AUTHORITY", "https://login.microsoftonline.com/common"),
        public_client_id=client_id,
    )
    write_env_file(path, cfg)
    return path


def app_exists(client_id: str) -> bool:
    """Quick local check: is this client ID recorded as our public client?"""
    from .config import load_config

    return load_config().public_client_id == client_id


def env_path_hint() -> str:
    from .config import default_env_path

    path = default_env_path()
    return str(Path(path).resolve())