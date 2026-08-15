"""Connector factory — pick the right auth mode automatically.

Microsoft Entra resolution order:
1. Existing device-code session (cached token) -> DeviceCodeAuth
2. Client-credentials config is complete -> ClientCredentialsAuth
3. Neither -> raise with instructions for the interactive path

Google Workspace is built via build_workspace_connector() using a direct
access token or a service account with domain-wide delegation.
"""
from __future__ import annotations

from ..auth import ClientCredentialsAuth, DeviceCodeAuth, load_auth_state
from ..config import Config
from .entra import EntraConnector
from .workspace import WorkspaceConnector


def build_connector(cfg: Config, prefer_device_code: bool = False) -> EntraConnector:
    """Build the best Microsoft Entra connector for the current environment."""
    # 1) Device-code session already established (interactive Global Admin login)
    device = DeviceCodeAuth(client_id=cfg.public_client_id or _DEFAULT_PUBLIC_CLIENT_ID)
    if prefer_device_code or device.has_cached_account or load_auth_state().get("mode") == "device_code":
        return EntraConnector(device)

    # 2) Client credentials (CI / service account)
    if cfg.is_complete:
        auth = ClientCredentialsAuth(cfg.client_id, cfg.client_secret, cfg.authority)
        return EntraConnector(auth)

    # 3) Nothing usable
    raise RuntimeError(
        "No usable auth found. Run `offboard auth login` (interactive Global Admin "
        "login, no config needed) or `offboard setup` (client credentials)."
    )


def build_workspace_connector(cfg: Config) -> WorkspaceConnector:
    """Build a Google Workspace connector.

    Expects GOOGLE_ACCESS_TOKEN (direct token) or GOOGLE_SERVICE_ACCOUNT_JSON
    (path to a service-account key with domain-wide delegation, impersonating
    OFFBOARD_GOOGLE_ADMIN). Falls back to an explanatory error.
    """
    import os

    token = os.environ.get("GOOGLE_ACCESS_TOKEN")
    if token:
        return WorkspaceConnector(lambda: token)

    sa_path = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON")
    admin = os.environ.get("OFFBOARD_GOOGLE_ADMIN", "")
    if sa_path and admin:
        from google.auth.transport.requests import Request
        from google.oauth2 import service_account

        credentials = service_account.Credentials.from_service_account_file(
            sa_path,
            scopes=["https://www.googleapis.com/auth/admin.directory.user.readonly"],
            subject=admin,
        )

        def _provider() -> str:
            credentials.refresh(Request())
            return str(credentials.token)

        return WorkspaceConnector(_provider)

    raise RuntimeError(
        "No Google Workspace auth found. Set GOOGLE_ACCESS_TOKEN, or "
        "GOOGLE_SERVICE_ACCOUNT_JSON + OFFBOARD_GOOGLE_ADMIN for domain-wide "
        "delegation."
    )


# Public client used for the interactive device-code login. Any Azure AD app
# registration that allows public client (mobile/desktop) flows can serve; this
# ships as a well-known dev default and can be overridden via config/env.
_DEFAULT_PUBLIC_CLIENT_ID = "1950a258-227b-4e31-a9cf-717495945fc2"  # Azure CLI public client — usable for device code flows