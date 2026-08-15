"""Connector factory — pick the right auth mode automatically.

Resolution order:
1. Existing device-code session (cached token) -> DeviceCodeAuth
2. Client-credentials config is complete -> ClientCredentialsAuth
3. Neither -> raise with instructions for the interactive path
"""
from __future__ import annotations

from ..auth import ClientCredentialsAuth, DeviceCodeAuth, load_auth_state
from ..config import Config
from .entra import EntraConnector


def build_connector(cfg: Config, prefer_device_code: bool = False) -> EntraConnector:
    """Build the best connector for the current environment."""
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


# Public client used for the interactive device-code login. Any Azure AD app
# registration that allows public client (mobile/desktop) flows can serve; this
# ships as a well-known dev default and can be overridden via config/env.
_DEFAULT_PUBLIC_CLIENT_ID = "1950a258-227b-4e31-a9cf-717495945fc2"  # Azure CLI public client — usable for device code flows