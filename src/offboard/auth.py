"""Authentication providers + token cache for ai-offboard.

Two providers:
- ClientCredentialsAuth: the classic app-only flow (client ID + secret + tenant).
  Good for CI / service accounts.
- DeviceCodeAuth: interactive device-code flow. The user signs in as a Global
  Admin at microsoft.com/devicelogin. NO tenant ID, NO client secret needed.
  Tenant ID is resolved automatically from the token.

The access token is cached on disk (in ~/.ai-offboard/token_cache.json) so
subsequent scans reuse the refresh token without re-authenticating.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Protocol

from msal import (
    ConfidentialClientApplication,
    PublicClientApplication,
    SerializableTokenCache,
)

GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
# Delegated read scopes for the device-code flow (admin-consented).
DEVICE_CODE_SCOPES = [
    "https://graph.microsoft.com/User.Read.All",
    "https://graph.microsoft.com/Group.Read.All",
    "https://graph.microsoft.com/Application.Read.All",
    "https://graph.microsoft.com/Directory.Read.All",
    # Required for the signInActivity field on /users (lastSignInDateTime).
    "https://graph.microsoft.com/AuditLog.Read.All",
    "https://graph.microsoft.com/Reports.Read.All",
]

STATE_DIR = os.path.join(os.path.expanduser("~"), ".ai-offboard")
TOKEN_CACHE_PATH = os.path.join(STATE_DIR, "token_cache.json")
AUTH_STATE_PATH = os.path.join(STATE_DIR, "auth.json")


@dataclass
class AuthResult:
    """Outcome of an authentication attempt."""

    token: str
    tenant_id: str
    account: str | None = None
    mode: str = "device_code"


class AuthProvider(Protocol):
    """Anything that can produce a usable access token."""

    def authenticate(self, scopes: list[str] | None = None, interactive: bool = True) -> AuthResult:
        ...


def _load_token_cache() -> SerializableTokenCache:
    cache = SerializableTokenCache()
    if os.path.exists(TOKEN_CACHE_PATH):
        try:
            with open(TOKEN_CACHE_PATH, encoding="utf-8") as fh:
                cache.deserialize(fh.read())
        except (json.JSONDecodeError, OSError):
            pass  # corrupted cache: start fresh
    return cache


def _save_token_cache(cache: SerializableTokenCache) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    if cache.has_state_changed:
        with open(TOKEN_CACHE_PATH, "w", encoding="utf-8") as fh:
            fh.write(cache.serialize())


def _tenant_from_token(token: str) -> str | None:
    """Extract the 'tid' claim from a JWT access token without validating it."""
    try:
        payload = token.split(".")[1]
        # pad base64url
        payload += "=" * (-len(payload) % 4)
        import base64

        claims = json.loads(base64.urlsafe_b64decode(payload))
        return claims.get("tid")
    except Exception:  # noqa: BLE001 - malformed tokens just yield no tenant
        return None


class ClientCredentialsAuth:
    """App-only auth for CI / service accounts (client ID + secret + tenant)."""

    mode = "client_credentials"

    def __init__(self, client_id: str, client_secret: str, authority: str) -> None:
        self._app = ConfidentialClientApplication(
            client_id,
            client_secret=client_secret,
            authority=authority,
        )
        self._tenant_id = authority.rstrip("/").rsplit("/", 1)[-1]

    def authenticate(self, scopes: list[str] | None = None, interactive: bool = True) -> AuthResult:
        result = self._app.acquire_token_for_client(scopes=[GRAPH_SCOPE])
        if "access_token" not in result:
            raise RuntimeError(f"Auth failed: {result.get('error_description')}")
        return AuthResult(
            token=result["access_token"],
            tenant_id=self._tenant_id,
            mode=self.mode,
        )


class DeviceCodeAuth:
    """Interactive device-code auth: sign in as the tenant's Global Admin.

    Run `offboard auth login`, copy the code, open microsoft.com/devicelogin,
    paste it, approve. No tenant ID and no client secret are ever required;
    the tenant is resolved from the token's claims.
    """

    mode = "device_code"

    def __init__(self, client_id: str, cache: SerializableTokenCache | None = None) -> None:
        self._client_id = client_id
        self._cache = cache if cache is not None else _load_token_cache()
        self._app = PublicClientApplication(
            client_id=client_id,
            authority="https://login.microsoftonline.com/common",
            token_cache=self._cache,
        )
        self._flow: dict | None = None

    @property
    def has_cached_account(self) -> bool:
        return len(self._app.get_accounts()) > 0

    def cached_tenant_id(self) -> str | None:
        """Tenant id of the first cached account, if any."""
        accounts = self._app.get_accounts()
        if not accounts:
            return None
        # msal accounts carry a 'tenant_id' attribute in newer versions
        tid = getattr(accounts[0], "tenant_id", None)
        return tid or _tenant_from_token(accounts[0].get("id_token_claims", {}).get("tid", ""))

    def _poll_device_flow(self, timeout: int | None = None) -> dict:
        """Poll the device token endpoint until success or a terminal error.

        MSAL 1.37 returns one token response per call, so authorization_pending
        must be handled by the application rather than assumed to be fatal.
        """
        if self._flow is None:
            raise RuntimeError("No active device flow. Call initiate_device_flow() first.")
        flow = self._flow
        interval = max(float(flow.get("interval", 5)), 1.0)
        flow_expires_at = float(flow.get("expires_at", time.time() + flow.get("expires_in", 900)))
        deadline = flow_expires_at
        if timeout is not None:
            deadline = min(deadline, time.time() + timeout)

        while True:
            result = self._app.acquire_token_by_device_flow(flow)
            if "access_token" in result:
                return result
            error = str(result.get("error", "")).lower()
            description = str(result.get("error_description", "")).lower()
            pending = error in {"authorization_pending", "slow_down"} or "aadsts70016" in description
            if not pending:
                return result
            remaining = deadline - time.time()
            if remaining <= 0:
                return result
            time.sleep(min(interval, remaining))
            if error == "slow_down":
                interval += 5

    def authenticate(self, scopes: list[str] | None = None, interactive: bool = True) -> AuthResult:
        scopes = scopes or DEVICE_CODE_SCOPES
        # 1) Try silent auth from the cached refresh token
        accounts = self._app.get_accounts()
        if accounts:
            result = self._app.acquire_token_silent(scopes, account=accounts[0])
            if result and "access_token" in result:
                _save_token_cache(self._cache)
                return AuthResult(
                    token=result["access_token"],
                    tenant_id=str(result.get("id_token_claims", {}).get("tid", ""))
                    or self.cached_tenant_id()
                    or "",
                    account=accounts[0].get("username"),
                    mode=self.mode,
                )
            if not interactive:
                raise RuntimeError(
                    "Cached Microsoft login expired. Run `offboard auth login` before "
                    "using --json or --bundle."
                )
        elif not interactive:
            raise RuntimeError(
                "No cached Microsoft login. Run `offboard auth login` before using "
                "--json or --bundle."
            )
        self._flow = self._app.initiate_device_flow(scopes=DEVICE_CODE_SCOPES)
        if "user_code" not in self._flow:
            raise RuntimeError(f"Device flow failed: {self._flow.get('error_description')}")
        print("=" * 60)
        print("  1. Open:", self._flow["verification_uri"])
        print("  2. Enter code:", self._flow["user_code"])
        print("  3. Sign in and approve when prompted.")
        print("=" * 60)
        result = self._poll_device_flow()
        if "access_token" not in result:
            raise RuntimeError(f"Device flow failed: {result.get('error_description')}")
        _save_token_cache(self._cache)
        return AuthResult(
            token=result["access_token"],
            tenant_id=str(result.get("id_token_claims", {}).get("tid", "")),
            account=result.get("account", {}).get("username"),
            mode=self.mode,
        )

    def begin_web_flow(self, scopes: list[str] | None = None) -> dict:
        """Start a device flow for the web UI; returns {user_code, uri}.

        The server can poll `finish_web_flow()` in a thread while the user
        completes the browser step. Raises RuntimeError if Microsoft rejects
        the initiation (e.g. AADSTS50059 for a single-tenant app against the
        `common` authority) so callers surface the real error, not a KeyError
        from a malformed flow dict.
        """
        if self._flow is None:
            self._flow = self._app.initiate_device_flow(scopes=scopes or DEVICE_CODE_SCOPES)
        if "user_code" not in self._flow:
            err = self._flow.get("error_description") or self._flow.get("error") or "unknown initiation error"
            hint = ""
            if "AADSTS50059" in err:
                hint = (
                    " (This usually means the app was registered as 'Single tenant only'. "
                    "Re-register with 'Multiple Entra ID tenants'.)"
                )
            elif "AADSTS65002" in err:
                hint = " (This client ID is a Microsoft first-party app; register your own app instead.)"
            raise RuntimeError(f"Device flow initiation failed: {err}{hint}")
        return {
            "user_code": self._flow.get("user_code", ""),
            "verification_uri": self._flow.get("verification_uri", ""),
        }


    def finish_web_flow(self, timeout: int = 300) -> AuthResult:
        """Block until the user completes the flow (call from a worker thread).

        The wrapper explicitly polls because current MSAL releases return one
        token response per call rather than handling authorization_pending
        internally.
        """
        if self._flow is None:
            raise RuntimeError("No active device flow. Call begin_web_flow() first.")
        result = self._poll_device_flow(timeout=timeout)
        if "access_token" not in result:
            raise RuntimeError(f"Device flow failed: {result.get('error_description')}")
        _save_token_cache(self._cache)
        return AuthResult(
            token=result["access_token"],
            tenant_id=str(result.get("id_token_claims", {}).get("tid", "")),
            account=result.get("account", {}).get("username"),
            mode=self.mode,
        )

    def logout(self) -> None:
        accounts = self._app.get_accounts()
        for account in accounts:
            self._app.remove_account(account)
        os.makedirs(STATE_DIR, exist_ok=True)
        if os.path.exists(TOKEN_CACHE_PATH):
            os.remove(TOKEN_CACHE_PATH)
        if os.path.exists(AUTH_STATE_PATH):
            os.remove(AUTH_STATE_PATH)


def save_auth_state(tenant_id: str, mode: str) -> None:
    """Persist the resolved tenant + mode so scans don't ask for tenant ID."""
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(AUTH_STATE_PATH, "w", encoding="utf-8") as fh:
        json.dump({"tenant_id": tenant_id, "mode": mode}, fh)


def load_auth_state() -> dict:
    if os.path.exists(AUTH_STATE_PATH):
        try:
            with open(AUTH_STATE_PATH, encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            pass
    return {}