from __future__ import annotations

import time
from types import SimpleNamespace

import offboard.auth as auth_module
from offboard.auth import AuthResult, DeviceCodeAuth


class FakeDeviceFlowApp:
    def __init__(self, responses: list[dict]) -> None:
        self.responses = responses
        self.calls = 0

    def get_accounts(self) -> list[dict]:
        return []

    def initiate_device_flow(self, scopes: list[str]) -> dict:
        return {
            "user_code": "TESTCODE",
            "verification_uri": "https://login.microsoft.com/device",
            "device_code": "device-code",
            "interval": 1,
            "expires_at": time.time() + 30,
        }

    def acquire_token_by_device_flow(self, flow: dict) -> dict:
        response = self.responses[min(self.calls, len(self.responses) - 1)]
        self.calls += 1
        return response


def make_auth(fake_app: object) -> DeviceCodeAuth:
    auth = object.__new__(DeviceCodeAuth)
    auth._client_id = "client-id"
    auth._cache = SimpleNamespace(has_state_changed=False)
    auth._app = fake_app
    auth._flow = None
    return auth


def test_device_code_login_keeps_polling_while_authorization_is_pending(monkeypatch) -> None:
    app = FakeDeviceFlowApp(
        [
            {
                "error": "authorization_pending",
                "error_description": "AADSTS70016: Authorization is pending.",
            },
            {
                "access_token": "access-token",
                "id_token_claims": {"tid": "tenant-id"},
                "account": {"username": "joe@example.com"},
            },
        ]
    )
    monkeypatch.setattr(auth_module.time, "sleep", lambda _: None)
    auth = make_auth(app)

    result = auth.authenticate()

    assert result == AuthResult(
        token="access-token",
        tenant_id="tenant-id",
        account="joe@example.com",
    )
    assert app.calls == 2


def test_expired_device_code_reports_actionable_error(monkeypatch) -> None:
    app = FakeDeviceFlowApp(
        [{
            "error": "authorization_pending",
            "error_description": "AADSTS70016: Authorization is pending.",
        }]
    )
    auth = make_auth(app)
    auth._flow = {
        "device_code": "device-code",
        "interval": 1,
        "expires_at": 100,
    }
    monkeypatch.setattr(auth_module.time, "time", lambda: 101)

    result = auth._poll_device_flow()

    assert result["error"] == "device_code_expired"
    assert "expired" in result["error_description"].lower()


def test_cached_auth_is_validated_silently() -> None:
    class App:
        def get_accounts(self) -> list[dict]:
            return [{"username": "joe@example.com"}]

        def acquire_token_silent(self, scopes: list[str], account: dict) -> dict:
            return {"access_token": "token"}

    auth = make_auth(SimpleNamespace())
    auth._app = App()

    assert auth.has_valid_cached_token() is True


def test_cached_auth_is_reported_invalid_when_silent_refresh_fails() -> None:
    class App:
        def get_accounts(self) -> list[dict]:
            return [{"username": "joe@example.com"}]

        def acquire_token_silent(self, scopes: list[str], account: dict) -> dict:
            return {"error": "no_tokens_found"}

    auth = make_auth(SimpleNamespace())
    auth._app = App()

    assert auth.has_valid_cached_token() is False
