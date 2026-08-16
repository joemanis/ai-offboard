from __future__ import annotations

import json

import pytest

from offboard import provision


class FakeResponse:
    def __init__(self, status_code: int, payload: dict | list):
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


def test_provision_creates_app_when_missing(monkeypatch):
    """No existing registration -> POST creates it and returns appId."""
    calls: list[tuple[str, dict]] = []

    def fake_post(url, headers=None, json=None, timeout=None):
        calls.append(("post", json or {}))
        return FakeResponse(201, {"appId": "aaaa1111-bbbb-2222-cccc-3333dddd4444", "id": "app-obj-1"})

    def fake_get(url, headers=None, params=None, timeout=None):
        return FakeResponse(200, {"value": []})

    monkeypatch.setattr(provision.requests, "get", fake_get)
    monkeypatch.setattr(provision.requests, "post", fake_post)

    app_id = provision.provision_public_client("fake-token")

    assert app_id == "aaaa1111-bbbb-2222-cccc-3333dddd4444"
    assert calls, "POST /applications was never called"
    payload = calls[0][1]
    assert payload["displayName"] == "ai-offboard"
    assert payload["isFallbackPublicClient"] is True
    # Only delegated read scopes requested, never a secret or write scope
    requested = {a["id"] for a in payload["requiredResourceAccess"][0]["resourceAccess"]}
    assert requested == {
        "a154be20-db9c-4678-8ab7-66f6cc099a59",  # User.Read.All
        "5b567255-7709-4cf8-902c-1a72a8d5e1e7",  # Group.Read.All
        "9a5d68dd-3bda-4839-b97b-5c8a6abd51e2",  # Application.Read.All
        "7ab1d382-f21e-4acd-a863-ba3e13f7da61",  # Directory.Read.All
    }


def test_provision_reuses_existing_app(monkeypatch):
    """App already exists -> no POST, return its appId (idempotent)."""
    posted = False

    def fake_post(url, headers=None, json=None, timeout=None):
        nonlocal posted
        posted = True
        return FakeResponse(201, {"appId": "existing-id"})

    def fake_get(url, headers=None, params=None, timeout=None):
        return FakeResponse(200, {"value": [{"appId": "existing-id", "displayName": "ai-offboard"}]})

    monkeypatch.setattr(provision.requests, "get", fake_get)
    monkeypatch.setattr(provision.requests, "post", fake_post)

    app_id = provision.provision_public_client("fake-token")
    assert app_id == "existing-id"
    assert posted is False


def test_provision_raises_on_graph_failure(monkeypatch):
    def fake_get(url, headers=None, params=None, timeout=None):
        return FakeResponse(200, {"value": []})

    def fake_post(url, headers=None, json=None, timeout=None):
        return FakeResponse(403, {"error": {"message": "insufficient privileges"}})

    monkeypatch.setattr(provision.requests, "get", fake_get)
    monkeypatch.setattr(provision.requests, "post", fake_post)

    with pytest.raises(provision.ProvisioningError, match="App registration failed"):
        provision.provision_public_client("fake-token")


def test_save_public_client_id_writes_env(tmp_path):
    env_path = str(tmp_path / ".env")
    # Pre-existing unrelated keys survive
    with open(env_path, "w") as fh:
        fh.write('OFFBOARD_CLIENT_ID=abc123\n')

    written = provision.save_public_client_id("deadbeef-1234", env_path=env_path)

    assert written == env_path
    with open(env_path) as fh:
        content = fh.read()
    assert "OFFBOARD_PUBLIC_CLIENT_ID=deadbeef-1234" in content
    assert "OFFBOARD_CLIENT_ID=abc123" in content


def test_bootstrap_scopes_include_provisioning_but_never_write():
    assert "https://graph.microsoft.com/Application.ReadWrite.All" in provision.BOOTSTRAP_SCOPES
    # The provisioned app's scopes are strictly read-only
    provisioned = " ".join(provision.PROVISION_SCOPES).lower()
    for bad in (".readwrite", ".write", "readwrite"):
        assert bad not in provisioned