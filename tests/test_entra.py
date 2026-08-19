from __future__ import annotations

import threading
from types import SimpleNamespace

from offboard.auth import AuthResult
from offboard.connectors.entra import EntraConnector


def test_noninteractive_connector_passes_through_to_auth_provider() -> None:
    calls: list[dict] = []

    class Provider:
        def authenticate(self, scopes: list[str] | None = None, interactive: bool = True) -> AuthResult:
            calls.append({"interactive": interactive})
            return AuthResult(token="token", tenant_id="tenant")

    connector = EntraConnector(Provider(), allow_interactive=False)

    assert connector._auth() == "token"
    assert calls == [{"interactive": False}]


def test_app_role_assignment_payload_maps_principal_and_role() -> None:
    service_principals = [
        {
            "id": "sp-ai",
            "appId": "app-ai",
            "appDisplayName": "ChatGPT Enterprise",
            "appRoles": [
                {"id": "role-files", "displayName": "Files.Read.All", "value": "Files.Read.All"}
            ],
        }
    ]
    assignments = {
        "sp-ai": [
            {
                "id": "assignment-1",
                "appRoleId": "role-files",
                "principalId": "user-1",
                "principalDisplayName": "Alex Example",
                "principalType": "User",
            }
        ]
    }

    mapped = EntraConnector._to_assignments(service_principals, assignments)

    assert len(mapped) == 1
    assert mapped[0].principal_id == "user-1"
    assert mapped[0].principal_display_name == "Alex Example"
    assert mapped[0].principal_type == "User"
    assert mapped[0].role_display_name == "Files.Read.All"
    assert mapped[0].app_id == "app-ai"


def test_service_principal_alone_does_not_create_assignment() -> None:
    mapped = EntraConnector._to_assignments(
        [{"id": "sp-ai", "appId": "app-ai", "appDisplayName": "ChatGPT Enterprise"}],
        {},
    )
    assert mapped == []


def test_list_all_follows_odata_next_link(monkeypatch) -> None:
    class Response:
        def __init__(self, body: dict) -> None:
            self.body = body

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return self.body

    responses = iter(
        [
            Response({"value": [{"id": "1"}], "@odata.nextLink": "https://graph.example/next"}),
            Response({"value": [{"id": "2"}]}),
        ]
    )
    calls: list[tuple[str, dict]] = []

    def fake_get(url: str, **kwargs):
        calls.append((url, kwargs))
        return next(responses)

    monkeypatch.setattr("offboard.connectors.entra.requests.get", fake_get)
    connector = EntraConnector(SimpleNamespace(authenticate=lambda: SimpleNamespace(token="token")))

    assert connector._list_all("/users", {"$select": "id"}) == [{"id": "1"}, {"id": "2"}]
    assert calls[0][0].endswith("/users")
    assert calls[1][0] == "https://graph.example/next"
    assert calls[1][1]["params"] == {}


def test_snapshot_attributes_delegated_and_application_grants(monkeypatch) -> None:
    connector = EntraConnector(SimpleNamespace(authenticate=lambda: SimpleNamespace(token="token")))
    monkeypatch.setattr(connector, "_fetch_users", lambda: [{"id": "u1", "userPrincipalName": "u@example.com"}])
    monkeypatch.setattr(connector, "_fetch_mfa_registration", lambda: [{"id": "u1", "isMfaRegistered": True}])
    service_principals = [
        {
            "id": "client-sp",
            "appId": "client-app",
            "appDisplayName": "AI Assistant",
            "appRoles": [],
        },
        {
            "id": "graph-sp",
            "appId": "graph-app",
            "appDisplayName": "Microsoft Graph",
            "appRoles": [{"id": "role-mail", "displayName": "Mail.Read"}],
        },
    ]
    monkeypatch.setattr(connector, "_fetch_service_principals", lambda: service_principals)
    monkeypatch.setattr(
        connector,
        "_fetch_ai_access",
        lambda sps, progress: (
            {"client-sp": [{"principalId": "u1", "appRoleId": "role-ai"}]},
            {"client-sp": [{"appRoleId": "role-mail", "resourceId": "graph-sp"}]},
            True,
        ),
    )
    monkeypatch.setattr(
        connector,
        "_fetch_oauth_grants",
        lambda: [
            {
                "clientId": "client-app",
                "resourceId": "graph-sp",
                "scope": "Files.ReadWrite.All",
                "consentType": "AllPrincipals",
                "principalId": None,
            }
        ],
    )

    snapshot = connector.snapshot("tenant-1")

    assert snapshot.enterprise_app_count == 2
    assert snapshot.coverage["mfa"] == "assessed"
    assert snapshot.app_assignments[0].principal_id == "u1"
    assert len(snapshot.permission_grants) == 2
    delegated, application = snapshot.permission_grants
    assert delegated.app_display_name == "AI Assistant"
    assert delegated.resource_display_name == "Microsoft Graph"
    assert delegated.consent_type == "AllPrincipals"
    assert application.grant_type == "application"
    assert application.resource_display_name == "Microsoft Graph"
    assert application.scope == "Mail.Read"


def test_ai_access_resolution_runs_catalog_apps_concurrently(monkeypatch) -> None:
    connector = EntraConnector(SimpleNamespace(authenticate=lambda: SimpleNamespace(token="token")))
    service_principals = [
        {"id": f"sp-{index}", "appDisplayName": name, "appRoles": []}
        for index, name in enumerate(("ChatGPT", "Claude", "Copilot"))
    ]
    barrier = threading.Barrier(3)

    def fetch_assignments(service_principal_id: str) -> list[dict]:
        barrier.wait(timeout=2)
        return [{"principalId": service_principal_id}]

    monkeypatch.setattr(connector, "_fetch_app_role_assignments", fetch_assignments)
    monkeypatch.setattr(connector, "_fetch_application_permissions", lambda _: [])

    assignments, permissions, complete = connector._fetch_ai_access(service_principals)

    assert complete
    assert set(assignments) == {"sp-0", "sp-1", "sp-2"}
    assert all(len(rows) == 1 for rows in assignments.values())
    assert permissions == {"sp-0": [], "sp-1": [], "sp-2": []}
