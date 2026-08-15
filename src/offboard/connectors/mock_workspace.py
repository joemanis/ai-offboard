"""Deterministic mock Workspace connector for tests and demos.

Subclasses WorkspaceConnector and overrides the two HTTP-backed fetch
methods, so the full mapping + snapshot pipeline is exercised without
any network access.
"""
from __future__ import annotations

from .workspace import WorkspaceConnector


class MockWorkspaceConnector(WorkspaceConnector):
    """In-memory Google Workspace connector."""

    def __init__(self) -> None:
        super().__init__(lambda: "fake-token", customer="test-customer")

    def _fetch_users(self) -> list[dict]:
        return [
            {
                "id": "u1",
                "primaryEmail": "alice@acme.test",
                "name": {"fullName": "Alice Engineer"},
                "suspended": False,
                "isEnrolledIn2Sv": True,
                "isEnforcedIn2Sv": True,
                "lastLoginTime": "2026-08-01T10:00:00.000Z",
            },
            {
                "id": "u2",
                "primaryEmail": "bob@acme.test",
                "name": {"fullName": "Bob Product"},
                "suspended": False,
                "isEnrolledIn2Sv": False,
                "isEnforcedIn2Sv": False,
                "lastLoginTime": "2026-08-10T10:00:00.000Z",
            },
            {
                "id": "u3",
                "primaryEmail": "carol@acme.test",
                "name": {"fullName": "Carol Stale"},
                "suspended": False,
                "lastLoginTime": "2025-01-15T10:00:00.000Z",
            },
        ]

    def _fetch_user_tokens(self, user_key: str) -> list[dict]:
        grants = {
            "alice@acme.test": [
                {"clientId": "c1", "displayText": "ChatGPT Enterprise", "scopes": ["https://www.googleapis.com/auth/mail.read"], "nativeApp": False},
                {"clientId": "c2", "displayText": "Fireflies.ai", "scopes": ["https://www.googleapis.com/auth/calendar"], "nativeApp": False},
            ],
            "bob@acme.test": [
                {"clientId": "c3", "displayText": "Notion AI", "scopes": ["https://www.googleapis.com/auth/drive.readonly"], "nativeApp": False},
            ],
            "carol@acme.test": [
                {"clientId": "c4", "displayText": "Zapier AI", "scopes": ["https://www.googleapis.com/auth/mail", "https://www.googleapis.com/auth/drive"], "nativeApp": False},
                {"clientId": "c5", "displayText": "Perplexity Enterprise", "scopes": ["https://www.googleapis.com/auth/devstorage.read_only"], "nativeApp": False},
            ],
        }
        return grants.get(user_key, [])