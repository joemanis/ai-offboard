"""Abstract connector interface for tenant scanners.

Every connector implements the same read-only view over a tenant so that
audit/scanner code stays connector-agnostic. In v1 only Microsoft Entra ID is
implemented; Google Workspace lands in phase 1b behind this same interface.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass
class Principal:
    """A user or service principal in the tenant."""

    id: str
    name: str
    type: str  # "user" | "service_principal"
    enabled: bool = True
    sign_in_last_seen: str | None = None  # optional sign-in context


@dataclass
class AppAssignment:
    """A real principal-to-application role assignment."""

    principal_id: str
    app_display_name: str
    app_role_id: str | None = None
    is_high_privilege: bool = False
    principal_display_name: str | None = None
    principal_type: str | None = None
    role_display_name: str | None = None
    app_id: str | None = None


@dataclass
class PermissionGrant:
    """A service principal's delegated or application permission grant."""

    app_id: str
    resource: str
    scope: str
    grant_type: str  # "delegated" | "application"
    app_display_name: str | None = None
    resource_display_name: str | None = None
    consent_type: str | None = None
    principal_id: str | None = None
    principal_display_name: str | None = None


@dataclass
class TenantSnapshot:
    """Immutable read-only view of a tenant at scan time."""

    tenant_id: str
    scanned_at: str
    principals: list[Principal] = field(default_factory=list)
    app_assignments: list[AppAssignment] = field(default_factory=list)
    permission_grants: list[PermissionGrant] = field(default_factory=list)
    enterprise_app_count: int | None = None
    coverage: dict[str, str] = field(default_factory=dict)
    coverage_notes: dict[str, str] = field(default_factory=dict)


class Connector(ABC):
    """Read-only tenant scanner."""

    @abstractmethod
    def snapshot(
        self,
        tenant_id: str,
        progress_callback: Callable[[str], None] | None = None,
        sign_in_context: bool = False,
    ) -> TenantSnapshot:
        """Return a read-only snapshot. MUST NOT perform any write.

        Optional sign-in context is disabled for the core AI-access scan.
        """
