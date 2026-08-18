"""Zero Trust policy engine (v3).

Evaluates a declarative set of policies (YAML) against the audit inventory
(TenantSnapshot + risk Findings). Each policy uses a *named* check with
parameters — there is deliberately no `eval`/arbitrary expression support, so
opening a policy file cannot execute code. This keeps "policy as code" safe to
share and contribute.

A PolicyEvaluation records whether the tenant COMPLIES, plus the evidence.
Policy violations are what plan/execute remediates.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .audit.risk import Finding, run_rules
from .catalog.matcher import match_app
from .connectors.base import TenantSnapshot

# Path(__file__) = <repo>/src/offboard/policy.py -> parent = src/offboard
_POLICY_DIR = Path(__file__).parent / "policies"
_DEFAULT_IMPORT_PATH = _POLICY_DIR / "default" / "baseline.yml"


@dataclass
class Policy:
    id: str
    name: str
    description: str
    severity: str  # low | medium | high | critical
    check: str  # name of a registered check
    params: dict[str, Any] = field(default_factory=dict)
    applies_to: str = "all"  # all | m365 | workspace
    default: bool = False

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Policy:
        return cls(
            id=d["id"],
            name=d["name"],
            description=d.get("description", ""),
            severity=d.get("severity", "medium"),
            check=d["check"],
            params=d.get("params", {}),
            applies_to=d.get("applies_to", "all"),
            default=d.get("default", False),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "check": self.check,
            "params": self.params,
            "applies_to": self.applies_to,
            "default": self.default,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class PolicyEvaluation:
    policy: Policy
    compliant: bool
    evidence: list[str] = field(default_factory=list)
    subjects: list[str] = field(default_factory=list)
    status: str = "assessed"  # assessed | not_assessed

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy.id,
            "name": self.policy.name,
            "severity": self.policy.severity,
            "compliant": self.compliant,
            "status": self.status,
            "evidence": self.evidence,
            "subjects": self.subjects,
        }


# ---------------------------------------------------------------------------
# Named checks. Each takes (policy, snapshot, findings, params).
# ---------------------------------------------------------------------------

def _check_stale_access(policy: Policy, snapshot: TenantSnapshot, findings: list[Finding], params: dict[str, Any]) -> PolicyEvaluation:
    related = [f for f in findings if f.rule_id == "R1"]
    if related:
        return PolicyEvaluation(policy, False, [f.evidence for f in related], [f.subject for f in related])
    return PolicyEvaluation(policy, True, ["No stale or orphaned access detected."])


def _check_mfa_enforced(policy: Policy, snapshot: TenantSnapshot, findings: list[Finding], params: dict[str, Any]) -> PolicyEvaluation:
    related = [f for f in findings if f.rule_id == "R2"]
    coverage = snapshot.coverage.get("mfa")
    if coverage is None:
        coverage = "assessed" if all(p.mfa_state is not None for p in snapshot.principals) else "not_assessed"
    if coverage != "assessed":
        return PolicyEvaluation(
            policy,
            False,
            ["MFA registration telemetry was not collected; this policy is not assessed."],
            status="not_assessed",
        )
    if related:
        return PolicyEvaluation(policy, False, [f.evidence for f in related], [f.subject for f in related])
    return PolicyEvaluation(policy, True, ["All assessed enabled principals have MFA registration."])


def _check_no_high_privilege_apps(policy: Policy, snapshot: TenantSnapshot, findings: list[Finding], params: dict[str, Any]) -> PolicyEvaluation:
    related = [f for f in findings if f.rule_id == "R4"]
    if related:
        return PolicyEvaluation(policy, False, [f.evidence for f in related], [f.subject for f in related])
    return PolicyEvaluation(policy, True, ["No high-privilege AI app assignments."])


def _check_no_broad_grants(policy: Policy, snapshot: TenantSnapshot, findings: list[Finding], params: dict[str, Any]) -> PolicyEvaluation:
    related = [f for f in findings if f.rule_id == "R5"]
    if related:
        return PolicyEvaluation(policy, False, [f.evidence for f in related], [f.subject for f in related])
    return PolicyEvaluation(policy, True, ["No OAuth grants request broad/sensitive scopes."])


def _check_unapproved_apps(policy: Policy, snapshot: TenantSnapshot, findings: list[Finding], params: dict[str, Any]) -> PolicyEvaluation:
    """Any catalog-matched app without an entry in `approved` (by name) is a policy breach.

    This is the "allowlist / Zero Trust" core: nothing AI is trusted by default.
    """
    approved = {str(a).lower() for a in params.get("approved", [])}
    breaches: list[str] = []
    subjects: list[str] = []
    for a in snapshot.app_assignments:
        entry = match_app(a.app_display_name)
        if entry and entry.name.lower() not in approved:
            breaches.append(f"App '{a.app_display_name}' is not on the approved AI-app allowlist.")
            subjects.append(a.app_display_name)
    if breaches:
        return PolicyEvaluation(policy, False, breaches, subjects)
    return PolicyEvaluation(policy, True, ["All AI apps are on the approved allowlist."])


# policy, snapshot, findings, params -> PolicyEvaluation
_Check = Callable[[Policy, TenantSnapshot, list[Finding], dict[str, Any]], PolicyEvaluation]

_registry: dict[str, _Check] = {
    "stale_access": _check_stale_access,
    "mfa_enforced": _check_mfa_enforced,
    "no_high_privilege_apps": _check_no_high_privilege_apps,
    "no_broad_grants": _check_no_broad_grants,
    "unapproved_apps": _check_unapproved_apps,
}


# ---------------------------------------------------------------------------
# Loading + evaluation
# ---------------------------------------------------------------------------

def load_policies(path: Path | None = None) -> list[Policy]:
    """Load policies from a YAML file (default bundled baseline)."""
    path = path or _DEFAULT_IMPORT_PATH
    if not path.exists():
        return []
    try:
        import yaml
    except ImportError:
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return [Policy.from_dict(p) for p in data.get("policies", [])]


def list_checks() -> list[str]:
    return sorted(_registry.keys())


def evaluate(
    snapshot: TenantSnapshot,
    findings: list[Finding] | None = None,
    policies: list[Policy] | None = None,
) -> list[PolicyEvaluation]:
    """Evaluate policies against a snapshot (plus its risk findings)."""
    policies = policies or load_policies()
    if findings is None:
        findings = run_rules(snapshot)
    results: list[PolicyEvaluation] = []
    for policy in policies:
        checker = _registry.get(policy.check)
        if checker is None:
            results.append(
                PolicyEvaluation(policy, False, [f"Unknown check '{policy.check}'. Policy must be reviewed."])
            )
            continue
        results.append(checker(policy, snapshot, findings, policy.params))
    return results


def summarize(evaluations: list[PolicyEvaluation]) -> dict[str, Any]:
    """Compress evaluations into a compliance summary for reports/CLI."""
    total = len(evaluations)
    compliant = sum(1 for e in evaluations if e.compliant)
    violations = [e for e in evaluations if not e.compliant and e.status != "not_assessed"]
    severities = ["critical", "high", "medium", "low"]
    by_severity = {s: len([e for e in violations if e.policy.severity == s]) for s in severities}
    not_assessed = sum(1 for e in evaluations if e.status == "not_assessed")
    overall = "FAIL" if violations else ("NOT_ASSESSED" if not_assessed else "PASS")
    return {
        "total": total,
        "compliant": compliant,
        "violations": len(violations),
        "not_assessed": not_assessed,
        "by_severity": by_severity,
        "overall": overall,
    }