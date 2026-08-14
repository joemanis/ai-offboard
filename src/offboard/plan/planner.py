"""Dry-run revocation planner.

Given findings, emit exact, typed revoke steps. This module NEVER executes
anything; it only produces StepSpec objects. `offboard execute` (v2) is the
only place writes would ever happen, behind an explicit approval gate.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..audit.risk import Finding


@dataclass
class StepSpec:
    action: str  # block_signin | revoke_license | remove_assignment | revoke_token
    target: str
    detail: str
    risky: bool


def plan_for_finding(finding: Finding, dry_run: bool = True) -> list[StepSpec]:
    """Produce revocation steps for a single finding.

    dry_run=True (default) guarantees no execution path is reachable here.
    """
    steps: list[StepSpec] = []
    if finding.rule_id == "R1":
        steps.append(StepSpec("block_signin", finding.subject, "Disable sign-in for stale account.", risky=True))
        steps.append(StepSpec("revoke_token", finding.subject, "Revoke active tokens/SSO sessions.", risky=True))
    elif finding.rule_id == "R2":
        steps.append(StepSpec("block_signin", finding.subject, "Enforce MFA before further access.", risky=False))
    elif finding.rule_id == "R4":
        steps.append(StepSpec("remove_assignment", finding.subject, "Review and remove high-priv app assignment.", risky=True))
        steps.append(StepSpec("revoke_token", finding.subject, "Revoke the app's active grants.", risky=True))
    return steps
