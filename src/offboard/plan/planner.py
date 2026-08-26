"""Dry-run AI access cleanup planner.

Given findings, emit exact, typed cleanup steps. This module NEVER executes
anything; it only produces StepSpec objects. `offboard execute` is the only
place writes would ever happen, behind an explicit approval gate.
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
    """Produce AI access cleanup steps for a single finding.

    dry_run=True (default) guarantees no execution path is reachable here.
    """
    steps: list[StepSpec] = []
    if finding.rule_id == "R1":
        steps.append(StepSpec("remove_assignment", finding.subject, "Review and remove connected AI app assignments.", risky=True))
        steps.append(StepSpec("revoke_token", finding.subject, "Revoke active app tokens/SSO sessions where supported.", risky=True))
    elif finding.rule_id == "R4":
        steps.append(StepSpec("remove_assignment", finding.subject, "Review and remove high-priv app assignment.", risky=True))
        steps.append(StepSpec("revoke_token", finding.subject, "Revoke the app's active grants.", risky=True))
    return steps
