"""Scan comparison / trend analysis.

Diffs findings between two saved scans (past vs present) so an MSP can show
a customer "6 findings (was 8 last month) - R4 resolved, R1 stale@x.com new".
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class FindingDelta:
    rule_id: str
    severity: str
    subject: str
    status: str  # new | resolved | unchanged


def _key(f: dict[str, Any]) -> tuple[str, str]:
    """Identity key for a finding: (rule_id, subject)."""
    return (f.get("rule_id", ""), f.get("subject", ""))


def compare_scans(past: dict[str, Any], present: dict[str, Any]) -> list[FindingDelta]:
    """Diff the findings of two stored scan rows (both must have findings_json)."""
    import json

    def _extract(row: dict[str, Any]) -> list[dict[str, Any]]:
        raw = row.get("findings")
        if isinstance(raw, list):
            return raw
        blob = row.get("findings_json") or "[]"
        try:
            parsed = json.loads(blob)
            return parsed if isinstance(parsed, list) else []
        except (json.JSONDecodeError, TypeError):
            return []

    past_map = {_key(f): f for f in _extract(past)}
    present_map = {_key(f): f for f in _extract(present)}

    deltas: list[FindingDelta] = []
    for key, f in present_map.items():
        if key in past_map:
            deltas.append(FindingDelta(f["rule_id"], f["severity"], f["subject"], "unchanged"))
        else:
            deltas.append(FindingDelta(f["rule_id"], f["severity"], f["subject"], "new"))
    for key, f in past_map.items():
        if key not in present_map:
            deltas.append(FindingDelta(f["rule_id"], f["severity"], f["subject"], "resolved"))
    return deltas


def trend_summary(deltas: list[FindingDelta]) -> str:
    """One-line trend: '6 findings (was 8, +2 new, -4 resolved)'."""
    new = sum(1 for d in deltas if d.status == "new")
    resolved = sum(1 for d in deltas if d.status == "resolved")
    return f"+{new} new, -{resolved} resolved"


def render_trend_table(past: dict[str, Any], present: dict[str, Any], deltas: list[FindingDelta]) -> str:
    past_count = int(past.get("finding_count", 0))
    present_count = int(present.get("finding_count", 0))
    lines = [
        "## Trend (last two scans)",
        "",
        f"- **Previous scan:** {past.get('scanned_at', '?')} — {past_count} findings",
        f"- **Latest scan:** {present.get('scanned_at', '?')} — {present_count} findings",
        f"- **Delta:** {trend_summary(deltas)}",
        "",
        "| Status | Rule | Subject |",
        "| --- | --- | --- |",
    ]
    ordered = sorted(deltas, key=lambda d: (d.status != "new", d.status != "resolved"))
    for d in ordered:
        lines.append(f"| {d.status} | {d.rule_id} | {d.subject} |")
    return "\n".join(lines) + "\n"