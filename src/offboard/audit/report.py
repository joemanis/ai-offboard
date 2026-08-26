"""Audit report rendering (Markdown + HTML).

The report is the product: a plain-English document a non-technical auditor,
insurer, or compliance reviewer can read. v1 renders from a TenantSnapshot +
findings list.
"""
from __future__ import annotations

import html

from ..connectors.base import TenantSnapshot
from .risk import Finding


def render_markdown(snapshot: TenantSnapshot, findings: list[Finding]) -> str:
    lines = [
        "# AI-Offboard AI Access Report",
        "",
        f"- **Tenant:** {snapshot.tenant_id}",
        f"- **Scanned at:** {snapshot.scanned_at}",
        f"- **Principals scanned:** {len(snapshot.principals)}",
        f"- **Enterprise apps:** {snapshot.enterprise_app_count if snapshot.enterprise_app_count is not None else len(snapshot.app_assignments)}",
        f"- **App-role assignments:** {len(snapshot.app_assignments)}",
        "",
    ]
    if snapshot.coverage:
        lines.extend(
            [
                "",
                "## Evidence coverage",
                "",
                *[f"- **{name.replace('_', ' ').title()}:** {state}" for name, state in sorted(snapshot.coverage.items())],
                *[
                    f"  - **Note:** {snapshot.coverage_notes[name]}"
                    for name in sorted(snapshot.coverage_notes)
                    if name in snapshot.coverage
                ],
            ]
        )
    if not findings:
        lines.append("No findings. Clean scan.")
        return "\n".join(lines) + "\n"

    lines.append("## Findings")
    lines.append("")
    lines.append("| Severity | Rule | Subject | Evidence |")
    lines.append("| --- | --- | --- | --- |")
    for f in findings:
        evidence = f.evidence.replace("|", "\\|")
        lines.append(f"| {f.severity} | {f.rule_id} | {f.subject} | {evidence} |")
    lines.append("")
    lines.append("## Remediation steps (dry-run)")
    lines.append("")
    for f in findings:
        lines.append(f"- **{f.subject} ({f.rule_id}):**")
        for step in f.remediation:
            lines.append(f"  - {step}")
    return "\n".join(lines) + "\n"


def render_html(snapshot: TenantSnapshot, findings: list[Finding]) -> str:
    md = render_markdown(snapshot, findings)
    body = html.escape(md).replace("\n", "<br>")
    return f"<!doctype html><html><head><meta charset='utf-8'><title>AI-Offboard Report</title></head><body>{body}</body></html>"
