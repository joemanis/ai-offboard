"""High-level scan orchestration shared by the CLI and the web UI.

A scan is: connect -> snapshot -> catalog match -> risk findings -> report.
Keeping it here means `offboard audit`, the web UI, and tests all call the
same code path.
"""
from __future__ import annotations

from dataclasses import dataclass

from .audit.report import render_html, render_markdown
from .audit.risk import run_rules
from .catalog.matcher import load_catalog
from .connectors.base import Connector, TenantSnapshot


@dataclass
class ScanResult:
    snapshot: TenantSnapshot
    findings: list
    report_md: str
    report_html: str


def run_scan(connector: Connector, tenant_id: str) -> ScanResult:
    """Run a full read-only scan and render the audit report."""
    snapshot = connector.snapshot(tenant_id)
    catalog = load_catalog()
    findings = run_rules(snapshot, apps=catalog)
    return ScanResult(
        snapshot=snapshot,
        findings=findings,
        report_md=render_markdown(snapshot, findings),
        report_html=render_html(snapshot, findings),
    )


def write_report(result: ScanResult, out_dir: str, base: str = "ai-offboard-report") -> tuple[str, str]:
    """Persist the report to <out_dir>/<base>.md and <base>.html.
    Returns (md_path, html_path).
    """
    import os

    os.makedirs(out_dir, exist_ok=True)
    md_path = os.path.join(out_dir, f"{base}.md")
    html_path = os.path.join(out_dir, f"{base}.html")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(result.report_md)
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(result.report_html)
    return md_path, html_path