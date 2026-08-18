"""High-level scan orchestration shared by the CLI and the web UI.

A scan is: connect -> snapshot -> catalog match -> risk findings -> report.
Keeping it here means `offboard audit`, the web UI, and tests all call the
same code path.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import zipfile
from collections.abc import Callable
from dataclasses import asdict, dataclass

from . import __version__
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


def run_scan(
    connector: Connector,
    tenant_id: str,
    progress_callback: Callable[[str], None] | None = None,
    save: bool = False,
) -> ScanResult:
    """Run a full read-only scan and render the audit report.

    When save=True the result is persisted to the local SQLite store so
    `offboard report --last` can re-render it without re-scanning.
    """
    snapshot = connector.snapshot(tenant_id, progress_callback=progress_callback)
    catalog = load_catalog()
    findings = run_rules(snapshot, apps=catalog)
    result = ScanResult(
        snapshot=snapshot,
        findings=findings,
        report_md=render_markdown(snapshot, findings),
        report_html=render_html(snapshot, findings),
    )
    if save:
        from .store import save_scan

        save_scan(result)
    return result


def write_report(result: ScanResult, out_dir: str, base: str = "ai-offboard-report") -> tuple[str, str]:
    """Persist the report to <out_dir>/<base>.md and <base>.html.
    Returns (md_path, html_path).
    """
    os.makedirs(out_dir, exist_ok=True)
    md_path = os.path.join(out_dir, f"{base}.md")
    html_path = os.path.join(out_dir, f"{base}.html")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(result.report_md)
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(result.report_html)
    return md_path, html_path


def write_findings_csv(result: ScanResult, path: str) -> str:
    """Export findings to a CSV file for ingestion into MSP tooling.

    Returns the path written.
    """
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            ["tenant_id", "scanned_at", "severity", "rule_id", "subject", "evidence", "remediation"]
        )
        for finding in result.findings:
            writer.writerow(
                [
                    result.snapshot.tenant_id,
                    result.snapshot.scanned_at,
                    finding.severity,
                    finding.rule_id,
                    finding.subject,
                    finding.evidence,
                    " | ".join(finding.remediation),
                ]
            )
    return path


def write_evidence_bundle(result: ScanResult, path: str) -> str:
    """Write a self-contained ZIP of the scan evidence for an auditor or MSP.

    The bundle contains human-readable reports plus machine-readable snapshot
    and findings data with SHA-256 checksums. It contains tenant identifiers and
    principal names, so treat it as confidential customer evidence.
    """
    snapshot_data = asdict(result.snapshot)
    findings_data = [asdict(finding) for finding in result.findings]
    csv_buffer = io.StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(["tenant_id", "scanned_at", "severity", "rule_id", "subject", "evidence", "remediation"])
    for finding in result.findings:
        writer.writerow(
            [
                result.snapshot.tenant_id,
                result.snapshot.scanned_at,
                finding.severity,
                finding.rule_id,
                finding.subject,
                finding.evidence,
                " | ".join(finding.remediation),
            ]
        )

    artifacts = {
        "snapshot.json": json.dumps(snapshot_data, indent=2, sort_keys=True) + "\n",
        "findings.json": json.dumps(findings_data, indent=2, sort_keys=True) + "\n",
        "findings.csv": csv_buffer.getvalue(),
        "report.md": result.report_md,
        "report.html": result.report_html,
    }
    checksums = {
        name: hashlib.sha256(content.encode("utf-8")).hexdigest()
        for name, content in artifacts.items()
    }
    manifest = {
        "schema_version": "1",
        "product": "ai-offboard",
        "product_version": __version__,
        "tenant_id": result.snapshot.tenant_id,
        "scanned_at": result.snapshot.scanned_at,
        "counts": {
            "principals": len(result.snapshot.principals),
            "enterprise_apps": result.snapshot.enterprise_app_count
            if result.snapshot.enterprise_app_count is not None
            else len(result.snapshot.app_assignments),
            "app_role_assignments": len(result.snapshot.app_assignments),
            "permission_grants": len(result.snapshot.permission_grants),
            "findings": len(result.findings),
        },
        "coverage": result.snapshot.coverage,
        "files": checksums,
        "confidentiality": "Contains tenant and principal identifiers; handle as confidential evidence.",
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        for name, content in artifacts.items():
            bundle.writestr(name, content)
        bundle.writestr(
            "checksums.sha256",
            "".join(f"{digest}  {name}\n" for name, digest in checksums.items()),
        )
    return path
