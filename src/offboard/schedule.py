"""Scheduled recurring audits + report delivery.

`offboard schedule add --tenant X --interval <daily|weekly|monthly>` registers
a recurring audit in the local store. `offboard schedule run-due` finds due
jobs, runs each scan, saves it, and delivers the report (email if SMTP is
configured, otherwise writes to the report directory). Intended to be driven
by an OS scheduler (cron on Linux/macOS, Task Scheduler on Windows) calling
`offboard schedule run-due`.

SMTP env vars (for email delivery):
  OFFBOARD_SMTP_HOST, OFFBOARD_SMTP_PORT, OFFBOARD_SMTP_USER,
  OFFBOARD_SMTP_PASS, OFFBOARD_MAIL_FROM, OFFBOARD_MAIL_TO
"""
from __future__ import annotations

import os
import smtplib
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Any


def _due_check(schedule: str, last_run: str | None) -> bool:
    """True when the job should run now based on its interval."""
    if last_run is None:
        return True
    try:
        last = datetime.fromisoformat(last_run)
    except ValueError:
        return True
    now = datetime.now(UTC)
    delta = now - last
    if schedule == "daily":
        return delta.days >= 1
    if schedule == "weekly":
        return delta.days >= 7
    if schedule == "monthly":
        return delta.days >= 30
    return True  # manual / unknown interval -> always run


def run_due(config: Any, connector, report_dir: str = "reports") -> list[dict]:
    """Run all due scheduled audits. Returns a summary list of dicts."""
    from .scan import run_scan, write_report
    from .store import list_schedules, touch_schedule

    results = []
    for job in list_schedules():
        if not _due_check(job["schedule"], job["last_run"]):
            continue
        try:
            result = run_scan(connector, job["tenant_id"], save=True)
            md_path, html_path = write_report(result, report_dir)
            touch_schedule(job["id"])
            deliver_report(
                subject=f"AI access audit: {job['tenant_id']} ({len(result.findings)} findings)",
                body=f"Findings: {len(result.findings)}\n\nSee attached report.",
                attachments=[md_path, html_path],
            )
            results.append(
                {"tenant": job["tenant_id"], "findings": len(result.findings), "delivered": True}
            )
        except Exception as exc:  # noqa: BLE001 - a failing schedule shouldn't kill the sweep
            results.append({"tenant": job["tenant_id"], "findings": "ERR", "delivered": False, "error": str(exc)})
    return results


def deliver_report(subject: str, body: str, attachments: list[str]) -> None:
    """Send the report via SMTP when configured; otherwise print the path.

    SMTP config comes from OFFBOARD_* env vars; if missing, delivery is a
    no-op with a note (the scheduler still wrote the report files).
    """

    host = os.environ.get("OFFBOARD_SMTP_HOST")
    if not host:
        print("[schedule] SMTP not configured; report written locally only.")
        return
    port = int(os.environ.get("OFFBOARD_SMTP_PORT", "587"))
    user = os.environ.get("OFFBOARD_SMTP_USER", "")
    password = os.environ.get("OFFBOARD_SMTP_PASS", "")
    mail_from = os.environ.get("OFFBOARD_MAIL_FROM", user)
    mail_to = os.environ.get("OFFBOARD_MAIL_TO", user)

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = mail_from
    msg["To"] = mail_to
    msg.set_content(body)
    for path in attachments:
        with open(path, "rb") as fh:
            msg.add_attachment(
                fh.read(),
                maintype="application",
                subtype="octet-stream",
                filename=os.path.basename(path),
            )

    with smtplib.SMTP(host, port) as smtp:
        smtp.starttls()
        if user:
            smtp.login(user, password)
        smtp.send_message(msg)
    print(f"[schedule] Report emailed to {mail_to}")