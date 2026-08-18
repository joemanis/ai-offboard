from __future__ import annotations

import json
import os
import zipfile

from offboard.config import Config, load_config, parse_env_file, write_env_file
from offboard.connectors.mock import MockConnector
from offboard.scan import run_scan, write_evidence_bundle, write_report


def test_config_load_from_env(monkeypatch):
    monkeypatch.setenv("OFFBOARD_CLIENT_ID", "cid")
    monkeypatch.setenv("OFFBOARD_CLIENT_SECRET", "secret")
    monkeypatch.setenv("OFFBOARD_TENANT_ID", "tid")
    cfg = load_config()
    assert cfg.is_complete
    assert cfg.client_id == "cid"


def test_config_incomplete_without_secret():
    cfg = Config(client_id="c", client_secret="", tenant_id="t")
    assert not cfg.is_complete


def test_env_file_roundtrip(tmp_path):
    p = str(tmp_path / ".env")
    write_env_file(p, Config(client_id="c", client_secret="s", tenant_id="t"))
    parsed = parse_env_file(p)
    assert parsed["OFFBOARD_CLIENT_ID"] == "c"
    assert parsed["OFFBOARD_CLIENT_SECRET"] == "s"
    assert parsed["OFFBOARD_TENANT_ID"] == "t"


def test_run_scan_produces_report(tmp_path):
    conn = MockConnector()
    result = run_scan(conn, "demo")
    assert len(result.snapshot.principals) == 3
    assert any(f.rule_id == "R1" for f in result.findings)  # stale disabled
    assert any(f.rule_id == "R2" for f in result.findings)  # no mfa
    assert any(f.rule_id == "R4" for f in result.findings)  # high-priv copilot
    assert "[deleted]" not in result.report_md
    assert "# ai-offboard" in result.report_md.lower()


def test_write_report_files(tmp_path):
    result = run_scan(MockConnector(), "demo")
    md, html = write_report(result, str(tmp_path))
    assert os.path.exists(md)
    assert os.path.exists(html)
    assert os.path.getsize(md) > 0


def test_write_evidence_bundle_contains_auditable_artifacts(tmp_path):
    result = run_scan(MockConnector(), "demo")
    bundle_path = write_evidence_bundle(result, str(tmp_path / "audit.zip"))

    assert bundle_path == str(tmp_path / "audit.zip")
    with zipfile.ZipFile(bundle_path) as bundle:
        names = set(bundle.namelist())
        assert {
            "manifest.json",
            "snapshot.json",
            "findings.json",
            "findings.csv",
            "report.md",
            "report.html",
        } <= names
        manifest = json.loads(bundle.read("manifest.json"))
        snapshot = json.loads(bundle.read("snapshot.json"))
        assert manifest["schema_version"] == "1"
        assert manifest["tenant_id"] == "demo"
        assert manifest["counts"]["findings"] == len(result.findings)
        assert snapshot["coverage"] == result.snapshot.coverage
        assert snapshot["principals"]
