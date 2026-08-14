# Changelog

## 0.1.0 (2026-08-13)

Initial release — read-only Microsoft 365 AI tool audit and offboarding report tool.

### Added
- **Connector:** Microsoft Entra ID (Graph) read-only scanner via MSAL client credentials.
- **Mock connector:** deterministic demo snapshot — `offboard audit --mock` works with zero Azure setup.
- **AI-app catalog** (JSON) with DLP-risk tiers; substring matcher for fast community contributions.
- **Risk rules:** R1 stale/unused accounts, R2 MFA gap, R4 high-privilege app.
- **Dry-run revocation planner** — typed revoke steps, provably executes nothing.
- **Audit report** — Markdown + HTML output with findings table and remediation steps.
- **JSON output** — `offboard audit --json` for machine consumption.
- **CLI:** `audit` (--report, --mock, --json), `plan` (--mock), `setup` (interactive wizard), `doctor` (pre-flight checks), `web` (local UI), `--version`.
- **Setup wizard** (`offboard setup`) — one-time interactive connector configuration that writes `.env`.
- **Local web UI** (`offboard web`) — FastAPI-based dashboard with scan results, drill-down, and report download.
- **Pre-flight doctor** (`offboard doctor`) — validates `.env`, config completeness, and auth connectivity.
- **README** with full usage, screenshots, and quick-start.
- **Docs:** `docs/connectors.md` (Entra App Registration guide), `SPEC.md` (build spec), `examples/` (sample reports + screenshots).
- **CI:** GitHub Actions (ruff + pytest on push/PR).
- **Security posture:** read-only by design (v1), `SECURITY.md`, Apache-2.0 license.