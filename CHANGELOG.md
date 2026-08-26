# Changelog

## Unreleased

Focused AI access cleanup scope.

### Changed
- Removed general sign-in posture from the default scan, risk rules, policy bundle, and progress stages.
- Added opt-in `offboard audit --sign-in-context` enrichment for tenants that explicitly need sign-in activity.
- Renamed the default policy bundle from generic Zero Trust checks to four AI access policies (`AI-001` through `AI-004`).
- Reworked the UI, reports, README, spec, connector guide, catalog notes, and sample reports around tenant-side connected, authorized, and provisioned AI applications.
- Updated dry-run remediation steps to prioritize removing AI assignments and connected-app access, with before/after verification as the next cleanup milestone.
- Documented that broad OAuth scopes are evaluated as `AI-003` only when the client matches the reviewed AI catalog; non-AI and unknown grants remain in raw inventory without creating AI findings.

## 0.4.2 (2026-08-18)

Noninteractive audit reliability patch.

### Fixed
- `audit --json` and `audit --bundle` now fail fast when the cached Microsoft
  login is missing or expired instead of blocking on a device-code prompt.
- Authentication failures are rendered as concise CLI errors instead of Rich
  tracebacks or invalid JSON output.

## 0.4.1 (2026-08-18)

Live-scan reliability patch.

### Fixed
- Resolve catalog-matched AI app assignments and application permissions through
  a bounded six-worker pool instead of serial 30-second Graph calls.
- Preserve explicit `not assessed` coverage when any assignment lookup returns
  HTTP 403.

## 0.4.0 (2026-08-18)

Audit evidence portability for MSP and insurance/compliance workflows.

### Added
- `offboard audit --bundle <path>` creates a self-contained evidence ZIP.
- Bundles include the Markdown and HTML reports, full machine-readable snapshot,
  findings JSON/CSV, coverage metadata, a manifest, and SHA-256 checksums.
- Bundle manifests record the package version, tenant, scan counts, and
  confidentiality handling warning.
- JSON stdout remains clean when bundle creation is combined with `--json`.

### Changed
- README now documents the evidence-bundle workflow and handling requirements.

## 0.3.0 (2026-08-17)

Trustworthy Entra inventory and safer operator workflows.

### Added
- Real Graph `appRoleAssignedTo` discovery for catalog-matched AI applications, including assigned principal and role attribution.
- Enterprise-app inventory counts are separated from actual app-role assignments.
- Delegated OAuth grants and application permissions now include client/resource names, consent type, and grant type where Graph provides them.
- Telemetry coverage states and explicit `NOT_ASSESSED` policy results when reports telemetry is unavailable.
- Remote web mode with explicit host opt-in, operator token, SameSite session cookie, cross-origin state-change protection, and POST-only logout.
- MSP guard preventing `audit --all` from reusing an interactive device-code session across tenants.
- Graph payload contract tests and a cross-platform built-wheel smoke-test matrix.

### Changed
- R4 no longer treats every Entra service principal as a high-privilege assignment.
- R5 findings use readable app/resource attribution and deduplicate identical grants.
- Reports expose data-coverage and app-role-assignment counts instead of overstating inventory.

## 0.2.0 (2026-08-15)

Zero Trust policy engine, gated remediation, MSP multi-tenant mode, Google Workspace. Full v1 → v3 roadmap delivered.

### Added
- **Zero Trust policy engine (v3):** declarative YAML policies evaluated against the scan inventory — `offboard policy list` / `policy check` (exit 0 = PASS, 2 = FAIL). Five bundled policies (ZT-001..ZT-005) including the default-deny approved-app allowlist. Named checks only — policy files can never execute code.
- **`offboard execute` (v2):** applies remediation (block sign-in, revoke tokens, remove app assignment) behind an explicit approval gate; every mutation logged to a local audit table.
- **Google Workspace connector:** reads users + OAuth-connected AI apps via Admin SDK Directory API (`offboard audit --workspace`); R5 scope normalization covers Google OAuth URLs. Full setup guide in `docs/connectors.md`.
- **Scheduled recurring audits:** `offboard schedule add/remove/list/run-due` (daily/weekly/monthly) with SMTP report delivery.
- **Multi-tenant MSP mode:** `offboard tenant add/remove/list` + `offboard audit --all` findings matrix.
- **Trend comparison:** `offboard report --compare` diffs the last two saved scans.
- **CSV export:** `offboard audit --csv`.
- **AI-app catalog** expanded 5 → 41 real tools with DLP tiers; specificity-aware matcher (longest match wins).
- **Web UI:** scan progress in CLI, pre-seeded sample report on first load, findings severity filter, Zero Trust policy compliance view.
- **PyPI publication:** `pip install "ai-offboard[web]"`.

### Changed
- Connector layer refactored around a `Connector` interface + auth providers (device code / client credentials); `build_connector` auto-detects.
- Device-code auth replaces App Registration as the recommended path — no tenant ID or client secret needed.

## 0.1.0 (2026-08-13)

Initial release — read-only Microsoft 365 AI tool audit and offboarding report tool.

### Added
- **Connector:** Microsoft Entra ID (Graph) read-only scanner via MSAL client credentials.
- **Mock connector:** deterministic demo snapshot — `offboard audit --mock` works with zero Azure setup.
- **AI-app catalog** (JSON) with DLP-risk tiers; substring matcher for fast community contributions.
- **Risk rules:** R1 disabled-account access, R4 high-privilege app, R5 broad OAuth grant.
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