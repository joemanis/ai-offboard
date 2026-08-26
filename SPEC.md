# AI-Offboard — v1 Build Spec

**Working title:** `AI-Offboard`
**Status:** Draft v0.1
**Owner:** Joe
**Thesis:** The SMB/MSP market has a loud, unfilled problem — no one can catalog the AI tools in use, see what data they touch, or prove on departure that access was revoked. Enterprise DLP vendors (Prompt Security / SentinelOne, Island Browser) chase the big-org blocking market and ignore the SMB audit-and-revoke-at-departure moment. That moment produces a compliance artifact an insurer, SOC2, or renewal actually accepts.

**Positioning (one line):**
> Find unwanted AI access, remove it with approval, and verify the cleanup.

## North-star principle
Ship the **cleanup evidence**, not another firewall. The product inventories connected tenant-side AI applications, explains their assignments and data reach, produces an approval-gated cleanup plan, and verifies what changed. General identity posture and DLP blocking are outside the core product.

## Tech decision
- **Language:** Python 3.11+. Rich, stable SDKs for Microsoft Graph and Google Workspace; fastest path from idea to audit PDF; easiest open-source contribution surface.
- **Form factor:** CLI-first, read-only in v1. `offboard audit --tenant X` → report. `offboard plan --user jdoe` → dry-run AI access cleanup plan. (`offboard execute` is v2, behind an explicit approval gate.)
- **No DB in v1.** Write the report to a file (Markdown + HTML). A local SQLite store is deferred to v2. Keeps scope tight.

## Repo structure
```
ai-offboard/
├── README.md
├── LICENSE                    (Apache-2.0 — contributor-friendly, MSP-safe)
├── SECURITY.md
├── CONTRIBUTING.md
├── pyproject.toml
├── .github/
│   ├── workflows/ci.yml
│   └── ISSUE_TEMPLATE/
├── src/offboard/
│   ├── __init__.py
│   ├── cli.py                 (typer/click interface)
│   ├── config.py              (tenant, auth, scopes)
│   ├── connectors/
│   │   ├── base.py            (abstract Connector: iter_users, iter_apps, iter_grants)
│   │   ├── entra.py           (Microsoft Entra ID / Graph)
│   │   └── google.py          (Workspace — phase 1b)
│   ├── catalog/
│   │   ├── apps.json          (AI-app catalog: name, DLP tier, scopes it needs)
│   │   └── matcher.py         (map detected principal/app → catalog entry)
│   ├── audit/
│   │   ├── scanner.py         (orchestrate connector reads + catalog match)
│   │   ├── risk.py            (risk rules → findings)
│   │   └── report.py          (render Markdown + HTML)
│   └── plan/
│       ├── planner.py         (dry-run: exact revoke steps per finding)
│       └── stepspec.py        (typed list of revoke actions)
├── tests/
│   ├── fixtures/
│   └── test_risk.py
├── examples/
│   └── sample-report.md
└── docs/
    ├── connectors.md
    └── risk-rules.md
```

## v1 Scope — trim to this
### Phase A (MVP — must ship)
- **Read-only Microsoft Entra ID connector** (Graph):
  - Users and groups: display name, UPN, account enabled, and assignments relevant to AI access. Sign-in activity is optional context and is not part of core findings.
  - Group/app membership + **app role assignments**.
  - **Service principals** and their **delegated/application permission grants** (the "what can this AI agent reach" signal).
- **AI-app catalog** (`catalog/apps.json`): map detected principals/apps/domains to known AI tools, each tagged with a **DLP-risk tier** (Low/Medium/High) based on the scopes they request (e.g. `Mail.Read`, `Files.ReadWrite.All` = High).
- **Risk rules** → findings:
  1. Disabled user or group still has connected AI access.
  2. Unknown or unapproved AI application remains connected.
  3. AI app has high-tier scopes or broad tenant reach.
  4. Residual OAuth consent, role assignment, or application permission needs removal.
- **Cleanup PLAN (dry-run first).** For each finding, emit exact steps such as remove assignment, revoke consent or tokens, disable an account where approved, and rescan to verify. Nothing executes without approval.
- **Audit report** (Markdown + HTML): tenant summary, catalog inventory, findings table, remediation plan, and a generated **"compliance artifact"** section suitable to hand to a broker/auditor.

### Explicitly NOT in v1
- Any write/revoke execution (v2).
- Google Workspace connector (phase 1b).
- Database, web UI, daemon, multi-tenant SaaS backend.
- DLP/blocking/monitoring (that's the enterprise space you're not competing in yet).

## Data model (core types, v1)
- `TenantSnapshot` — tenant id, display name, scan time.
- `Principal` — type (user|service_principal|group), upn/id, enabled, optional sign-in timestamp.
- `AppAssignment` — principal → app (id, displayName, appRoleId, isHighPrivilege).
- `PermissionGrant` — app/service principal → resource + permission scope (delegated|app).
- `Finding` — rule id, severity, subject, evidence, remediation steps.
- `AuditReport` — snapshot + catalog inventory + findings + remediation.

## MVP acceptance criteria
A scan is successful when, against a test tenant:
1. `offboard audit --tenant T` returns exit 0, lists connected AI applications, assignments, service-principal grants, and data-access scopes. Identity context is not required.
2. Catalog matching works: a known AI app (e.g. an M365 Copilot-like principal or a named enterprise AI app in `apps.json`) is tagged with the correct DLP tier.
3. `offboard plan --user <upn>` returns a **dry-run** cleanup plan (remove assignments, revoke grants/tokens, and disable access only where appropriate) and makes **zero** API writes.
4. `offboard report` emits both `.md` and `.html` that a non-technical auditor can read: plain-English findings + remediation steps.
5. All risk rules covered by unit tests against `tests/fixtures/`.
6. GitHub Actions CI passes: `ruff` + `pytest` on push/PR.

## Roadmap
- **v1 (this spec):** read-only Entra audit + catalog + dry-run plan + report. ✅ *Delivered in v0.1.0*
- **Option B — setup wizard:** one-time `offboard setup` writes `.env`, validates connection. ✅ *Delivered in v0.1.0*
- **Option A — local web UI:** `offboard web` serves a FastAPI dashboard. ✅ *Delivered in v0.1.0*
- **v1b:** Google Workspace connector, logo/domain enrichment of catalog, SQLite snapshot store.
- **v2:** `offboard execute` with an explicit approval gate (confirm list → apply → log every change → rescan).
- **Next:** richer provider-specific cleanup and before/after verification for tenant-side AI remnants.

### Delivered since spec write (Aug 2026)
- **Option B (usability core):** `offboard setup` interactive wizard, `audit --report` (+ `--out`), `plan`, shared `scan.py` pipeline, `config.py` + `.env.example`, MockConnector + `--mock` for Azure-free eval.
- **Option A (local web UI):** `offboard web` — FastAPI app wrapping the same scan pipeline, demo-mode scan, findings table with severity colors, `.md`/`.html` download; localhost-only, no multi-tenant auth.
- **Public-release hardening:** package data ships in the wheel (catalog + templates verified), Apache-2.0 LICENSE file, PEP 561 `py.typed`, ruff + mypy + pytest in CI, web-UI TestClient tests, committed `examples/ai-offboard-report.{md,html}` sample, `.env.example`.

### First public release checklist
- [x] Wheel ships runtime data (apps.json + templates) — verified in built wheel
- [x] LICENSE (Apache-2.0) present so GitHub shows the license
- [x] Mock/demo mode so anyone evaluates without Azure creds
- [x] Committed sample report for proof-of-value on the landing page
- [x] CI gates: ruff, mypy, pytest (incl. web UI TestClient tests)
- [x] README leads with positioning + sample output
- [x] SECURITY.md / CONTRIBUTING.md / connector docs
- [ ] Repo made public (currently private)
- [ ] Repo description + topics set on GitHub (needs gh/token auth)
- [ ] Optional: PyPI publish (`pip install ai-offboard`) for widest reach

## Open-source posture
- Apache-2.0. `README` leads with the one-line positioning + a sample screenshot of the compliance artifact. `SECURITY.md` states read-only posture in v1 (a trust differentiator reviewers check).
- Contribution surface intentionally thin at first: an `apps.json` entry is a one-PR contribution — that's how the catalog grows without a connector-count death march.

## Risks / honest limits
- **Don't out-build SentinelOne on scopes.** Win on the SMB audit artifact they ignore.
- **Connector treadmill is the tax.** Mitigate via read-only Graph calls (one code path) + community `apps.json`.
- **Requires App Registration + permissions to scan**, which is a dev friction for self-serve. Document the setup clearly (docs/connectors.md) as the #1 onboarding step.
