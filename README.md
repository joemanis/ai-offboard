# AI-Offboard

**The AI tool audit + offboarding report you hand your insurance agent.**

SMBs and MSPs have a loud, unfilled problem: no one can catalog the AI tools
running in a tenant, see what data they touch, or prove on departure that
access was revoked. Enterprise DLP vendors chase the big-org blocking market
and skip the small-org audit-and-revoke-at-departure moment. `ai-offboard`
closes that gap with a **read-only** scanner that produces the compliance
artifact an insurer, SOC2, or renewal actually accepts.

> **Read-only by design.** v1 makes zero writes: it never disables an account,
> never revokes a token, never changes anything. It audits and reports. The
> plan it produces is a dry-run checklist for a human to approve.

## What it does

- Enumerates users, app assignments, and service-principal grants in a
  Microsoft 365 tenant
- Maps them to an AI-app catalog with **DLP-risk tiers** (high/medium/low)
- Flags risky access: stale access on departure, MFA gaps, unused high-tier
  seats, broad high-privilege grants
- Emits a **dry-run revocation plan** (execute nothing)
- Renders a plain-English **audit report** (.md + .html) an auditor can read

## Quick start

### Try the demo now (no Azure required)

```bash
pip install -e ".[web]"
offboard web                 # local web UI, then click "Run demo scan"
offboard audit --tenant demo --mock  # or a terminal report
```

### Connect your tenant (interactive, recommended)

One command — no App Registration, no tenant ID, no client secret. Sign in as a
Global Administrator via Microsoft's device code flow; the tenant ID is
automatically detected from the token:

```bash
offboard auth login         # copy the code → microsoft.com/devicelogin → done
offboard audit              # scan your tenant
```

On subsequent runs the cached token is reused silently.

### Connect your tenant (CI / service account)

For automation, still supports client credentials via an Azure App Registration:

```bash
offboard setup                          # guides through App Registration + writes .env
offboard audit --tenant <id>            # scan to terminal
offboard audit --tenant <id> --report   # write report.md + report.html
offboard plan --user <upn>              # dry-run revocation steps (executes nothing)
```

## Screenshots

**Landing page** — run a live scan or a one-click demo (no Azure required):

![ai-offboard landing](examples/ai-offboard-landing.png)

**Audit report** — stat cards, AI app inventory with DLP-risk tiers,
per-finding remediation steps, and `.md` / `.html` downloads:

![ai-offboard report](examples/ai-offboard-report.png)

Reproduce with `offboard web` then `python scripts/capture_screenshots.py`.

## Sample output

Run `offboard audit --tenant demo --mock` (or the web UI) to see a live report.
A representative report renders like this:

```markdown
# AI-Offboard Audit Report

- **Tenant:** demo
- **Principals scanned:** 3
- **App assignments:** 2

| Severity | Rule | Subject | Evidence |
| --- | --- | --- | --- |
| medium | R1 | stale@example.com | Account is disabled in directory. |
| high   | R2 | nomfa@example.com | Account lacks enforced MFA registration. |
| high   | R4 | Microsoft 365 Copilot | High-privilege app has an active assignment. |
```

## v1 scope

- **Two auth modes**: interactive device-code login (`offboard auth login`, no
  tenant ID needed) or client credentials (CI/service accounts via App Registration).
- **Read-only** Microsoft Entra ID connector (Graph, GET-only)
- AI-app catalog (`apps.json`) with DLP-risk tiers
- Risk rules → findings (stale access, MFA gaps, unused high-tier seats, broad grants)
- Dry-run revocation plan + audit report (MD + HTML)
- Local web UI (`offboard web`) with "Connect Microsoft 365" flow
- Mock/demo mode (`--mock`) so anyone can evaluate with zero creds

**Not in v1:** write/execute revocation, Google Workspace connector, DB,
multi-tenant SaaS. See [SPEC.md](SPEC.md) for the roadmap.

## Install

```bash
# Core CLI (no web UI)
pipx install .                        # or: pip install -e .

# With the local web UI
pip install -e ".[web]"
```

Requires Python 3.11+. The wheel ships the app catalog and web templates, so
a normal `pip install` is whole (4 data files verified in the built wheel).

## Contributing

The fastest way in is a one-PR `apps.json` catalog entry. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Read-only by design; v1 makes zero mutating Graph calls. See
[SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).