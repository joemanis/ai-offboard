# AI-Offboard

**The AI tool audit + offboarding report you hand your insurance agent.**

SMBs and MSPs have a loud, unfilled problem: no one can catalog the AI tools
running in a tenant, see what data they touch, or prove on departure that
access was revoked. Enterprise DLP vendors chase the big-org blocking market
and skip the small-org audit-and-revoke-at-departure moment. That moment
produces a compliance artifact an insurer, SOC2, or renewal actually accepts.

`ai-offboard` scans a Microsoft Entra tenant (read-only), maps principals and
apps to an AI-app catalog, flags risky AI access, and emits a plain-English
audit report plus a dry-run revocation plan. **In v1 it writes nothing.**

## Quick start
```bash
pip install -e .
offboard audit --tenant <tenant-id>
offboard plan --user <upn>     # dry-run: exact revoke steps, executes nothing
offboard report                # writes report.md + report.html
```

## v1 scope
- Read-only Microsoft Entra ID connector (Graph)
- AI-app catalog (`src/offboard/catalog/apps.json`) with DLP-risk tiers
- Risk rules → findings (orphaned access, MFA gaps, unused high-tier seats, broad grants)
- Dry-run revocation plan + audit report (MD + HTML)

**Not in v1:** any write/execute, Google Workspace, DB, web UI, DLP/monitoring.
See [SPEC.md](SPEC.md) for the full build spec and roadmap.

## Security posture
Read-only by design. v1 makes zero mutating Graph calls. See [SECURITY.md](SECURITY.md).

## Contributing
The fastest way in is a one-PR `apps.json` catalog entry. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License
Apache-2.0
