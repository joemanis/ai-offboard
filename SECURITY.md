# Security Policy

## Supported versions
Only the latest release is supported.

## Reporting a vulnerability
Open a private GitHub security advisory, or email the maintainers (see
package metadata). Do **not** file a public issue for a real vulnerability.

## Design trust posture
`ai-offboard` is **read-only by default**:

- The scan path performs **zero** mutating Microsoft Graph / Workspace calls.
  Only `GET` requests are issued.
- The `plan` command produces a dry-run revocation plan and **never** applies
  it.
- The only write path is `offboard execute`, which is **opt-in**: it prints
  the full plan, requires typed confirmation (unless `--yes` for automation),
  and appends every mutation — success or failure — to a local audit log.
- Scans are run with the **least privilege** the connector documents. Review
  `docs/connectors.md` before granting permissions to a scan principal.
- Credentials are read from environment variables or a local config file that
  is not committed to source. Never commit tokens or client secrets.
