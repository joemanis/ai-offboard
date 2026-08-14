# Security Policy

## Supported versions
Only the latest release is supported.

## Reporting a vulnerability
Open a private GitHub security advisory, or email the maintainers (see
package metadata). Do **not** file a public issue for a real vulnerability.

## Design trust posture (v1)
`ai-offboard` is **read-only** by design in v1:

- The v1 code path performs **zero** mutating Microsoft Graph calls.
  Only `GET` requests against the Graph API are issued.
- The `plan` command produces a dry-run revocation plan and **never** applies
  it. `execute` does not exist yet.
- Scans are run with the **least privilege** the connector documents. Review
  `docs/connectors.md` before granting permissions to a scan principal.
- Credentials are read from environment variables or a local config file that
  is not committed to source. Never commit tokens or client secrets.
