# AI-Offboard Audit Report

- **Tenant:** demo
- **Scanned at:** 2026-01-01T00:00:00Z
- **Principals scanned:** 3
- **App assignments:** 2

## Findings

| Severity | Rule | Subject | Evidence |
| --- | --- | --- | --- |
| medium | R1 | stale@example.com | Account 'stale@example.com' is disabled in directory. |
| high | R2 | nomfa@example.com | Account 'nomfa@example.com' lacks enforced MFA registration. |
| high | R4 | Microsoft 365 Copilot | High-privilege app 'Microsoft 365 Copilot' has an active assignment. |

## Remediation steps (dry-run)

- **stale@example.com (R1):**
  - Confirm no durable app assignments remain.
  - Revoke tokens/SSO sessions.
- **nomfa@example.com (R2):**
  - Enforce MFA for the account.
  - Rotate credentials if a breach is suspected.
- **Microsoft 365 Copilot (R4):**
  - Review the assigned role scope.
  - Remove assignment for departed/durable principals.
  - Confirm least-privilege on the service principal.
