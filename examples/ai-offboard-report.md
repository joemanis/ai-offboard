# AI-Offboard AI Access Report

- **Tenant:** demo
- **Scanned at:** 2026-01-01T00:00:00Z
- **Principals scanned:** 3
- **Enterprise apps:** 3
- **App-role assignments:** 3

## Findings

| Severity | Rule | Subject | Evidence |
| --- | --- | --- | --- |
| medium | R1 | disabled@example.com | Account 'disabled@example.com' is disabled in directory and retains connected AI app assignments: ChatGPT Enterprise. |
| high | R4 | Microsoft 365 Copilot | AI app 'Microsoft 365 Copilot' is assigned to 'u1'. |
| high | R5 | Microsoft 365 Copilot | Delegated grant for 'Microsoft 365 Copilot' against 'Microsoft Graph' requests sensitive scopes: files.read.all, mail.read, mail.send. |

## Remediation steps (dry-run)

- **disabled@example.com (R1):**
  - Review and remove the listed AI app assignments.
  - Revoke connected-app tokens or sessions where supported.
- **Microsoft 365 Copilot (R4):**
  - Review the assigned role scope.
  - Remove assignment for departed/durable principals.
  - Confirm least-privilege on the service principal.
- **Microsoft 365 Copilot (R5):**
  - Review the consent from the tenant admin perspective.
  - Restrict to least-privilege scopes.
  - Revoke consent / block the app if not business-required.
