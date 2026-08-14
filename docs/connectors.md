# Microsoft Entra ID Connector Setup

`ai-offboard` reads a tenant through the Microsoft Graph API. This guide tells
you exactly how to register the app, grant the least-privilege permissions it
needs, and wire it to the CLI. **The scanner is read-only**: it only ever
issues `GET` requests to Graph. Follow these steps once per tenant you scan.

> **Security note:** v1 performs no writes. Grant only the scopes below.
> Do not add `Mail.ReadWrite`, `Files.ReadWrite`, or any `*.All` write scope.

## 1. Register the app (Azure portal)

1. Sign in to the [Azure portal](https://portal.azure.com) as an admin or
   Global Administrator for the tenant you want to scan.
2. Go to **Microsoft Entra ID → App registrations → New registration**.
3. Give it a name, e.g. `ai-offboard-scanner`.
4. **Supported account types:** leave the default ("Accounts in this
   organizational directory only") for a single-tenant scanner.
5. **Redirect URI:** leave blank (this is a confidential client used by a CLI,
   not a browser app).
6. Click **Register**, then copy the **Application (client) ID** and the
   **Directory (tenant) ID** — you'll need both.

## 2. Create a client secret

1. In the app registration, go to **Certificates & secrets → New client secret**.
2. Give it a description and an expiry (90 days is a sensible default).
3. **Copy the secret value immediately** — it's shown once and never again.
   Store it somewhere safe; it will go into an environment variable, never
   into source control.

## 3. Grant the API permissions

In the app registration, go to **API permissions → Add a permission →
Microsoft Graph → Application permissions**, and add exactly these:

| Permission | Purpose | Required? |
| --- | --- | --- |
| `User.Read.All` | Read user list, account enabled state | Yes |
| `Group.Read.All` | Read group membership and app assignments | Yes |
| `Application.Read.All` | Read service principals and permission grants | Yes |
| `Directory.Read.All` | Read directory data for grants and licensing | Recommended |
| `AuditLog.Read.All` | Read `signInActivity` for last-sign-in heuristics | Recommended |

Then click **Grant admin consent** for the tenant. Without admin consent the
scanner will 403 on Graph calls.

> **Why not a delegated (`User.Read`) scope?** The scanner audits the whole
> tenant, not just the signed-in user. It needs application-level access.
> That's also why the least-privilege scopes above matter.

## 4. Wire the CLI

Set four environment variables, then run the CLI:

```bash
export OFFBOARD_CLIENT_ID="<Application (client) ID>"
export OFFBOARD_CLIENT_SECRET="<client secret value>"
export OFFBOARD_AUTHORITY="https://login.microsoftonline.com/<Directory (tenant) ID>"
export OFFBOARD_TENANT_ID="<Directory (tenant) ID>"   # scanned tenant

offboard audit --tenant "$OFFBOARD_TENANT_ID"
```

On Windows (PowerShell):

```powershell
$env:OFFBOARD_CLIENT_ID = "<Application (client) ID>"
$env:OFFBOARD_CLIENT_SECRET = "<client secret value>"
$env:OFFBOARD_AUTHORITY = "https://login.microsoftonline.com/<Directory (tenant) ID>"
$env:OFFBOARD_TENANT_ID = "<Directory (tenant) ID>"
offboard audit --tenant $env:OFFBOARD_TENANT_ID
```

## 5. Verify it works

Run `offboard audit --tenant <id>`. A successful run prints a principal count
and exits 0. If you see a `403 Authorization_RequestDenied`, re-check admin
consent in step 3. If you see `AADSTS700016`, double-check the client ID and
tenant ID.

## Troubleshooting

- **`403 Authorization_RequestDenied`** — permissions were added but admin
  consent wasn't granted, or the scope list doesn't match what's consented.
- **`AADSTS7000215` / "invalid client secret"** — the secret was mistyped or
  expired. Create a new one in step 2.
- **Empty results you expected to be populated** — `signInActivity` requires
  the `AuditLog.Read.All` scope and a licensed user; unlicensed users return
  no value. Treat missing dates as "unknown," not "never."