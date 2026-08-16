# Connector Setup

`ai-offboard` reads a tenant through either the Microsoft Graph API (Entra ID)
or the Admin SDK Directory API (Google Workspace). The scanner is **read-only**:
it only ever issues `GET` requests. This guide covers setup for both.

---

## Microsoft Entra ID Connector Setup

Follow these steps once per tenant you scan.

> **Security note:** v1 performs no writes. Grant only the scopes below.
> Do not add `Mail.ReadWrite`, `Files.ReadWrite`, or any `*.All` write scope.

### Option A — interactive device-code login (recommended, no App Registration)

```bash
offboard auth login      # copy the code → microsoft.com/devicelogin → sign in as Global Admin
offboard audit           # tenant ID is auto-detected from the token
```

No client secrets, no tenant ID entry. Requires the tenant to allow device-code
flows (default in the Microsoft Entra admin center for most tenants).

### Option B — App Registration (CI / service account)

1. Sign in to the [Azure portal](https://portal.azure.com) as an admin or
   Global Administrator for the tenant you want to scan.
2. Go to **Microsoft Entra ID → App registrations → New registration**.
3. Name it `ai-offboard`, choose **"Multiple Entra ID tenants"** (the second
   radio option under *Supported account types*). Single-tenant apps cannot run
   the device-code flow against the `common` authority (AADSTS50059), which is
   what the tool uses. Registration requires no redirect URI.
4. Under **Certificates & secrets**, create a client secret and copy the value.
5. Grant least-privilege delegated permissions under **API permissions →
   Add a permission → Microsoft Graph → Delegated permissions**:
   - `User.Read.All`
   - `Group.Read.All`
   - `Application.Read.All`

   **Do not grant `Directory.ReadWrite.All` or any write scope.**
6. Copy the **Application (client) ID** and **Tenant ID**.

Then wire the CLI:

```bash
offboard setup                    # guides + validates + writes .env
offboard audit --tenant <id>      # scan to terminal
offboard audit --tenant <id> --report   # write report.md + report.html
```

### Trouble

| Symptom | Cause / fix |
| --- | --- |
| `AADSTS700016 Application not found` | Wrong client ID or tenant ID in `.env`. |
| `AADSTS65001 consent required` | Admin must grant consent: **API permissions → Grant admin consent**. |
| `AADSTS70011 scope invalid` | Public client flow disabled; enable under **Authentication (Preview) → Settings → Allow public client flows**. |

---

## Google Workspace Connector Setup

The Workspace connector reads users + their OAuth-connected apps through the
Admin SDK Directory API (`offboard audit --workspace`). It maps each user's
granted third-party apps (ChatGPT, Fireflies, Zapier, …) into the same risk
rules as the Entra connector.

> **Security note:** the Directory API is read-only here. We only call
> `GET /users` and `GET /users/{key}/tokens`.

### Setup (service account with domain-wide delegation)

1. In the [Google Cloud Console](https://console.cloud.google.com), create a
   project, enable the **Admin SDK API**, and create a **service account**.
2. Download the service account JSON key.
3. In **Google Admin console → Security → Access and data control → Domain
   wide delegation**, authorize that service account's **Client ID** with the
   scope `https://www.googleapis.com/auth/admin.directory.user.readonly`.
4. Note the email of an admin account to impersonate (e.g.
   `admin@yourdomain.com`).

Then:

```bash
export GOOGLE_SERVICE_ACCOUNT_JSON=/path/to/service-account.json
export OFFBOARD_GOOGLE_ADMIN=admin@yourdomain.com
offboard audit --workspace       # scan the Workspace tenant
```

For a direct token (short-lived, e.g. from OAuth playground):

```bash
export GOOGLE_ACCESS_TOKEN=ya29...
offboard audit --workspace
```

All existing outputs work: `--report`, `--json`, `--csv`, and the web UI.

### Scope note

The Workspace connector only reads `admin.directory.user.readonly` plus the
**tokens** endpoint (which lists third-party OAuth grants). There is no write
path — `offboard execute` remains Entra-only in this release.