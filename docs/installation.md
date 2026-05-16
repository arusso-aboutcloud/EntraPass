# EntraPass — Installation Guide

> **Version:** 0.1.0
> **License:** MIT
> **Last updated:** 2026-05-14

---

## Table of contents

1. [Overview](#1-overview)
2. [Step 1: Create the App Registration](#2-step-1-create-the-app-registration)
3. [Step 2: Choose how to run EntraPass](#3-step-2-choose-how-to-run-entrapass)
   - [Option A: Use the hosted version](#option-a-use-the-hosted-version)
   - [Option B: Self-host on Cloudflare Pages](#option-b-self-host-on-cloudflare-pages)
   - [Option C: Run locally for development](#option-c-run-locally-for-development)
4. [Step 3: Grant admin consent](#4-step-3-grant-admin-consent)
5. [Verification checklist](#5-verification-checklist)
6. [Cleanup](#6-cleanup)
7. [Appendix: infrastructure files](#7-appendix-infrastructure-files)

---

## 1. Overview

Running EntraPass always involves two pieces:

1. **An App Registration in your Entra ID tenant** — a PKCE-only SPA with seven
   read-only Microsoft Graph delegated permissions. EntraPass uses it to
   authenticate the signed-in user and read tenant data.
2. **The EntraPass web app itself** — a static SPA you can either use as hosted
   on Cloudflare Pages, self-host, or run locally.

| Hosting method | Difficulty | Best for |
|---|---|---|
| **Hosted version** | Easy | Most users — no infrastructure needed |
| **Self-host (Cloudflare Pages)** | Medium | Organizations that want their own deployment |
| **Local development** | Higher | Developers, contributors, air-gapped review |

> **About Bicep / ARM templates:** `infra/app-registration.bicep` and
> `infra/app-registration.json` are kept in the repository **for reference
> only**. Deploying `Microsoft.Graph/applications` resources through Bicep/ARM
> is not reliably supported, so use one of the three methods in
> [Step 1](#2-step-1-create-the-app-registration) instead.

---

## 2. Step 1: Create the App Registration

Pick **one** of the three methods below. All of them create the same thing: a
SPA app registration named `entrapass-scanner` with seven Graph delegated
permissions and no client secret.

You will need: an Entra ID tenant, and the **Application Developer** role (or
higher) to create app registrations. Granting admin consent additionally
requires a **Global Administrator** (see [Step 3](#4-step-3-grant-admin-consent)).

### Method 1: Azure Portal blade (recommended)

1. In the EntraPass setup wizard, click **Create App Registration** — it opens
   the Azure Portal "Register an application" blade.
2. Configure:
   - **Name:** `entrapass-scanner`
   - **Supported account types:** *Accounts in this organizational directory only*
   - **Redirect URI:** select **Single-page application (SPA)** and enter your
     portal URL (e.g. `https://entrapass.aboutcloud.io`, or `http://localhost:5173`
     for local development).
3. Click **Register**.
4. Go to **API permissions → Add a permission → Microsoft Graph → Delegated
   permissions** and add all seven scopes:
   `User.Read`, `User.Read.All`, `Device.Read.All`, `Policy.Read.All`,
   `Application.Read.All`, `AuditLog.Read.All`, `Organization.Read.All`.
5. Click **Grant admin consent for [tenant]** (requires Global Administrator).
6. Copy the **Application (client) ID** and **Directory (tenant) ID** from the
   app's **Overview** page.

### Method 2: Azure Cloud Shell script (fastest)

1. Open [Azure Cloud Shell](https://shell.azure.com) in **PowerShell** mode.
2. Run:
   ```powershell
   irm https://raw.githubusercontent.com/arusso-aboutcloud/EntraPass/main/infra/deploy-entrapass.ps1 | iex
   ```
3. When prompted for the portal URL, **press Enter** to accept the default
   (`https://entrapass.aboutcloud.io`), or type your own URL if you self-host.
4. The script creates the app registration and its service principal, adds all
   seven permissions, grants admin consent, and prints your **Client ID** and
   **Tenant ID**. It is idempotent — re-running it reuses the existing app.

### Method 3: Manual PowerShell

For full control, run the equivalent of the Cloud Shell script yourself:

```powershell
Connect-MgGraph -Scopes "Application.ReadWrite.All","DelegatedPermissionGrant.ReadWrite.All"

$redirectUri = "https://entrapass.aboutcloud.io"   # or http://localhost:5173

$app = New-MgApplication `
  -DisplayName "entrapass-scanner" `
  -SignInAudience "AzureADMyOrg" `
  -Spa @{ RedirectUris = @($redirectUri) } `
  -RequiredResourceAccess @(
    @{
      ResourceAppId  = "00000003-0000-0000-c000-000000000000"   # Microsoft Graph
      ResourceAccess = @(
        @{ Id = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"; Type = "Scope" }  # User.Read
        @{ Id = "a154be20-db9c-4678-8ab7-66f6cc099a59"; Type = "Scope" }  # User.Read.All
        @{ Id = "951183d1-1a61-466f-a6d1-1fde911bfd95"; Type = "Scope" }  # Device.Read.All
        @{ Id = "572fea84-0151-49b2-9301-11cb16974376"; Type = "Scope" }  # Policy.Read.All
        @{ Id = "c79f8feb-a9db-4090-85f9-90d820caa0eb"; Type = "Scope" }  # Application.Read.All
        @{ Id = "e4c9e354-4dc5-45b8-9e7c-e1393b0b1a20"; Type = "Scope" }  # AuditLog.Read.All
        @{ Id = "4908d5b9-3fb2-4b1e-9336-1888b7937185"; Type = "Scope" }  # Organization.Read.All
      )
    }
  )

Write-Host "Client ID: $($app.AppId)"
Write-Host "Tenant ID: $((Get-MgContext).TenantId)"
```

Then grant admin consent — see [Step 3](#4-step-3-grant-admin-consent).

---

## 3. Step 2: Choose how to run EntraPass

### Option A: Use the hosted version

The hosted version is available at **[entrapass.aboutcloud.io](https://entrapass.aboutcloud.io)**.

1. Open the portal URL in your browser.
2. Read and accept the **Terms & Conditions**.
3. Complete [Step 1](#2-step-1-create-the-app-registration) if you have not already.
4. Enter your **Client ID** and **Tenant ID**, then click **Save & Start Scanning**.
5. Sign in with Microsoft and consent to the requested permissions.

No installation is required.

### Option B: Self-host on Cloudflare Pages

Self-hosting gives you full control over the deployment URL.

**Prerequisites:** a Cloudflare account (free tier is fine), a GitHub account,
Node.js 18+ (CI uses Node 22).

1. **Clone (or fork) the repository:**
   ```bash
   git clone https://github.com/arusso-aboutcloud/EntraPass.git
   cd EntraPass
   ```
2. **(Optional) configure environment variables** to skip the setup wizard.
   Create a `.env` file:
   ```env
   VITE_CLIENT_ID=your-client-id
   VITE_TENANT_ID=your-tenant-id
   ```
3. **Build:**
   ```bash
   npm install
   npm run build
   ```
   This produces a static `dist/` directory.
4. **Deploy to Cloudflare Pages** — either via Wrangler:
   ```bash
   npx wrangler pages deploy dist --project-name entrapass
   ```
   or via the Cloudflare dashboard (**Pages → Create a project → Direct upload**,
   then upload `dist/`).
5. **(Optional) add a custom domain** in **Pages → your project → Custom domains**.
6. **Create the App Registration** for your deployment URL — see
   [Step 1](#2-step-1-create-the-app-registration). The redirect URI must match
   your portal URL exactly.

> **Tip:** the repository already includes
> [`.github/workflows/deploy.yml`](../.github/workflows/deploy.yml), which
> deploys to Cloudflare Pages on every push to `main`. To use it, set the
> `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, and optionally
> `AZURE_CLIENT_ID` / `AZURE_TENANT_ID` repository secrets.

### Option C: Run locally for development

**Prerequisites:** Node.js 18+, npm 9+, a modern browser.

1. **Clone and install:**
   ```bash
   git clone https://github.com/arusso-aboutcloud/EntraPass.git
   cd EntraPass
   npm install
   ```
2. **Create the App Registration** with redirect URI `http://localhost:5173` —
   see [Step 1](#2-step-1-create-the-app-registration).
3. **Start the dev server:**
   ```bash
   npm run dev
   ```
   Vite serves the app at `http://localhost:5173`.
4. **Configure in the portal:** open `http://localhost:5173`, complete the setup
   wizard, and enter your Client ID and Tenant ID (redirect URI is already
   `http://localhost:5173`).
5. **(Optional) skip the wizard** by adding a `.env` file:
   ```env
   VITE_CLIENT_ID=your-client-id
   VITE_TENANT_ID=your-tenant-id
   ```
   Restart the dev server afterwards.
6. **Debugging** — open browser DevTools (F12):
   - **Console:** scan progress and errors
   - **Network:** Microsoft Graph API calls
   - **Application → Session Storage:** `entrapass_config` and `entrapass_results`

---

## 4. Step 3: Grant admin consent

Several Graph permissions require **admin consent** before EntraPass can use them.

> **Method 2 (Cloud Shell script) already does this for you** — it grants admin
> consent automatically and prints a confirmation. Only follow the steps below
> if you used Method 1 or Method 3, or if the script reported it could not
> grant consent.

### In the Azure Portal (recommended)

1. Go to **Azure Portal → App registrations → entrapass-scanner**.
2. Open **API permissions**.
3. Click **Grant admin consent for [tenant]** and confirm.
4. All seven permissions should show a green **Granted** status.

### Via PowerShell (for automation)

```powershell
Connect-MgGraph -Scopes "Application.ReadWrite.All","DelegatedPermissionGrant.ReadWrite.All"

# Find the service principal created for the app
$sp        = Get-MgServicePrincipal -Filter "appId eq '<your-client-id>'"
$graph     = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# Grant tenant-wide admin consent for all delegated scopes
New-MgOauth2PermissionGrant -ClientId $sp.Id -ConsentType "AllPrincipals" -ResourceId $graph.Id `
  -Scope "User.Read User.Read.All Device.Read.All Policy.Read.All Application.Read.All AuditLog.Read.All Organization.Read.All"
```

> If you skip admin consent, users can still consent interactively at sign-in —
> but only if your tenant allows user consent for these scopes. Tenant-wide
> admin consent is the reliable path.

---

## 5. Verification checklist

| # | Check | How to verify |
|---|---|---|
| 1 | App Registration created | Azure Portal → App registrations → find `entrapass-scanner` |
| 2 | API permissions configured | All seven delegated Graph permissions are listed |
| 3 | Admin consent granted | API permissions page shows green "Granted" status |
| 4 | Redirect URI correct | SPA redirect URI matches your portal URL exactly |
| 5 | Client ID entered | Appears in the EntraPass config screen |
| 6 | Tenant ID entered | Appears in the EntraPass config screen |
| 7 | Sign-in works | MSAL redirect completes without errors |
| 8 | Scan runs | "Scan Tenant Now" populates the stats grid |
| 9 | Results display | All 5 dashboard tabs show data |
| 10 | Reset works | "Reset app" clears config and re-shows the setup wizard |

---

## 6. Cleanup

When you are done, remove the App Registration from your tenant:

```powershell
.\infra\cleanup-entrapass.ps1 -ClientId "<your-client-id>" -RevokeConsent
```

- Without `-RevokeConsent`: deletes the App Registration only.
- With `-RevokeConsent`: also deletes the service principal and its admin consent.

To clear local browser data, click **Reset app** in the dashboard header, or
simply close the browser tab.

---

## 7. Appendix: infrastructure files

| File | Purpose |
|---|---|
| `infra/deploy-entrapass.ps1` | Azure Cloud Shell deployment script (Method 2) |
| `infra/cleanup-entrapass.ps1` | Removes the App Registration and optionally revokes consent |
| `infra/app-registration.bicep` | Bicep template — **reference only** (see Overview note) |
| `infra/app-registration.json` | ARM JSON template — **reference only** |
| `.github/workflows/deploy.yml` | CI/CD: deploys the SPA to Cloudflare Pages |
| `.github/workflows/security-scan.yml` | CI: Trivy filesystem and dependency scanning |

### Cloud Shell script prompt

The `deploy-entrapass.ps1` script asks one question:

| Prompt | Description |
|---|---|
| **Portal URL** | The EntraPass deployment URL, used as the SPA redirect URI. **Press Enter** to accept the default `https://entrapass.aboutcloud.io`, or type your own URL if you self-host. |

The script is idempotent: re-running it finds the existing `entrapass-scanner`
app instead of creating a duplicate, and ensures the redirect URI is present.
