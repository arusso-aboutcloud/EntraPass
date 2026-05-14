# EntraPass — Installation Guide

> **Version:** 0.1.0  
> **License:** MIT  
> **Last Updated:** 2026-05-14

---

## Table of Contents

1. [Overview](#1-overview)
2. [Option A: Use the Hosted Version](#2-option-a-use-the-hosted-version)
3. [Option B: Self-Host on Cloudflare Pages](#3-option-b-self-host-on-cloudflare-pages)
4. [Option C: Run Locally (Development)](#4-option-c-run-locally-development)
5. [Post-Installation: Grant Admin Consent](#5-post-installation-grant-admin-consent)
6. [Verification Checklist](#6-verification-checklist)

---

## 1. Overview

EntraPass can be used in three ways:

| Method | Difficulty | Best For |
|---|---|---|
| **Hosted version** (Cloudflare Pages) | ? Easy | Most users — no infrastructure needed |
| **Self-host** (Cloudflare Pages) | ?? Medium | Organizations with their own Cloudflare account |
| **Local development** | ??? Harder | Developers, contributors, air-gapped tenants |

All methods require deploying a Bicep template to your Azure subscription.

---

## 2. Option A: Use the Hosted Version

The hosted version is available at a Cloudflare Pages deployment URL (configured by the repository owner).

### Step 1: Access the Portal

1. Open the hosted portal URL in your browser
2. You will see the **Terms & Conditions** screen

### Step 2: Deploy the App Registration

Choose one of three methods:

#### ?? Option A: Azure Portal (Recommended)

1. Click the **?? Create App Registration** button in the portal
2. You will be redirected to the Azure Portal App Registration creation blade
3. Configure:
   - **Name**: `entrapass-scanner`
   - **Accounts**: "Only this organizational directory"
   - **Redirect URI**: SPA ? your portal URL (e.g., `https://entrapass.pages.dev`)
4. Click **Register**
5. Go to **API Permissions** ? **Add a permission** ? **Microsoft Graph** ? **Delegated permissions**
6. Add all 7 scopes: User.Read, User.Read.All, Device.Read.All, Policy.Read.All, Application.Read.All, AuditLog.Read.All, Organization.Read.All
7. Click **Grant admin consent** (requires Global Admin)

#### ?? Option B: Azure Cloud Shell (Fastest)

1. Open [Azure Cloud Shell](https://shell.azure.com) in PowerShell mode
2. Run this one-liner:
   ```powershell
   irm https://raw.githubusercontent.com/arusso-aboutcloud/EntraPass/main/infra/deploy-entrapass.ps1 | iex
   ```
3. Enter your portal URL when prompted
4. The script creates the App Registration, adds all permissions, and outputs your **Client ID**

#### ?? Option C: Manual PowerShell

```powershell
Connect-MgGraph -Scopes Application.ReadWrite.All,DelegatedPermissionGrant.ReadWrite.All
$app = New-MgApplication -DisplayName "entrapass-scanner" -SignInAudience AzureADMyOrg -Spa @{RedirectUris=@("https://entrapass.pages.dev")}
# Then add required permissions (see deploy-entrapass.ps1 for full script)
```

### Step 3: Configure

1. Enter your **Client ID** and **Tenant ID**
2. Click **Save & Start Scanning**
3. Sign in with Microsoft
4. Consent to the requested permissions

> **No additional install steps needed.** The hosted version is ready to use.

---

## 3. Option B: Self-Host on Cloudflare Pages

Self-hosting gives you full control over the deployment.

### Prerequisites

| Requirement | Details |
|---|---|
| **Cloudflare account** | Free tier is sufficient |
| **GitHub account** | To fork the repository |
| **Node.js 18+** | For building |
| **Azure subscription** | For the App Registration |

### Step 1: Fork the Repository

```bash
git clone https://github.com/arusso-aboutcloud/EntraPass.git
cd EntraPass
```

### Step 2: Configure Environment Variables

Create a `.env` file (optional — only needed to skip the setup wizard):

```env
VITE_CLIENT_ID=your-client-id-from-bicep
VITE_TENANT_ID=your-tenant-id
```

### Step 3: Build the Application

```bash
npm install
npm run build
```

This produces a `dist/` directory with the static files.

### Step 4: Deploy to Cloudflare Pages

**Via Wrangler CLI:**

```bash
npm install -g wrangler
wrangler pages deploy dist/ --project-name entrapass
```

**Via Cloudflare Dashboard:**
1. Go to Cloudflare Dashboard > Pages
2. Click **Create a project** > **Direct upload**
3. Upload the `dist/` folder

### Step 5: Configure Custom Domain (Optional)

1. In Cloudflare Pages > your project > **Custom domains**
2. Add your domain (e.g., `entrapass.yourcompany.com`)
3. Update DNS records as instructed

### Step 6: Deploy the Bicep Template

Same as Option A — use the **Deploy to Azure** button or CLI.

```bash
az deployment group create \
  --resource-group <your-rg> \
  --template-file infra/app-registration.bicep \
  --parameters redirectUri="https://entrapass.yourcompany.com" \
               tenantId="<your-tenant-id>"
```

### Step 7: Verify

1. Visit your custom URL
2. Follow the setup wizard
3. Enter your Client ID and Tenant ID
4. Start scanning

---

## 4. Option C: Run Locally (Development)

### Prerequisites

| Requirement | Version |
|---|---|
| **Node.js** | 18+ |
| **npm** | 9+ |
| **Azure CLI** | Latest (for Bicep deploys) |
| **Modern browser** | Latest Chrome/Edge/Firefox |

### Step 1: Clone and Install

```bash
git clone https://github.com/arusso-aboutcloud/EntraPass.git
cd EntraPass
npm install
```

### Step 2: Deploy the App Registration

```bash
# Create a resource group
az group create --name entrapass-rg --location westeurope

# Deploy the Bicep template
az deployment group create \
  --resource-group entrapass-rg \
  --template-file infra/app-registration.bicep \
  --parameters redirectUri="http://localhost:5173" \
               tenantId="<your-tenant-id>"
```

### Step 3: Start the Dev Server

```bash
npm run dev
```

This starts Vite\'s development server at `http://localhost:5173`

### Step 4: Configure in the Portal

1. Open `http://localhost:5173`
2. Follow the setup wizard
3. Enter your Client ID (from Bicep output)
4. Enter your Tenant ID
5. The redirect URI should already be `http://localhost:5173`
6. Click **Save & Start Scanning**

### Step 5: (Optional) Use Environment Variables

To skip the setup wizard during development, create `.env`:

```env
VITE_CLIENT_ID=your-client-id
VITE_TENANT_ID=your-tenant-id
```

Then restart the dev server. The app will use these values directly.

### Step 6: Debugging

Open browser developer tools (F12):
- **Console**: View scan progress and error messages
- **Network**: Watch Graph API calls
- **Application > Session Storage**: View `entrapass_config` and `entrapass_results`

---

## 5. Post-Installation: Grant Admin Consent

After deploying the App Registration, some Graph permissions require **admin consent** before they can be used.

### Automatic (during deploy)

If the user deploying has Global Admin rights, consent is granted during the Bicep deployment.

### Manual (in Azure Portal)

1. Go to **Azure Portal** > **App Registrations**
2. Select the EntraPass scanner app
3. Go to **API Permissions**
4. Click **Grant admin consent for [tenant]**
5. Click **Yes** to confirm

### Using Graph API (for automation)

```powershell
# Install Microsoft.Graph module
Install-Module Microsoft.Graph -Scope CurrentUser

# Connect as Global Admin
Connect-MgGraph -Scopes "Application.ReadWrite.All","Directory.ReadWrite.All"

# Get the service principal
$sp = Get-MgServicePrincipal -Filter "displayName eq 'entrapass-scanner-...'"

# Grant admin consent (scopes from Bicep template)
# Or approve in Azure Portal as shown above
```

---

## 6. Verification Checklist

Use this checklist to ensure your installation is complete:

| # | Check | Method |
|---|---|---|
| 1 | App Registration created | Azure Portal > App Registrations > find "entrapass-scanner-*" |
| 2 | API Permissions configured | Check all 7 delegated permissions are listed |
| 3 | Admin consent granted | API Permissions should show a green checkmark |
| 4 | Redirect URI correct | Must match your portal URL exactly (including trailing slash) |
| 5 | Client ID entered | Appears in EntraPass config screen |
| 6 | Tenant ID entered | Appears in EntraPass config screen |
| 7 | Sign-in works | MSAL redirect completes without errors |
| 8 | Scan runs | Click "Scan Tenant Now" — see stats populate |
| 9 | Results display | Switch between all 5 tabs — data visible |
| 10 | Reset works | Click "Reset app" — config cleared, setup wizard reappears |

---

## Appendix: Infrastructure Files

| File | Purpose |
|---|---|
| `infra/deploy-entrapass.ps1` | Cloud Shell one-click deployment script (recommended) |
| `infra/app-registration.bicep` | Bicep template (CLI deployment) |
| `infra/app-registration.json` | ARM JSON template (portal reference) |
| `infra/cleanup-entrapass.ps1` | PowerShell script to remove the App Registration |
| `.github/workflows/deploy.yml` | CI/CD for Cloudflare Pages deployment |
| `.github/workflows/trivy-scan.yml` | Security scanning |

### Bicep Parameters (if using CLI)

| Parameter | Default | Description |
|---|---|---|
| `appName` | `entrapass-scanner` | Base name for the app registration |
| `redirectUri` | `http://localhost:5173` | SPA redirect URI (your portal URL) |
| `tenantId` | (required) | Your Entra ID tenant ID |

### Cloud Shell Script Parameters

The `deploy-entrapass.ps1` script prompts for:

| Prompt | Description |
|---|---|
| **Portal URL** | Your EntraPass deployment URL (e.g., `https://entrapass.pages.dev`) |


