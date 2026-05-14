# EntraPass — User Manual

> **Version:** 0.1.0  
> **Product:** EntraPass — Passkey Migration Assistant  
> **License:** MIT

---

## Table of Contents

1. [What is EntraPass?](#1-what-is-entrapass)
2. [Prerequisites](#2-prerequisites)
3. [Quick Start](#3-quick-start)
4. [Setup Wizard Walkthrough](#4-setup-wizard-walkthrough)
5. [Dashboard Tour](#5-dashboard-tour)
6. [Understanding Your Results](#6-understanding-your-results)
7. [Working with Recommendations](#7-working-with-recommendations)
8. [Using the AI Assistant](#8-using-the-ai-assistant)
9. [Cleanup](#9-cleanup)
10. [Troubleshooting](#10-troubleshooting)
11. [FAQ](#11-faq)

---

## 1. What is EntraPass?

EntraPass is a **browser-based tool** that scans your Microsoft Entra ID tenant to assess how ready your organization is for **passkey (FIDO2) authentication**.

It answers questions like:
- Which users can use passkeys right now?
- Which devices need OS updates?
- Which Conditional Access policies block passkey registration?
- Which apps may silently fall back to passwords?

### Key Principles

| Principle | What it means |
|---|---|
| **Your data stays in your browser** | No data is sent to any server except Microsoft Graph |
| **You own the app registration** | The scanner uses an app registration in YOUR tenant |
| **Open source (MIT)** | Full transparency — inspect the code yourself |
| **PKCE security** | No client secrets, no API keys |

---

## 2. Prerequisites

Before using EntraPass, ensure you have:

### Required

| Requirement | Details |
|---|---|
| **Entra ID tenant** | The tenant you want to scan |
| **Azure subscription** | To deploy the Bicep template (or use an existing resource group) |
| **Application Developer role** | Or higher in Entra ID to create app registrations |
| **Admin consent capability** | Or a Global Admin who can grant Graph permissions |
| **Modern browser** | Edge, Chrome, Firefox, or Safari (latest versions) |

### Optional

| Requirement | For |
|---|---|
| **Azure CLI** | Deploying via CLI instead of the Azure Portal |
| **PowerShell 7+** | Running the cleanup script |
| **AI API key** | Using the "Bring Your Own Key" AI assistant |

---

## 3. Quick Start

```
Step 1: Open the portal
Step 2: Read and accept the Terms & Conditions
Step 3: Deploy the App Registration to your tenant
         - Use "Deploy to Azure" button OR
         - Use Azure CLI
Step 4: Enter your Client ID + Tenant ID
Step 5: Sign in with Microsoft
Step 6: Click "Scan Tenant Now"
Step 7: Review your results across 5 tabs
Step 8: (Optional) Run the cleanup script when done
```

---

## 4. Setup Wizard Walkthrough

### Step 1: Terms & Conditions

When you first open the portal, you are greeted with the **Terms & Conditions** screen.

1. Read the terms carefully
2. Check the acknowledgment checkbox: *"I understand and acknowledge..."*
3. Click **?? Continue to Setup**

> **Why this is required:** EntraPass creates an App Registration in your tenant with delegated permissions. You must acknowledge you have authority to do this.

### Step 2: Deploy the App Registration

Three deployment options:

#### ?? Option A: Create in Azure Portal (Recommended)

1. Click the **?? Create App Registration** button in the portal
2. You will be redirected to the Azure Portal App Registration creation blade
3. Configure:
   - **Name**: `entrapass-scanner`
   - **Accounts**: "Only this organizational directory"
   - **Redirect URI**: SPA ? your portal URL
4. Click **Register**
5. Go to **API Permissions** ? **Add a permission** ? **Microsoft Graph** ? **Delegated permissions**
6. Add all 7 scopes:
   - User.Read, User.Read.All, Device.Read.All, Policy.Read.All
   - Application.Read.All, AuditLog.Read.All, Organization.Read.All
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
Connect-MgGraph -Scopes Application.ReadWrite.All
$app = New-MgApplication -DisplayName "entrapass-scanner" -SignInAudience AzureADMyOrg -Spa @{RedirectUris=@("https://entrapass.pages.dev")}
```
See the [installation guide](installation.md) for the full script.

### Step 3: Configure

After deployment:

1. Click **?? I Deployed It — Let\'s Configure**
2. Enter:
   - **Client ID**: The App ID from the Bicep output
   - **Tenant ID**: Your Microsoft Entra ID tenant ID
   - **Portal URL**: Your EntraPass portal URL (pre-filled)
3. Click **?? Save & Start Scanning**

> **Tip:** Both IDs are GUIDs in the format `11111111-2222-3333-4444-555555555555`

### Step 4: Sign In

1. You will be redirected to Microsoft\'s login page
2. Sign in with an account that has:
   - Access to your Entra ID tenant
   - The required Graph permissions
3. **Consent to the delegated permissions** when prompted

---

## 5. Dashboard Tour

After signing in and scanning, the dashboard shows 5 tabs:

### ?? Overview (Default Tab)

```
+----------+  +--------+  +--------+  +--------+
| Total    |  | Ready  |  | Needs  |  | Blocked|
| Users    |  |        |  | Attn   |  |        |
+----------+  +--------+  +--------+  +--------+

?? Passkey Migration Summary
  [Executive summary text]
  [Toxic combinations alerts]
  [Prioritized recommendations]
```

| Card | Meaning |
|---|---|
| **Total Users** | Number of users scanned |
| **Ready** | Users who can use passkeys immediately |
| **Needs Attention** | Users who need device or MFA updates |
| **Blocked** | Users blocked by Conditional Access policies |

### ? Passkey Readiness

This tab shows a **per-user table** with:

| Column | Description |
|---|---|
| **User** | Display name or UPN |
| **Status** | ?? Ready / ?? Needs Attention / ?? Blocked |
| **Issues** | List of specific blockers per user |

**Common issues per user:**
- "No MFA method registered"
- "Device OS outdated for passkeys"
- "No compatible device registered"
- "Blocked by CA policy: [name]"
- "Already has passkey/FIDO2 registered"

### ?? Entra Tip: Apps

This is a **bonus analysis** tab showing application compatibility.

| Column | Description |
|---|---|
| **App** | Application name + "Microsoft-managed" label if applicable |
| **Status** | ?? OK / ?? Flagged / ?? Info (substrate) |
| **Issues** | Password credentials, legacy auth, certificate auth |
| **Description & Fix** | Explanation of the issue + recommended fix |

**Severity colors:**
- **Red** (high) — Password credentials present (blocks passkeys)
- **Orange** (medium) — No delegated permissions (may fall back)
- **Gray** (info) — Microsoft-managed app, not directly fixable

> **Note:** Apps flagged as "Microsoft-managed" (substrate) are informational only. They are included for completeness.

### ?? CA Policies

This tab shows all **Conditional Access policies** and whether they block passkey registration.

| Column | Description |
|---|---|
| **Policy** | Policy name |
| **Blocks Passkeys?** | ?? Yes / ?? No |
| **Action** | Fix recommendation if blocking |

**What blocks passkeys:** Policies that require "password" as a grant control. These must use "FIDO2 authentication strength" instead.

### ?? AI Assistant

An opt-in AI chat to ask questions about your scan results.

**Modes:**
| Mode | How it works |
|---|---|
| **Off** | Rule-based only (no AI calls) |
| **Cloudflare Free AI** | Uses Cloudflare\'s free Workers AI |
| **Bring Your Own Key** | Use your own API key (OpenAI, Azure, etc.) |

---

## 6. Understanding Your Results

### Readiness Classification

| Status | Criteria | What to do |
|---|---|---|
| **Ready** | Has FIDO2 passkey, MFA, modern device, no policy blocks | Start pilot |
| **Needs Attention** | Missing MFA, outdated device, or no device | Guide user to register MFA + modern device |
| **Blocked** | CA policy explicitly blocks passkeys | Update CA policy to use FIDO2 auth strength |

### Toxic Combinations

These are **high-severity alerts** shown on the overview:

| Severity | Example | Why critical |
|---|---|---|
| **Critical** | Privileged user with no MFA and no passkey | Direct security risk — single factor |
| **High** | CA policy allows password fallback | Users can bypass passkeys by choosing password |

### Recommendations

The recommendation list is prioritized:

```
Critical (??) ? High (??) ? Medium (??) ? Low (??) ? All Clear (??)
```

---

## 7. Working with Recommendations

Each recommendation includes:

| Field | Example |
|---|---|
| **Severity** | ?? High |
| **Category** | Policy, Security Risk, Apps, etc. |
| **Title** | "CA policy blocks passkeys: Require MFA" |
| **Description** | "This policy requires password as a grant control..." |
| **Fix** | "Create a separate CA policy for passkey-capable users..." |

### Rollout Plan (from Executive Summary)

The summary suggests a 4-phase rollout:

```
Phase 1: Pilot with [N] ready users
Phase 2: Enable for attention users after updates
Phase 3: Resolve blocking policies
Phase 4: Full rollout
```

---

## 8. Using the AI Assistant

### Setup

1. Go to the **?? AI Assistant** tab
2. Select your AI mode:
   - **Off**: No AI, rule-based only
   - **Cloudflare Free AI**: Requires deployment via Cloudflare Workers
   - **Bring Your Own Key**: Enter your API endpoint + key + model

### Example Questions

- "Which users are blocked by CA policies?"
- "What apps need password credential removal?"
- "Create a rollout plan for my tenant"
- "What\'s the biggest risk in my results?"

### Privacy

- When AI is **off**, no data leaves your browser
- When using **BYOK**, data goes to your specified endpoint
- When using **Cloudflare**, data goes to Cloudflare Workers AI

---

## 9. Cleanup

After you finish scanning, you can remove all artifacts:

### Option A: Clear Browser Data

Click the **Reset app** button in the header. This clears:
- Configuration (Client ID, Tenant ID)
- Scan results
- MSAL authentication cache

### Option B: Delete App Registration

Run the provided cleanup script:

```powershell
.\infra\cleanup-entrapass.ps1 -ClientId "<your-client-id>" -RevokeConsent
```

This removes:
- The App Registration from your tenant
- The Service Principal (if -RevokeConsent is used)
- All delegated permissions admin consent

> **Note:** The \`-RevokeConsent\` switch also removes admin consent. Omit it if you want to keep consent for future scans.

---

## 10. Troubleshooting

| Problem | Likely Cause | Solution |
|---|---|---|
| **"Sign-in failed"** | Wrong Client ID or Tenant ID | Double-check the GUIDs from your Bicep deployment |
| **Blank scan results** | Permissions not granted | Go to Azure Portal > App Registrations > API Permissions > Grant admin consent |
| **"Access denied" on Graph API** | Insufficient delegated permissions | Ensure Global Admin has granted consent for all 7 permissions |
| **Scan stuck at "Fetching..."** | Large tenant (>50 users) | The scan limits to 50 users by design. Results may lag. |
| **"Config validation failed"** | Invalid GUID format | GUIDs must be 8-4-4-4-12 hex format |
| **MSAL popup blocked** | Browser popup blocker | Allow popups for the EntraPass portal URL |
| **Session expired** | Token expired (60 min) | Sign out and sign in again |
| **Cleanup script fails** | Missing Microsoft.Graph module | Script auto-installs it, but may need admin rights |

### Known Limitations

| Limitation | Detail |
|---|---|
| **Max 50 users** | Scans up to 50 users for performance. Large tenants may need sampling. |
| **Max 100 devices** | Scans up to 100 devices. |
| **Read-only** | EntraPass cannot make changes — it\'s an assessment tool only. |
| **No persistent storage** | Data is lost when the tab closes. Export results if needed. |
| **App registrations only** | Cannot scan on-prem resources or other identity providers. |

---

## 11. FAQ

### Is EntraPass a Microsoft product?

No. EntraPass is an **open-source community tool** licensed under MIT. It is not affiliated with Microsoft.

### Where is my data stored?

**In your browser only.** No data is stored on servers, sent to analytics, or shared with third parties. See the [Data Architecture](data-architecture.md) document for details.

### Can this tool make changes to my tenant?

**No.** EntraPass is a **read-only assessment tool**. It only reads data via Microsoft Graph — it cannot create users, change policies, or modify configurations.

### Does the tool store passwords?

**No.** The tool never requests, reads, or stores passwords. It only checks which authentication methods are *registered* (not their secrets).

### Why do I need to deploy an App Registration?

The App Registration is how the application authenticates to Microsoft Graph on your behalf. By deploying it in **your own tenant**, you maintain full control:

| Aspect | Your App Reg | Shared App Reg |
|---|---|---|
| **Control** | You own it | Third-party controls |
| **Audit** | Full audit trail | No visibility |
| **Permissions** | You grant consent | Pre-consented by vendor |
| **Security** | Can be deleted anytime | Persistent |

### What if I don't want to deploy Bicep?

You can self-host the application and set the `VITE_CLIENT_ID` and `VITE_TENANT_ID` environment variables during build. The setup wizard will be skipped. However, this still requires an App Registration in your tenant.

### Can I use this in production?

EntraPass is **MIT-licensed** with no warranty. It is intended as an **assessment tool** to help plan passkey migration. Review the code and test in a non-production environment first.

### How do I get support?

Open an issue on the [GitHub repository](https://github.com/arusso-aboutcloud/EntraPass/issues). As an open-source project, support is community-driven.

