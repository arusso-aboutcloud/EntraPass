# EntraPass — User Manual

> **Version:** 0.1.0
> **Product:** EntraPass — Passkey Migration Assistant
> **License:** MIT

---

## Table of contents

1. [What is EntraPass?](#1-what-is-entrapass)
2. [Prerequisites](#2-prerequisites)
3. [Quick start](#3-quick-start)
4. [Setup wizard walkthrough](#4-setup-wizard-walkthrough)
5. [Dashboard tour](#5-dashboard-tour)
6. [Understanding your results](#6-understanding-your-results)
7. [Working with recommendations](#7-working-with-recommendations)
8. [Using the AI Assistant](#8-using-the-ai-assistant)
9. [Cleanup](#9-cleanup)
10. [Troubleshooting](#10-troubleshooting)
11. [FAQ](#11-faq)

---

## 1. What is EntraPass?

EntraPass is a **browser-based tool** that scans your Microsoft Entra ID tenant
to assess how ready your organization is for **passkey (FIDO2) authentication**.

It answers questions like:

- Which users can use passkeys right now?
- Which devices need OS updates?
- Which Conditional Access policies block passkey registration?
- Which apps may silently fall back to passwords?

### Key principles

| Principle | What it means |
|---|---|
| **Your data stays in your browser** | No data is sent to any server except the Microsoft Graph API (and the AI endpoint, only if you opt in) |
| **You own the App Registration** | The scanner uses an App Registration in *your* tenant |
| **Open source (MIT)** | Full transparency — inspect the code yourself |
| **PKCE security** | No client secrets, no API keys |
| **Read-only** | EntraPass can assess but never modify your tenant |

---

## 2. Prerequisites

### Required

| Requirement | Details |
|---|---|
| **Entra ID tenant** | The tenant you want to scan |
| **Application Developer role** | Or higher in Entra ID, to create the App Registration |
| **Admin consent capability** | A Global Administrator who can grant Graph permissions |
| **Modern browser** | Latest Edge, Chrome, Firefox, or Safari |

### Optional

| Requirement | For |
|---|---|
| **Azure Cloud Shell / PowerShell** | Creating the App Registration via script instead of the portal |
| **PowerShell 7+ with the Microsoft Graph module** | Running the cleanup script |
| **An AI API key** | Using the "Bring your own key" AI Assistant mode |

---

## 3. Quick start

```
Step 1: Open the portal
Step 2: Read and accept the Terms & Conditions
Step 3: Create the App Registration in your tenant
         (Azure Portal blade, Cloud Shell script, or manual PowerShell)
Step 4: Enter your Client ID + Tenant ID
Step 5: Sign in with Microsoft
Step 6: Click "Scan Tenant Now"
Step 7: Review your results across the 5 tabs
Step 8: (Optional) run the cleanup script when done
```

For full setup instructions see the [Installation Guide](installation.md).

---

## 4. Setup wizard walkthrough

### Step 1: Terms & Conditions

When you first open the portal you are greeted with the **Terms & Conditions**
screen.

1. Read the terms.
2. Check the acknowledgment box: *"I understand and acknowledge... I am authorized
   to scan this tenant."*
3. Click **Continue to Setup**.

> **Why this is required:** EntraPass needs an App Registration in your tenant
> with delegated permissions. You must confirm you are authorized to create it.

### Step 2: Create the App Registration

The wizard offers three options. Pick whichever suits you — see the
[Installation Guide](installation.md) for the full step-by-step for each.

| Option | Summary |
|---|---|
| **Azure Portal blade** (recommended) | The wizard links to the "Register an application" blade; you add the 7 Graph permissions and grant admin consent |
| **Azure Cloud Shell script** | Run a one-line script that creates the app and all 7 permissions, then prints your Client ID |
| **Manual PowerShell** | Run the Microsoft Graph PowerShell commands yourself for full control |

### Step 3: Configure

After the App Registration exists:

1. Click **I Deployed It — Let's Configure**.
2. Enter:
   - **Client ID** — the Application (client) ID of the App Registration
   - **Tenant ID** — your Microsoft Entra ID directory ID
   - **Portal URL** — your EntraPass URL, used as the redirect URI (pre-filled)
3. Click **Save & Start Scanning**.

> **Tip:** both IDs are GUIDs in the form `11111111-2222-3333-4444-555555555555`.
> The wizard validates the format before continuing.

### Step 4: Sign in

1. You are redirected to Microsoft's sign-in page.
2. Sign in with an account that has access to the tenant and the required
   Graph permissions.
3. **Consent to the delegated permissions** when prompted (if admin consent was
   not already granted).

---

## 5. Dashboard tour

After signing in and running a scan, the dashboard shows five tabs.

### Overview (default tab)

```
┌──────────┐  ┌────────┐  ┌────────┐  ┌────────┐
│ Total    │  │ Ready  │  │ Needs  │  │ Blocked│
│ Users    │  │        │  │ Attn.  │  │        │
└──────────┘  └────────┘  └────────┘  └────────┘

Passkey Migration Summary
  • Executive summary text
  • Toxic combination alerts
  • Prioritized recommendations
```

| Card | Meaning |
|---|---|
| **Total Users** | Number of users analyzed (up to 50) |
| **Ready** | Users who can use passkeys immediately |
| **Needs Attention** | Users who need device or MFA updates |
| **Blocked** | Users blocked by a Conditional Access policy |

### Passkey Readiness

A **per-user table**:

| Column | Description |
|---|---|
| **User** | Display name or UPN |
| **Status** | 🟢 Ready / 🟡 Needs Attention / 🔴 Blocked |
| **Issues** | Specific blockers for that user |

Common per-user issues:

- "No MFA method registered"
- "Device OS outdated for passkeys"
- "No compatible device registered"
- "Blocked by CA policy: [name]"
- "Already has passkey/FIDO2 registered"

### Entra Tip: Apps

A **bonus analysis** of application compatibility.

| Column | Description |
|---|---|
| **App** | Application name, plus a "Microsoft-managed" label where applicable |
| **Status** | 🟢 OK / 🔴 Flagged / 📄 Info (Microsoft-managed) |
| **Issues** | Password credentials, legacy auth, certificate auth |
| **Description & Fix** | Why it matters and what to do |

Severity colors:

- **Red (high)** — password credentials present (can bypass passkeys)
- **Orange (medium)** — no delegated permissions (may fall back to password)
- **Gray (info)** — Microsoft-managed app, not directly fixable by you

> Focus on your **custom enterprise apps** first. Microsoft first-party and
> Microsoft-managed ("substrate") apps are included for completeness but are
> not actionable by you.

### CA Policies

All **Conditional Access policies** and whether they block passkey registration.

| Column | Description |
|---|---|
| **Policy** | Policy name |
| **Blocks Passkeys?** | 🔴 Yes / 🟢 No |
| **Action** | Fix recommendation if the policy blocks passkeys |

A policy is flagged as blocking when it is enabled and requires "password" as a
grant control — that prevents passkey-only authentication. The fix is to require
**FIDO2 authentication strength** instead.

### AI Assistant (opt-in)

An optional AI chat for asking questions about your scan results. See
[section 8](#8-using-the-ai-assistant).

---

## 6. Understanding your results

### Readiness classification

| Status | Criteria | What to do |
|---|---|---|
| **Ready** | Has an MFA method, a modern device, and no blocking policy | Start a pilot |
| **Needs Attention** | Missing MFA, outdated device OS, or no registered device | Guide the user to register MFA and a modern device |
| **Blocked** | A Conditional Access policy explicitly blocks passkeys | Update the CA policy to use FIDO2 authentication strength |

"Modern device" means: Windows 10+, iOS 16+, Android 14+, or macOS 13+.

### Toxic combinations

High-severity alerts shown on the Overview tab:

| Severity | Example | Why it matters |
|---|---|---|
| **Critical** | A privileged user with no MFA and no passkey | A single-factor admin account is a direct security risk |
| **High** | A CA policy allows password fallback alongside passkey | Users can bypass passkeys by choosing a password |

### Recommendations

The recommendation list is prioritized:

```
Critical 🚨  →  High 🔴  →  Medium 🟡  →  Low 🟢  →  All Clear ✅
```

---

## 7. Working with recommendations

Each recommendation includes:

| Field | Example |
|---|---|
| **Severity** | High |
| **Category** | Policy, Security Risk, Apps, etc. |
| **Title** | "CA policy blocks passkeys: Require MFA" |
| **Description** | "This policy requires password as a grant control..." |
| **Fix** | "Create a separate CA policy for passkey-capable users..." |

### Rollout plan (from the executive summary)

When you have ready users, the summary suggests a 4-phase rollout:

```
Phase 1: Pilot with your ready users
Phase 2: Enable passkeys for "needs attention" users after their updates
Phase 3: Resolve blocking Conditional Access policies
Phase 4: Full rollout
```

---

## 8. Using the AI Assistant

The AI Assistant is **opt-in and off by default**.

### Setup

1. Go to the **AI Assistant** tab.
2. Choose a mode:
   - **Off** — rule-based responses only; no data leaves your browser.
   - **Cloudflare Free AI** — requires the optional Cloudflare Worker
     (`workers/ai.js`) to be deployed.
   - **Bring your own key (BYOK)** — enter your API endpoint, key, and model
     (e.g. an OpenAI-compatible endpoint).

### Example questions

- "Which users are blocked by CA policies?"
- "What apps need password credentials removed?"
- "Create a rollout plan for my tenant."
- "What's the biggest risk in my results?"

### Privacy

| Mode | Where your scan data goes |
|---|---|
| **Off** | Nowhere — stays in the browser |
| **Cloudflare Free AI** | To the Cloudflare Worker, which calls Cloudflare Workers AI |
| **BYOK** | To the AI endpoint you configured, using your own key |

If you must keep all tenant data inside the browser, leave the AI Assistant
set to **Off**.

---

## 9. Cleanup

### Option A: clear browser data

Click **Reset app** in the dashboard header. This clears:

- Configuration (Client ID, Tenant ID)
- Scan results
- The MSAL authentication cache

Closing the browser tab has the same effect — `sessionStorage` is session-scoped.

### Option B: delete the App Registration

Run the cleanup script:

```powershell
.\infra\cleanup-entrapass.ps1 -ClientId "<your-client-id>" -RevokeConsent
```

This removes:

- The App Registration from your tenant
- The service principal and its admin consent (only with `-RevokeConsent`)

> Omit `-RevokeConsent` if you want to keep the App Registration's consent for
> future scans but still delete the app.

---

## 10. Troubleshooting

| Problem | Likely cause | Solution |
|---|---|---|
| **"Sign-in failed"** | Wrong Client ID or Tenant ID | Re-check the GUIDs against the App Registration's Overview page |
| **Blank scan results** | Permissions not consented | Azure Portal → App registrations → API permissions → Grant admin consent |
| **"Graph API error" / access denied** | Insufficient delegated permissions | Ensure all 7 permissions are added and admin consent is granted |
| **Redirect / reply URL mismatch** | SPA redirect URI doesn't match the portal URL | The redirect URI must match your portal URL exactly |
| **Config validation failed** | Invalid GUID format | Client ID and Tenant ID must be in 8-4-4-4-12 hex format |
| **Session expired mid-scan** | Access token expired (~60 min) | Sign out and sign in again |
| **Cleanup script fails** | Microsoft Graph module missing or insufficient rights | The script auto-installs the module; run as a user with `Application.ReadWrite.All` |

### Known limitations

| Limitation | Detail |
|---|---|
| **Up to 50 users** | The scan analyzes per-user detail for the first 50 users returned, for performance |
| **Up to 100 devices** | Device ownership is resolved for the first 100 devices |
| **Read-only** | EntraPass is an assessment tool — it cannot make changes to your tenant |
| **No persistent storage** | Results are lost when the tab closes; re-scan or capture them before closing |
| **Entra ID only** | Cannot assess on-prem resources or non-Microsoft identity providers |

---

## 11. FAQ

### Is EntraPass a Microsoft product?

No. EntraPass is an **open-source community tool** licensed under MIT. It is not
affiliated with or endorsed by Microsoft.

### Where is my data stored?

**In your browser only.** Nothing is stored on an EntraPass server, sent to
analytics, or shared with third parties. The only exception is the optional AI
Assistant, which sends data to an AI endpoint only if you explicitly enable it.
See [Data Architecture](data-architecture.md) for details.

### Can this tool make changes to my tenant?

**No.** EntraPass is **read-only**. It only reads data via Microsoft Graph — it
cannot create users, change policies, or modify configurations.

### Does the tool store passwords?

**No.** EntraPass never requests, reads, or stores passwords. It only checks
*which* authentication methods are registered — never their secrets.

### Why do I need to create an App Registration?

The App Registration is how EntraPass authenticates to Microsoft Graph on your
behalf. By creating it in **your own tenant** you keep full control:

| Aspect | Your App Registration | A shared third-party app |
|---|---|---|
| **Control** | You own it | A third party controls it |
| **Audit** | Full audit trail in your tenant | No visibility |
| **Permissions** | You grant and review consent | Pre-consented by the vendor |
| **Lifecycle** | Delete it whenever you want | Persistent |

### What if I don't want to use the setup wizard?

When self-hosting, set `VITE_CLIENT_ID` and `VITE_TENANT_ID` at build time. The
wizard is skipped and the app goes straight to sign-in. You still need an App
Registration in your tenant.

### Can I use this in production?

EntraPass is **MIT-licensed with no warranty**. It is an **assessment tool** to
help plan a passkey migration. Review the code and test in a non-production
tenant first.

### How do I get support?

Open an issue on the [GitHub repository](https://github.com/arusso-aboutcloud/EntraPass/issues).
As an open-source project, support is community-driven.
