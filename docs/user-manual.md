# EntraPass — User Manual

> **Version:** 1.0.0
> **Product:** EntraPass — Passkey Migration Assistant
> **Published by:** [Aboutcloud](https://aboutcloud.io)
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

For answers to common questions, see the [FAQ](FAQ.md).

---

## 1. What is EntraPass?

EntraPass is a **browser-based tool** that scans your Microsoft Entra ID tenant
to assess how ready your organization is for **passkey (FIDO2) authentication**.

It answers questions like:

- Which users already have passkeys registered?
- Which users can self-register a passkey with no IT help?
- Which users need a device update or MFA registration first?
- Which Conditional Access policies block passkey registration?
- Which app identities expose credentials that could bypass passkeys?

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
| **Azure Cloud Shell script** | Run a one-line script that creates the app and all 7 permissions, grants admin consent, and prints your Client ID and Tenant ID |
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

The Overview tab shows a high-level picture of your tenant's passkey readiness.

**Readiness score ring** — an animated 0–100 score that summarizes overall
readiness. The score is computed from your user breakdown and infrastructure state.
On tenants with more than 50 users the ring label changes to "Sample Readiness Score" and the verdict pill is labelled "(sampled)" to indicate the score is based on the first 50 users returned by Graph. When all scanned users are exempt or have no registration data available, the ring shows '—' and the verdict reads 'No scorable users' instead of a numeric score.

| Score band | Reading |
|---|---|
| 85–100 | Very strong — most users Ready or Capable |
| 65–84 | Good progress — some gaps to address |
| 40–64 | Needs work — significant blocked or unprepared users |
| 0–39 | Significant gaps — review FIDO2 policy and CA policies |

**Stat tiles** (six):

| Tile | Meaning |
|---|---|
| **Total** | Number of users analyzed |
| **Ready** | Users with a FIDO2 passkey already registered |
| **Capable** | Users who can self-register a passkey today |
| **Needs Prep** | Users with one gap to resolve |
| **Blocked** | Users blocked by multiple gaps or a CA policy |
| **Exempt** | Break-glass / guest / personal account — excluded from passkey targets |

**Readiness breakdown bar** — a proportional bar showing the tier distribution.

**Infrastructure health chips**:
- **FIDO2 policy** — whether the FIDO2 authentication method is enabled for the tenant.
- **TAP policy** — whether Temporary Access Pass is enabled (needed for onboarding).
- **App risks** — number of app registrations with password credentials present.
- **Policy gaps** — number of critical or high-severity CA policy findings.

**Executive summary** — a natural-language summary with recommendations, prioritized
from critical to low.

### Passkey Readiness tab

A detailed per-user view with filter pills and search.

**Filter pills** — click any tier to show only those users:
`All` | `Ready` | `Capable` | `Needs Prep` | `Blocked` | `Exempt`

**Search** — type any text to filter by display name, UPN, or account type.

**User cards** — each card shows:

| Field | Description |
|---|---|
| **Display name + UPN** | UPN is always shown prominently (users with the same display name are always shown as separate cards) |
| **Status badge** | Ready / Capable / Needs Prep / Blocked / Exempt |
| **Account type badge** | Member / Guest / Personal MSA / Break-glass |
| **Flags** | Privileged role, Stale sign-in (>90 days) |
| **Issues** | Specific blockers for that user |
| **Recommended action** | One specific next step |
| **Auth methods** | Colored chips for registered MFA methods (FIDO2, Authenticator, TOTP, phone, TAP, etc.) |
| **Devices** | Count and OS summary |
| **Groups** | Named group membership (up to 3 shown, then +N) |
| **Last sign-in** | Date of most recent sign-in |

**Phase planner** — below the user cards, a rollout roadmap groups users into
actionable phases:

| Phase | Who | What to do |
|---|---|---|
| Phase 1 — Pilot | Ready users | Start immediately — these users can enroll passkeys now |
| Phase 2 — Capable | Capable users | Enable passkey registration; guide self-enrollment |
| Phase 3 — Prepare | Needs Prep users | Address single gaps (MFA, device OS, device enrollment) |
| Phase 4 — Unblock | Blocked users | Resolve CA policies or multiple blockers |

**CSV export** — exports 13 columns: Display Name, UPN, Account Type, Status,
Privileged, Stale, Issues, Recommended Action, Auth Methods, Device Count, Device
Summary, Groups, Last Sign-In.

### App Identities tab

Analysis of **app registrations and service principals** relevant to passkey migration.
Microsoft first-party substrate service principals (Graph Explorer, Teams, Exchange,
Azure services, and other Microsoft-owned SPs) are excluded — they cannot be modified
by tenant admins and are not relevant to migration planning.

**Stat tiles:**

| Tile | What it counts |
|---|---|
| **Apps scanned** | All analyzed app registrations and non-Microsoft service principals |
| **Need attention** | Apps with one or more findings |
| **Clean** | Apps with no findings |
| **Expiring credentials** | Apps with credentials expiring imminently (conditional — shown only when > 0) |

**Filter pills** — click to narrow the list:
`All` | `Needs Attention` | `Clean`

Default pill when the tab opens: **Needs Attention** if any apps have findings;
otherwise **All**.

**List sections:**

| Section | Expand default | Contents |
|---|---|---|
| **Needs Attention** | Always expanded | Apps with findings, sorted by severity |
| **Clean** | Expanded when ≤ 10 apps; collapsed otherwise | Apps with no findings |

**Severity levels:**

| Severity | Meaning |
|---|---|
| **Critical / High** | Client secrets or expired credentials — the app authenticates without user interaction, bypassing CA, MFA, and passkey enforcement entirely |
| **Medium** | No delegated permissions on a user-facing app (may fall back to password), multi-tenant sign-in audience, or orphaned app with no owner |
| **Low** | Certificate credentials — more secure than secrets but still non-interactive |
| **Good** | No issues |

**Scanning app badge** — when the EntraPass scanner app itself appears in the list, it
displays a **Scanning app** badge for identification. Normal issue detection still applies.

**CSV export** — exports all scanned apps as a 15-column file:

| # | Column | Notes |
|---|---|---|
| 1 | App Name | Display name |
| 2 | Source | App Registration or Service Principal |
| 3 | App Type | spa / web / native / daemon / api |
| 4 | Sign-in Audience | AzureADMyOrg, AzureADMultipleOrgs, etc. |
| 5 | Compatible | Yes / No |
| 6 | Severity | critical / high / medium / low / good |
| 7 | Issues | Semicolon-separated list |
| 8 | Secrets | Count of client secrets |
| 9 | Certs | Count of certificate credentials |
| 10 | Earliest Expiry | ISO date of the nearest expiring credential |
| 11 | Owner Count | Number of registered owners |
| 12 | Orphaned | Yes / No |
| 13 | Multi-tenant | Yes / No |
| 14 | Created | ISO date of app creation |
| 15 | Fix Guide | Recommended remediation text |

A second block appended below the main rows lists per-credential expiry detail (App,
Credential label, Type, Severity, Expiry Date, Days Left, Age).

### CA Policies tab

All **Conditional Access policies** in your tenant, evaluated by their role in your
passkey deployment.

| Column | Description |
|---|---|
| **Policy** | Policy name |
| **Blocks Passkeys?** | Yes — the policy requires `password` as a grant control |
| **Action** | Fix recommendation if the policy blocks passkeys |

EntraPass categorises each policy by what it does:

| Role | Criteria |
|---|---|
| **Blocks passkeys** | Enabled; requires `password` grant control — prevents passkey-only auth |
| **Enforces passkeys** | Auth strength requires ALL combinations to be phishing-resistant (`fido2`, `windowsHelloForBusiness`, `x509CertificateMultiFactor`) |
| **Protects registration** | Targets the "Register security information" user action |
| **Blocks legacy auth** | Targets Exchange ActiveSync + Other clients with a Block control |
| **Risk-based** | Uses sign-in or user risk conditions |

A policy is credited as enforcing passkeys only when **every** entry in its authentication
strength's allowed combinations is phishing-resistant. The built-in **Passwordless MFA**
strength (which also allows `microsoftAuthenticatorPush` and `deviceBasedPush`) does not
qualify. Only the built-in **Phishing-resistant MFA** strength — or a custom strength
containing exclusively phishing-resistant combinations — is credited.

The recommended fix for a blocking policy is to replace the `password` grant control with
**Phishing-resistant MFA** authentication strength.

### AI Assistant tab (opt-in)

An optional AI chat for asking questions about your scan results. See
[section 8](#8-using-the-ai-assistant).

---

## 6. Understanding your results

### Readiness classification

| Status | Criteria | What to do |
|---|---|---|
| **Ready** | Has a FIDO2 passkey registered | Pilot group — start enforcing passkeys for these users |
| **Capable** | Has MFA + a modern device, no CA blocker | Direct to self-registration at `aka.ms/mfasetup` |
| **Needs Prep** | One gap: no MFA method, outdated device OS, or no modern device registered | Fix the single gap; user can then self-register |
| **Blocked** | Multiple gaps, or a CA policy actively blocking passkey registration | Resolve the CA policy first; then address any remaining gaps |
| **Exempt** | Break-glass account, guest, or personal account | Do not target for passkeys (these accounts are excluded by design) |

"Modern device" means: Windows 10+, iOS 16+, Android 14+, or macOS 13+.

### Account types

| Type | Detected by | Treatment |
|---|---|---|
| **Member** | Standard domain account | Included in readiness analysis |
| **Guest** | `#ext#` in UPN or `userType = Guest` | Exempt (passkey capability depends on home tenant) |
| **Personal account** | Common consumer email domains (gmail.com, outlook.com, icloud.com, proton.me, and others) | Exempt — governed by an external identity provider, not tenant policies |
| **Break-glass** | Name matches emergency account patterns | Exempt (no MFA by design — do not enroll passkeys) |

### Toxic combinations

High-severity alerts shown on the Overview tab:

| Severity | Example | Why it matters |
|---|---|---|
| **Critical** | A privileged user with no MFA and no passkey | Single-factor admin account is a direct security risk |
| **High** | A CA policy allows password fallback alongside passkey | Users can bypass passkeys by choosing password |

### Privileged user detection

A user is flagged as privileged when any entry in their `/memberOf` response has `@odata.type` equal to `#microsoft.graph.directoryRole` (the primary signal, reliable even when the scanning account has limited permissions) or when the entry's display name contains 'admin', 'global', 'privileged', or 'exchange' (a best-effort fallback that can produce false positives for groups with similar names).

### App credential staleness

Each password credential on an app registration is classified into one of four mutually exclusive states:

| State | Condition | Severity |
|---|---|---|
| **Expired** | `endDateTime` is in the past | Critical |
| **Expiring soon** | `endDateTime` is within 30 days | Critical |
| **Expiring** | `endDateTime` is 31–90 days away | High |
| **Stale** | Created more than 365 days ago and not expiring within 90 days | Medium |

Credentials with no `endDateTime` are not flagged (Graph returns `null` for some legacy secrets — known limitation).

### Recommendations

The recommendation list is prioritized:

```
Critical   →  High   →  Medium   →  Low   →  All Clear
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
| **Fix** | "Replace the password grant control with FIDO2 authentication strength..." |

### Phase planner

The phase planner (in the Passkey Readiness tab) translates user tier counts into
an actionable deployment plan:

- **Phase 1 — Pilot** with Ready users (zero blockers, can start now)
- **Phase 2 — Enable** Capable users to self-register (guided enrollment)
- **Phase 3 — Prepare** Needs Prep users (one targeted fix each)
- **Phase 4 — Unblock** blocked users (CA policy review and multi-gap resolution)

---

## 8. Using the AI Assistant

The AI Assistant is **opt-in and off by default**.

### Setup

1. Go to the **AI Assistant** tab.
2. Choose a mode:
   - **Off** — rule-based responses only; no data leaves your browser.
   - **Cloudflare Free AI** — uses the Cloudflare Pages Function (`functions/ai/ask.js`).
     Requires the optional AI binding to be configured in Cloudflare Pages settings.
   - **Bring your own key (BYOK)** — enter your API endpoint, key, and model
     (e.g. an OpenAI-compatible endpoint).

### Example questions

- "Which users are blocked by CA policies?"
- "What apps have password credentials that should be removed?"
- "Create a rollout plan for my tenant."
- "What does the readiness score mean?"
- "What is Temporary Access Pass and why does it matter?"

### Microsoft Learn references

When relevant, the AI Assistant ends each response with **1 to 3 Microsoft Learn
links** selected from a fixed, curated list embedded in the system prompt:

- A narrow single-topic question gets 1 link.
- A question spanning multiple topics (for example, CA policies + authentication
  strengths + passkey enrollment) gets 2 or 3 links.

All referenced URLs are verified `learn.microsoft.com` pages — no `aka.ms`
shortlinks, no invented URLs. The list is fixed in the source code and can only
be changed via a repository commit.

### Privacy

| Mode | Where your scan data goes |
|---|---|
| **Off** | Nowhere — stays in the browser |
| **Cloudflare Free AI** | A non-identifying summary (counts only) is sent to the Cloudflare Pages Function, which calls Cloudflare Workers AI |
| **BYOK** | The summary and your question are sent to the AI endpoint you configured, using your own key |

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

> Omit `-RevokeConsent` if you want to keep the consent grants for future scans
> but still remove the App Registration record.

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
| **All users show as Blocked (status = 0)** | Old cached results in sessionStorage | Click Reset app, then re-scan |
| **Cleanup script fails** | Microsoft Graph module missing or insufficient rights | The script auto-installs the module; run as a user with `Application.ReadWrite.All` |

### Known limitations

| Limitation | Detail |
|---|---|
| **Up to 50 users** | The scan fetches per-user detail for the first 50 users returned, for performance |
| **Up to 100 devices** | Device ownership is resolved for the first 100 devices |
| **Read-only** | EntraPass is an assessment tool — it cannot make changes to your tenant |
| **No persistent storage** | Results are lost when the tab closes; re-scan or export CSV before closing |
| **Entra ID only** | Cannot assess on-premises resources or non-Microsoft identity providers |
| **sessionStorage cache** | Scan results are cached for the browser session; always use the live user array counts (not pre-computed fields) for display accuracy |
