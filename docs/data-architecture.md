# EntraPass — Data Architecture

> **Version:** 1.0.0
> **Last updated:** 2026-05-16

---

## Table of contents

1. [Data flow overview](#1-data-flow-overview)
2. [Data at each step](#2-data-at-each-step)
3. [Data classification](#3-data-classification)
4. [Storage and retention](#4-storage-and-retention)
5. [Data lifecycle](#5-data-lifecycle)
6. [AI Assistant data handling](#6-ai-assistant-data-handling)

---

## 1. Data flow overview

EntraPass processes data exclusively in the user's browser. The only server it
contacts for tenant data is the Microsoft Graph API. (The optional AI Assistant
is the one exception — see [section 6](#6-ai-assistant-data-handling).) Here is
where data lives at each stage:

```
Step 0: App Registration
┌─────────────────────────────┐     ┌─────────────────────────────┐
│  User's Entra ID tenant     │     │  User's Browser             │
│  App Registration (SPA)     │     │  (no data yet)              │
│  PKCE, 7 delegated perms    │     │                             │
└─────────────────────────────┘     └─────────────────────────────┘

Step 1: Configuration
                                    ┌─────────────────────────────┐
                                    │  sessionStorage             │
                                    │  entrapass_config: {        │
                                    │    clientId, tenantId,      │
                                    │    redirectUri              │
                                    │  }                          │
                                    └─────────────────────────────┘

Step 2: Authentication (MSAL PKCE)
┌─────────────────────────────┐     ┌─────────────────────────────┐
│  Microsoft Entra ID         │     │  Browser (MSAL cache)       │
│  (user's tenant)            │     │  Access token (expires ~1h) │
│  Validates credentials      │     │  ID token (user info)       │
└─────────────────────────────┘     └─────────────────────────────┘

Step 3: Data fetching (Microsoft Graph)
┌─────────────────────────────┐     ┌─────────────────────────────┐
│  Microsoft Graph API        │────▶│  Browser memory (variables) │
│  (user's tenant data)       │     │  Raw API responses held     │
│  Users, devices, policies,  │     │  temporarily for analysis   │
│  apps, auth methods, logs   │     │                             │
└─────────────────────────────┘     └─────────────────────────────┘

Step 4: Analysis
                                    ┌─────────────────────────────┐
                                    │  Browser memory             │
                                    │  Analyzer processes data    │
                                    │  into structured results    │
                                    └─────────────────────────────┘

Step 5: Storage
                                    ┌─────────────────────────────┐
                                    │  sessionStorage             │
                                    │  entrapass_results: {       │
                                    │    passkeyReadiness,        │
                                    │    apps, policies,          │
                                    │    toxicCombos,             │
                                    │    recommendations,         │
                                    │    narrative, timestamp     │
                                    │  }                          │
                                    └─────────────────────────────┘

Step 6: Display
                                    ┌─────────────────────────────┐
                                    │  Browser DOM (current tab)  │
                                    │  Rendered tables, stats,    │
                                    │  summary                    │
                                    └─────────────────────────────┘

Step 7: Cleanup
                                    ┌─────────────────────────────┐
                                    │  sessionStorage cleared     │
                                    │  All data removed           │
                                    └─────────────────────────────┘
```

---

## 2. Data at each step

### Step 0 — App Registration (user's Azure tenant)

| Data | Where | Duration | Security |
|---|---|---|---|
| App Registration metadata | User's Entra ID tenant | Until cleanup | User-controlled |
| Redirect URIs | App Registration config | Until cleanup | User-controlled |
| OAuth2 permission grants | App Registration config | Until cleanup | User-controlled |
| Client ID (public) | App Registration properties | Until cleanup | Public (SPA) |

### Step 1 — Configuration (browser)

| Data | Where | Duration | Security |
|---|---|---|---|
| Client ID | `sessionStorage.entrapass_config` | Session | Same-origin only |
| Tenant ID | `sessionStorage.entrapass_config` | Session | Same-origin only |
| Redirect URI | `sessionStorage.entrapass_config` | Session | Same-origin only |

### Step 2 — Authentication (MSAL)

| Data | Where | Duration | Security |
|---|---|---|---|
| Access token | MSAL cache (`sessionStorage`) | ~60 min or until tab close | Same-origin, HTTPS |
| ID token | MSAL cache (`sessionStorage`) | ~60 min or until tab close | Same-origin, HTTPS |
| Auth code (transient) | Redirect URL fragment | Seconds (exchanged for a token) | HTTPS, PKCE-protected |

### Step 3 — Fetched data (Microsoft Graph)

| Data | Where | Duration | Notes |
|---|---|---|---|
| User profiles (id, name, UPN) | Browser memory variable | Until page reload | Up to 50 users analyzed in detail |
| Device info (OS, version, compliance) | Browser memory variable | Until page reload | Up to 100 devices |
| Conditional Access policies | Browser memory variable | Until page reload | All policies |
| Applications / service principals | Browser memory variable | Until page reload | All apps and SPs |
| Auth methods per user | Browser memory variable | Until page reload | `GET /users/{id}/authenticationMethods` |
| Sign-in activity (last sign-in) | Browser memory variable | Until page reload | `GET /users/{id}/signInActivity` |
| Group membership | Browser memory variable | Until page reload | `GET /users/{id}/memberOf` |

### Step 4 — Analysis results (browser memory)

| Data | Produced by | Duration |
|---|---|---|
| Per-user readiness (status, issues) | `analyzePasskeyReadiness()` | Until saved or reloaded |
| Per-app compatibility (severity, fix) | `analyzeAppCompatibility()` | Until saved or reloaded |
| Per-policy analysis | `analyzePolicies()` | Until saved or reloaded |
| Toxic combinations | `findToxicCombinations()` | Until saved or reloaded |
| Recommendations + narrative | `generateRecommendations()` / `generateNarrative()` | Until saved or reloaded |

### Step 5 — Stored results (`sessionStorage`)

| Key | Content | Approx. size | Duration |
|---|---|---|---|
| `entrapass_config` | `{ clientId, tenantId, redirectUri }` | ~150 bytes | Session |
| `entrapass_results` | Full analysis result object | ~50–200 KB | Session |
| MSAL cache keys | MSAL internal token cache | ~2–5 KB | Session |

### Step 6 — Rendered UI (DOM)

| Data | Where | Duration |
|---|---|---|
| Stats grid (4 numbers) | `#stats-grid` | Until re-render |
| Readiness table | `#readiness-table` | Until tab switch |
| Apps table | `#apps-table` | Until tab switch |
| Policies table | `#policies-table` | Until tab switch |
| Recommendations + summary | `#summary-content` | Until re-render |

### Step 7 — Cleanup

| Action | What happens |
|---|---|
| Browser tab close | `sessionStorage` cleared; all in-memory data freed |
| "Reset app" button | `entrapass_config` and `entrapass_results` removed |
| `cleanup-entrapass.ps1` | App Registration (and optionally the service principal / consent) deleted |

---

## 3. Data classification

| Classification | Details |
|---|---|
| **Personal data (PII)** | User display names, UPNs, device registrations, sign-in activity |
| **Security data** | Auth method *presence* flags (e.g. "has FIDO2" — **not** secrets), CA policies |
| **App data** | App registration names and API permission configs (public metadata) |
| **Organizational data** | Tenant ID (public), tenant display name |
| **Credentials** | **None** — no passwords, client secrets, or API keys are stored or transmitted |

### What is NOT collected

- Passwords or password hashes
- Authentication method secrets (TOTP seeds, FIDO2 private keys)
- Emails, messages, or file/SharePoint content
- Any data outside the read-only Microsoft Graph scopes listed in the architecture doc

### Anonymous page analytics

EntraPass uses **self-hosted Umami** at `analytics.aboutcloud.io`. Umami records:

- The URL of the page visited and the referrer
- Browser and OS strings
- IP-derived country (the IP itself is hashed and not stored by Umami)
- An anonymous session identifier

Umami does **not** record: Microsoft Graph responses, scan results, user
identifiers, tenant identifiers, app registration details, or anything typed into
the AI Assistant chat. Umami is hosted in Aboutcloud's private cloud — no
third-party analytics SaaS receives any data.

---

## 4. Storage and retention

| Storage type | Content | Retention | Security |
|---|---|---|---|
| **sessionStorage** | Config, results, MSAL cache | Session — cleared on tab close | Same-origin policy; not persisted to disk |
| **Browser memory** | Raw API responses, intermediate analysis | While the page is active | No cross-origin access |
| **DOM** | Rendered tables and text | While the tab is visible | No cross-origin access |
| **Server** | **None** | N/A | N/A |
| **Cookies** | **None** | N/A | N/A |
| **localStorage** | **None** (intentionally unused) | N/A | N/A |

### Why `sessionStorage` and not `localStorage`?

- `sessionStorage` is cleared when the browser tab closes — no persistent storage.
- `localStorage` persists indefinitely — intentionally avoided.
- No tenant data should remain on the machine after the user is done.

---

## 5. Data lifecycle

```
User opens the portal
  │
  ├── sessionStorage empty
  │
  ├── Setup: configuration        → sessionStorage
  │
  ├── Sign in: tokens             → MSAL cache (sessionStorage)
  │
  ├── Scan: raw data              → browser memory (variables)
  │
  ├── Analyze: results            → browser memory (objects)
  │
  ├── Render: display             → DOM elements
  │
  ├── Save: scan results          → sessionStorage
  │
User closes the tab
  │
  ├── sessionStorage cleared (browser behavior)
  │
  ├── All memory freed (browser GC)
  │
  └── [Optional] run cleanup script → App Registration deleted
        → zero data remaining on the machine
```

### Emergency data removal

| Situation | User action |
|---|---|
| Working on a shared computer | Close all browser tabs |
| Need to clear immediately | Click the "Reset app" button (clears config + results) |
| Remove all app artifacts | Run `cleanup-entrapass.ps1 -ClientId <id>` |
| Browser crashed before cleanup | MSAL cache and `sessionStorage` are session-scoped and cleared on next browser start |

---

## 6. AI Assistant data handling

The AI Assistant tab is **opt-in** and **off by default**. Its behavior depends
on the selected mode:

| Mode | Data leaving the browser |
|---|---|
| **Off** (default) | Nothing — rule-based responses only |
| **Cloudflare Workers AI** | A non-identifying summary (counts only) is built in the browser and sent to the Cloudflare Pages Function (`functions/ai/ask.js`), which calls Cloudflare Workers AI. No user names or UPNs are transmitted. |
| **Bring your own key (BYOK)** | A non-identifying summary (same shape as the Cloudflare mode) and your question are sent to the AI endpoint you configure (e.g. OpenAI, Azure OpenAI) using your own API key |

If you must keep all tenant data inside the browser, leave the AI Assistant set
to **Off**.
