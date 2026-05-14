# EntraPass — Data Architecture

> **Version:** 0.1.0  
> **Last Updated:** 2026-05-14

---

## Table of Contents

1. [Data Flow Overview](#1-data-flow-overview)
2. [Data at Each Step](#2-data-at-each-step)
3. [Data Classification](#3-data-classification)
4. [Storage & Retention](#4-storage--retention)
5. [Data Lifecycle](#5-data-lifecycle)

---

## 1. Data Flow Overview

EntraPass processes data exclusively in the user\'s browser. No data is sent to any server other than Microsoft Graph API for fetching. Here\'s where data lives at each stage:

```
Step 0: App Registration
+-----------------------------+     +-----------------------------+
|  User\'s Azure Subscription |     |  User\'s Browser             |
|  App Registration (SPA)     |     |  (No data yet)              |
|  PKCE, 7 delegated perms   |     |                             |
+-----------------------------+     +-----------------------------+

Step 1: Configuration
                                    +-----------------------------+
                                    |  sessionStorage             |
                                    |  entrapass_config: {        |
                                    |    clientId, tenantId,      |
                                    |    redirectUri              |
                                    |  }                          |
                                    +-----------------------------+

Step 2: Authentication (MSAL PKCE)
+-----------------------------+     +-----------------------------+
|  Microsoft Entra ID         |     |  Browser Memory             |
|  (User\'s Tenant)           |     |  Access Token (expires 1h)  |
|  Validates credentials      |     |  ID Token (user info)       |
+-----------------------------+     +-----------------------------+

Step 3: Data Fetching (Microsoft Graph)
+-----------------------------+     +-----------------------------+
|  Microsoft Graph API        |---->|  Browser Memory (variable)  |
|  (User\'s Tenant Data)      |     |  Raw API responses stored   |
|  Users, Devices, Policies,  |     |  temporarily for analysis  |
|  Apps, Auth Methods, Logs   |     |                             |
+-----------------------------+     +-----------------------------+

Step 4: Analysis
                                    +-----------------------------+
                                    |  Browser Memory             |
                                    |  Analyzer processes data    |
                                    |  into structured results    |
                                    +-----------------------------+

Step 5: Storage
                                    +-----------------------------+
                                    |  sessionStorage             |
                                    |  entrapass_results: {       |
                                    |    passkeyReadiness,        |
                                    |    apps, policies,          |
                                    |    toxicCombos,             |
                                    |    recommendations,         |
                                    |    narrative,               |
                                    |    timestamp                |
                                    |  }                          |
                                    +-----------------------------+

Step 6: Display
                                    +-----------------------------+
                                    |  Browser DOM (current tab)  |
                                    |  Rendered HTML tables,      |
                                    |  charts, summary            |
                                    +-----------------------------+

Step 7: Cleanup
                                    +-----------------------------+
                                    |  sessionStorage.clear()     |
                                    |  All data removed           |
                                    +-----------------------------+
```

---

## 2. Data at Each Step

### Step 0 — App Registration (User\'s Azure)

| Data | Where | Duration | Security |
|---|---|---|---|
| App Registration metadata | User\'s Azure tenant | Until cleanup | User-controlled |
| Redirect URIs | App Registration config | Until cleanup | User-controlled |
| OAuth2 permissions | App Registration config | Until cleanup | User-controlled |
| Client ID (public) | App Registration properties | Until cleanup | Public (SPA) |

### Step 1 — Configuration (Browser)

| Data | Where | Duration | Security |
|---|---|---|---|
| Client ID | `sessionStorage.entrapass_config` | Session | Same-origin only |
| Tenant ID | `sessionStorage.entrapass_config` | Session | Same-origin only |
| Redirect URI | `sessionStorage.entrapass_config` | Session | Same-origin only |

### Step 2 — Authentication (MSAL)

| Data | Where | Duration | Security |
|---|---|---|---|
| Access Token | Browser memory (MSAL cache) | 60 min or session end | Same-origin, HTTPS |
| ID Token | Browser memory (MSAL cache) | 60 min or session end | Same-origin, HTTPS |
| Auth Code (transient) | Redirect URL fragment | Seconds (exchanged for token) | HTTPS, PKCE protected |

### Step 3 — Fetched Data (Microsoft Graph)

| Data | Where | Duration | Notes |
|---|---|---|---|
| User profiles (ids, names, UPNs) | Browser memory variable | Until page refresh | Up to 50 users |
| Device info (OS, version, compliance) | Browser memory variable | Until page refresh | Up to 100 devices |
| CA Policies | Browser memory variable | Until page refresh | All policies |
| Applications / Service Principals | Browser memory variable | Until page refresh | All apps + SPs |
| Auth Methods per user | Browser memory variable | Until page refresh | `GET /users/{id}/authMethods` |
| Sign-in logs (last activity) | Browser memory variable | Until page refresh | `GET /users/{id}/signInActivity` |
| Group membership | Browser memory variable | Until page refresh | `GET /users/{id}/memberOf` |

### Step 4 — Analysis Results (Browser Memory)

| Data | Where | Duration |
|---|---|---|
| Per-user readiness (status, issues) | `analyzePasskeyReadiness()` output | Until saved or refreshed |
| Per-app compatibility (severity, fix) | `analyzeAppCompatibility()` output | Until saved or refreshed |
| Per-policy analysis | `analyzePolicies()` output | Until saved or refreshed |
| Toxic combinations | `findToxicCombinations()` output | Until saved or refreshed |
| Recommendations + Narrative | `generateRecommendations/Narrative()` | Until saved or refreshed |

### Step 5 — Stored Results (sessionStorage)

| Key | Content | Size Estimate | Duration |
|---|---|---|---|
| `entrapass_config` | `{clientId, tenantId, redirectUri}` | ~150 bytes | Session |
| `entrapass_results` | Full analysis result object | ~50-200 KB | Session |
| MSAL cache keys | MSAL internal token cache | ~2-5 KB | Session |

### Step 6 — Rendered UI (DOM)

| Data | Where | Duration |
|---|---|---|
| Stats grid (4 numbers) | `#stats-grid` element | Until re-render |
| Readiness table | `#readiness-table` element | Until tab switch |
| Apps table | `#apps-table` element | Until tab switch |
| Policies table | `#policies-table` element | Until tab switch |
| Recommendations list | `#summary-content` element | Until re-render |

### Step 7 — Cleanup

| Action | What happens |
|---|---|
| `sessionStorage.clear()` | Config + results + MSAL cache removed |
| Browser tab close | All memory freed, sessionStorage cleared |
| `cleanup-entrapass.ps1` | App registration + service principal deleted |

---

## 3. Data Classification

| Classification | Details |
|---|---|
| **Personal Data (PII)** | User names, UPNs, device registrations, sign-in activity |
| **Security Data** | Auth methods (FIDO2 presence flag — NOT secrets), CA policies |
| **App Data** | App registration names, API permission configs (public metadata) |
| **Organizational Data** | Tenant ID (public), tenant display name |
| **Credentials** | **NONE** — no passwords, no client secrets, no API keys stored or transmitted |

### What is NOT collected

- Passwords or password hashes
- Authentication method secrets (TOTP seeds, FIDO2 keys)
- Emails or messages
- File contents or SharePoint documents
- Any data outside Microsoft Graph read scope
- Browser fingerprints, IP addresses, or analytics

---

## 4. Storage & Retention

| Storage Type | Content | Retention | Security |
|---|---|---|---|
| **sessionStorage** | Config + results + MSAL cache | Session (cleared on tab close) | Same-origin policy, not persisted to disk |
| **Browser memory** | Raw API responses, intermediate analysis | While page is active | No cross-origin access |
| **DOM** | Rendered tables, charts, text | While tab is visible | No cross-origin access |
| **Server** | **NONE** | N/A | N/A |
| **Cookies** | **NONE** | N/A | N/A |
| **localStorage** | **NONE** (intentionally not used) | N/A | N/A |

### Why sessionStorage and NOT localStorage?

- `sessionStorage` is cleared when the browser tab closes — no persistent storage
- `localStorage` persists indefinitely — intentionally avoided
- No user data should remain after the user is done

---

## 5. Data Lifecycle

```
User opens portal
  |
  +-- sessionStorage empty
  |
  +-- Setup: Configuration -> sessionStorage
  |
  +-- Sign in: Tokens -> MSAL cache (memory)
  |
  +-- Scan: Raw data -> Browser memory (variables)
  |
  +-- Analyze: Results -> Browser memory (objects)
  |
  +-- Render: Display -> DOM elements
  |
  +-- Save: Scan results -> sessionStorage
  |
User closes tab
  |
  +-- sessionStorage cleared (browser behavior)
  |
  +-- All memory freed (browser GC)
  |
  +-- [Optional] Run cleanup script -> Azure app reg deleted
  |
  +-- Zero data remaining on the machine
```

### Emergency Data Removal

| Situation | User Action |
|---|---|
| Working on shared computer | Close all browser tabs |
| Need to clear immediately | Click "Reset app" button (clears config + results) |
| Remove all app artifacts | Run `cleanup-entrapass.ps1 -ClientId <id>` |
| Browser crash (no cleanup) | MSAL cache is memory-only, sessionStorage cleared on next browser restart |
