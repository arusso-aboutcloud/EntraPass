# EntraPass — Architecture Document

> **Version:** 0.1.0
> **License:** MIT
> **Last updated:** 2026-05-14

---

## Table of contents

1. [High-level architecture (HLD)](#1-high-level-architecture-hld)
2. [Low-level architecture (LLD)](#2-low-level-architecture-lld)
3. [Component descriptions](#3-component-descriptions)
4. [Authentication flow](#4-authentication-flow)
5. [Scan flow](#5-scan-flow)
6. [Security model](#6-security-model)

---

## 1. High-level architecture (HLD)

### 1.1 System overview

EntraPass is a **client-side browser application** that assesses passkey (FIDO2)
readiness in Microsoft Entra ID tenants. It operates entirely within the user's
browser — no backend servers, no data storage, no telemetry.

```
                ┌───────────────────────────────────────────────┐
                │               User's Browser                  │
                │                                                │
                │  ┌─────────────────┐  ┌──────────────────┐     │
                │  │  Setup Wizard   │─▶│  MSAL (PKCE)      │     │
                │  │  (T&C + Config) │  │  Authentication  │     │
                │  └─────────────────┘  └────────┬─────────┘     │
                │                                │               │
                │  ┌─────────────────┐           │               │
                │  │ Graph API Client│◀──────────┘               │
                │  │  (data fetcher) │                           │
                │  └────────┬────────┘                           │
                │           │                                    │
                │  ┌────────▼────────┐  ┌──────────────────┐     │
                │  │    Analyzer     │─▶│  Dashboard (UI)  │     │
                │  │  (browser-side) │  │  (5-tab view)    │     │
                │  └─────────────────┘  └──────────────────┘     │
                │                                                │
                │  sessionStorage ── entrapass_config            │
                │                 ── entrapass_results           │
                └───────────────────────────────────────────────┘
                                  │
                                  ▼
                ┌───────────────────────────────┐
                │  Microsoft Graph API (v1.0)   │
                │  (read-only, delegated)       │
                └───────────────────────────────┘
```

### 1.2 System boundaries

| Boundary | Description |
|---|---|
| **Inside the browser** | All processing, analysis, rendering, and storage |
| **Microsoft Graph API** | The only external call — authenticated, read-only, delegated permissions |
| **GitHub** | Source code distribution only |
| **Cloudflare Pages** | Static hosting (no backend, no API, no storage) |
| **Cloudflare Workers AI** | Optional — only used if the AI Assistant is enabled in "Cloudflare" mode |

### 1.3 Deployment topology

```
┌───────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   GitHub      │────▶│  Cloudflare      │────▶│  User's Browser  │
│  Repository   │     │  Pages (CDN)     │     │  (SPA app)       │
│  (source)     │     │  (static files)  │     └────────┬─────────┘
└───────────────┘     └──────────────────┘              │
                                                        │
                                              ┌─────────▼─────────┐
                                              │  Microsoft Graph  │
                                              │  API (v1.0)       │
                                              │  (read-only)      │
                                              └───────────────────┘
```

> **Note:** The App Registration is created by the **user** in their own tenant
> via the Azure Portal blade, the Cloud Shell script, or manual PowerShell. It is
> **not** part of the hosted application. See
> [`infra/deploy-entrapass.ps1`](../infra/deploy-entrapass.ps1) for the Cloud
> Shell deployment script.

---

## 2. Low-level architecture (LLD)

### 2.1 Module structure

```
index.html                 # SPA entry point: setup wizard + dashboard markup

src/
  main.js                  # Application orchestration: MSAL, scan, rendering
  graph.js                 # Microsoft Graph API client (data fetching)
  analyzer.js              # Analysis engine (passkey readiness, apps, policies)
  style.css                # UI styling

workers/
  ai.js                    # Optional Cloudflare Worker for the AI Assistant

infra/
  app-registration.bicep   # Bicep template (reference only — see note below)
  app-registration.json    # ARM JSON template (reference)
  deploy-entrapass.ps1     # Cloud Shell deployment script
  cleanup-entrapass.ps1    # App Registration cleanup script

docs/
  architecture.md          # This document
  data-architecture.md     # Data flow documentation
  installation.md          # Installation guide
  user-manual.md           # User manual
  diagrams/
    architecture.svg       # Architecture diagram
```

### 2.2 Module dependencies

```
index.html
  ├── src/style.css                 (stylesheet)
  └── src/main.js                   (ES module, type="module")
        ├── @azure/msal-browser     (MSAL.js v3, PKCE)
        ├── ./graph.js              (GraphAPI class)
        └── ./analyzer.js           (Analyzer class)
```

### 2.3 Data flow (detailed)

```
1. User clicks "Scan Tenant Now"
   │
2. main.js startScan() calls GraphAPI methods (Promise.all)
   ├── getUsers()                       → GET /users
   ├── getDevices()                     → GET /devices
   ├── getConditionalAccessPolicies()   → GET /identity/conditionalAccess/policies
   ├── getApplications()                → GET /applications
   ├── getServicePrincipals()           → GET /servicePrincipals
   ├── getOrganization()                → GET /organization
   ├── getAuthorizationPolicy()         → GET /policies/authorizationPolicy
   └── getAuthenticationMethodsPolicy() → GET /policies/authenticationMethodsPolicy
   │
3. For each user (up to 50):
   ├── getAuthenticationMethodsForUser(id) → GET /users/{id}/authenticationMethods
   ├── getUserSignInActivity(id)           → GET /users/{id}/signInActivity
   └── getUserMemberOf(id)                 → GET /users/{id}/memberOf
   │
4. For each device (up to 100):
   └── getDeviceRegisteredOwners(id)       → GET /devices/{id}/registeredOwners
   │
5. analyzer.analyzeAll({ users, devices, policies, apps, ... })
   ├── analyzePasskeyReadiness()  → per-user readiness
   ├── analyzeAppCompatibility()  → per-app compatibility
   ├── analyzePolicies()          → per-policy analysis
   ├── findToxicCombinations()    → security risks
   ├── generateRecommendations()  → prioritized actions
   └── generateNarrative()        → executive summary
   │
6. renderDashboard(results)       → 5-tab view
```

---

## 3. Component descriptions

### 3.1 `index.html` — application shell

| Aspect | Detail |
|---|---|
| **Purpose** | Single-page application shell with the setup wizard and the dashboard |
| **Sections** | Auth screen (multi-step wizard), dashboard (5 tabs), loading overlay |
| **State** | `hidden` / `active` CSS classes toggle section visibility |
| **Key IDs** | `auth-screen`, `dashboard`, `tab-*`, `stats-grid`, etc. |

### 3.2 `src/main.js` — application orchestrator

| Function | Responsibility |
|---|---|
| `loadConfig()` | Reads the App Registration config from `sessionStorage` or `VITE_*` env vars |
| `getMsalConfig()` | Builds the MSAL configuration object |
| `showAuthScreen()` | Manages the setup wizard flow |
| `window.signIn()` | Initiates the MSAL PKCE redirect login |
| `window.signOut()` | Logs out and clears the session |
| `window.startScan()` | Orchestrates the full scan pipeline |
| `renderDashboard()` | Calls all render functions to populate the 5 tabs |

### 3.3 `src/graph.js` — Graph API client

| Method | API endpoint | Permission needed |
|---|---|---|
| `getUsers()` | `GET /users` | `User.Read.All` |
| `getDevices()` | `GET /devices` | `Device.Read.All` |
| `getConditionalAccessPolicies()` | `GET /identity/conditionalAccess/policies` | `Policy.Read.All` |
| `getApplications()` | `GET /applications` | `Application.Read.All` |
| `getServicePrincipals()` | `GET /servicePrincipals` | `Application.Read.All` |
| `getOrganization()` | `GET /organization` | `Organization.Read.All` |
| `getAuthenticationMethodsForUser()` | `GET /users/{id}/authenticationMethods` | `User.Read.All` |
| `getUserSignInActivity()` | `GET /users/{id}/signInActivity` | `AuditLog.Read.All` |
| `getUserMemberOf()` | `GET /users/{id}/memberOf` | `User.Read.All` |
| `getDeviceRegisteredOwners()` | `GET /devices/{id}/registeredOwners` | `Device.Read.All` |
| `getAuthorizationPolicy()` | `GET /policies/authorizationPolicy` | `Policy.Read.All` |
| `getAuthenticationMethodsPolicy()` | `GET /policies/authenticationMethodsPolicy/...` | `Policy.Read.All` |

### 3.4 `src/analyzer.js` — analysis engine

| Method | Input | Output |
|---|---|---|
| `analyzePasskeyReadiness()` | users, devices, policies | Per-user readiness plus breakdown |
| `analyzeAppCompatibility()` | apps, servicePrincipals | Per-app compatibility plus fixes |
| `analyzePolicies()` | policies | Per-policy block/allow analysis |
| `findToxicCombinations()` | users, policies | Critical / high-risk combinations |
| `generateRecommendations()` | all analysis | Prioritized recommendations |
| `generateNarrative()` | all analysis | Executive summary text |

### 3.5 `infra/` — deployment templates

| File | Type | Purpose |
|---|---|---|
| `deploy-entrapass.ps1` | PowerShell script | Cloud Shell deployment — creates the App Registration, adds 7 Graph delegated permissions, outputs the Client ID |
| `cleanup-entrapass.ps1` | PowerShell script | Removes the App Registration and optionally revokes admin consent |
| `app-registration.bicep` | Bicep template | **Reference only.** `Microsoft.Graph/applications` Bicep deployment is not reliably supported |
| `app-registration.json` | ARM JSON template | **Reference only**, same caveat as the Bicep template |

**Recommended deployment methods** (in order of ease):

1. **Azure Portal App Registration blade** — the setup wizard links to it directly.
2. **Azure Cloud Shell script:**
   ```powershell
   irm https://raw.githubusercontent.com/arusso-aboutcloud/EntraPass/main/infra/deploy-entrapass.ps1 | iex
   ```
3. **Manual PowerShell** with the Microsoft Graph PowerShell module.

All three methods create a **PKCE-only SPA** with no client secret
(`passwordCredentials: []`). See the
[Installation Guide](installation.md) for full steps.

---

## 4. Authentication flow

```
┌──────────┐         ┌────────────────┐         ┌───────────────────┐
│  User    │         │  MSAL.js       │         │  Microsoft Entra  │
│  Browser │         │  (PKCE)        │         │  (user's tenant)  │
└────┬─────┘         └───────┬────────┘         └────────┬──────────┘
     │                       │                           │
     │ 1. Click "Sign in"    │                           │
     │──────────────────────▶│                           │
     │                       │ 2. PKCE auth request      │
     │                       │   (code_challenge, S256)  │
     │                       │──────────────────────────▶│
     │ 3. Redirect to login  │                           │
     │◀──────────────────────│                           │
     │ 4. User authenticates │                           │
     │──────────────────────────────────────────────────▶│
     │ 5. Auth code redirect │                           │
     │◀──────────────────────────────────────────────────│
     │                       │ 6. Exchange code for      │
     │                       │    token (PKCE verified)  │
     │                       │──────────────────────────▶│
     │                       │ 7. Access + ID token      │
     │                       │◀──────────────────────────│
     │ 8. Graph API calls    │                           │
     │    with Bearer token  │                           │
     │──────────────────────────────────────────────────▶│
```

**Key properties:**

- **PKCE (Proof Key for Code Exchange)** — prevents authorization code interception.
- **No client secret** — SPA apps cannot securely store secrets, so none is used.
- **Delegated permissions** — the app acts on behalf of the signed-in user.
- **Token scope** — limited to Microsoft Graph read operations.
- **Token cache** — `sessionStorage`, cleared when the browser tab closes.

---

## 5. Scan flow

```
┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│  main.js │   │ graph.js │   │ analyzer │   │   UI     │
│ (orches- │   │ (fetch)  │   │ (analyze)│   │ (render) │
│  trator) │   │          │   │          │   │          │
└────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘
     │ startScan()  │              │              │
     │─────────────▶│              │              │
     │ Phase 1:     │              │              │
     │ Promise.all( │              │              │
     │   getUsers,  │── Graph ────▶│              │
     │   getDevices,│── Graph ────▶│              │
     │   ...)       │              │              │
     │◀─────────────│              │              │
     │ Phase 2:     │              │              │
     │ per-user     │── Graph ────▶│              │
     │ details      │              │              │
     │◀─────────────│              │              │
     │ Phase 3:     │              │              │
     │ device owners│── Graph ────▶│              │
     │◀─────────────│              │              │
     │ analyzeAll() │              │              │
     │────────────────────────────▶│              │
     │              │              │ result       │
     │              │              │─────────────▶│
     │ renderDash() │              │              │
     │───────────────────────────────────────────▶│
```

---

## 6. Security model

### 6.1 Threat model

| Threat | Mitigation |
|---|---|
| **Token interception** | PKCE (S256 code challenge), no client secret |
| **Cross-tenant access** | The user's App Registration lives in their own tenant; delegated permissions only |
| **Data exfiltration** | All analysis happens in the browser; no calls to an EntraPass server |
| **Stored XSS** | No user-supplied content is persisted beyond config GUIDs in `sessionStorage` |
| **Supply chain** | Open source (MIT); build verifiable from source; Trivy + Dependabot scanning |
| **Credential leak** | No service principal secret, no client secret, no API keys stored or transmitted |

### 6.2 Required permissions (Microsoft Graph, delegated)

| Permission | Why it is needed |
|---|---|
| `User.Read` | Sign in and read the signed-in user's profile |
| `User.Read.All` | List all users in the tenant |
| `Device.Read.All` | List all devices and their OS versions |
| `Policy.Read.All` | Read Conditional Access policies and the authentication-methods policy |
| `Application.Read.All` | Read app registrations for the compatibility check |
| `AuditLog.Read.All` | Read sign-in activity (last sign-in time) |
| `Organization.Read.All` | Read the tenant display name |

### 6.3 Data residency

```
Data at rest:    sessionStorage (browser, not persisted to disk)
Data in transit: HTTPS / TLS to the Microsoft Graph API
Data processing: Browser JavaScript (V8 engine)
Data deletion:   Tab close          → sessionStorage cleared
                 "Reset app" button → config + results cleared
                 Cleanup script     → App Registration deleted
```

> **AI Assistant note:** when the AI Assistant is enabled, scan results are sent
> to the configured AI endpoint (Cloudflare Workers AI, or your own
> bring-your-own-key endpoint). When the AI Assistant is **off** (the default),
> no data leaves the browser except Graph API calls. See the
> [Data Architecture](data-architecture.md) document for details.
