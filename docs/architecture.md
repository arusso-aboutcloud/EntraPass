# EntraPass — Architecture Document

> **Version:** 0.1.0  
> **License:** MIT  
> **Last Updated:** 2026-05-14

---

## Table of Contents

1. [High-Level Architecture (HLD)](#1-high-level-architecture-hld)
2. [Low-Level Architecture (LLD)](#2-low-level-architecture-lld)
3. [Component Descriptions](#3-component-descriptions)
4. [Authentication Flow](#4-authentication-flow)
5. [Scan Flow](#5-scan-flow)
6. [Security Model](#6-security-model)

---

## 1. High-Level Architecture (HLD)

### 1.1 System Overview

EntraPass is a **client-side browser application** that assesses passkey (FIDO2) readiness in Microsoft Entra ID tenants. It operates entirely within the user\'s browser — no backend servers, no data storage, no telemetry.

```
                    +-----------------------------------------------+
                    |              User\'s Browser                    |
                    |                                                |
                    |  +-----------------+  +------------------+    |
                    |  |  Setup Wizard   |->|  MSAL (PKCE)     |    |
                    |  | (T&C + Config)  |  |  Authentication  |    |
                    |  +-----------------+  +--------+---------+    |
                    |                                  |            |
                    |  +-----------------+              |            |
                    |  |  GraphAPI Client|<------------+            |
                    |  |  (data fetcher) |                           |
                    |  +--------+--------+                           |
                    |           |                                    |
                    |  +--------v--------+  +------------------+    |
                    |  |    Analyzer      |->|  Dashboard (UI)  |    |
                    |  |  (browser-side)  |  |  (5 tabs view)   |    |
                    |  +-----------------+  +------------------+    |
                    |                                                |
                    |  sessionStorage --- entrapass_config           |
                    |                   --- entrapass_results        |
                    +-----------------------------------------------+
                                      |
                                      v
                    +-------------------------------+
                    |  Microsoft Graph API (v1.0)   |
                    |  (read-only, delegated)       |
                    +-------------------------------+
```

### 1.2 System Boundaries

| Boundary | Description |
|---|---|
| **Inside browser** | All processing, analysis, rendering, storage |
| **Microsoft Graph API** | Only external call (authenticated, read-only, delegated permissions) |
| **GitHub** | Source code distribution only |
| **Cloudflare Pages** | Static hosting (no backend, no API, no storage) |

### 1.3 Deployment Topology

```
+---------------+     +------------------+     +-----------------+
|   GitHub      |---->|  Cloudflare      |---->|  User\'s Browser |
|  Repository   |     |  Pages (CDN)     |     |  (SPA App)      |
|  (source)     |     |  (static files)  |     +--------+--------+
+---------------+     +------------------+              |
                                                        |
                                              +---------v---------+
                                              |  Microsoft Graph   |
                                              |  API (v1.0)        |
                                              |  (read-only)       |
                                              +-------------------+
```

> **Note:** The App Registration is deployed by the **user** to their own tenant via the Azure Portal blade, Cloud Shell script, or PowerShell. It is NOT part of the hosted application. See [`infra/deploy-entrapass.ps1`](../infra/deploy-entrapass.ps1) for the one-click deployment script.

---

## 2. Low-Level Architecture (LLD)

### 2.1 Module Structure

```
src/
  index.html       # Entry point, UI shell, setup wizard HTML
  main.js          # Application orchestration, MSAL, scan, rendering
  graph.js         # Microsoft Graph API client (data fetching)
  analyzer.js      # Business logic: passkey readiness analysis
  style.css        # UI styling

infra/
  deploy-entrapass.ps1     # Cloud Shell one-click deployment script
  app-registration.bicep   # Bicep template (CLI deployment)
  app-registration.json    # ARM JSON template (portal reference)
  cleanup-entrapass.ps1    # PowerShell cleanup script

docs/
  architecture.md          # This document
  data-architecture.md     # Data flow documentation
  installation.md          # Installation guide
  user-manual.md           # User manual
  diagrams/
    architecture.svg       # Architecture diagram
```

### 2.2 Module Dependencies

```
index.html
  +-- style.css (stylesheet)
  +-- main.js (module, type="module")
        +-- @azure/msal-browser (MSAL.js v3, PKCE)
        +-- ./graph.js (GraphAPI class)
        +-- ./analyzer.js (Analyzer class)
```

### 2.3 Data Flow (Detailed)

```
1. User clicks "Scan Tenant Now"
   |
2. main.js.startScan() calls GraphAPI methods (Promise.all)
   |
   +-- getUsers()              -> GET /users
   +-- getDevices()            -> GET /devices
   +-- getConditionalAccessPolicies() -> GET /identity/conditionalAccess/policies
   +-- getApplications()       -> GET /applications
   +-- getServicePrincipals()  -> GET /servicePrincipals
   +-- getOrganization()       -> GET /organization
   +-- getAuthorizationPolicy() -> GET /policies/authorizationPolicy
   +-- getAuthenticationMethodsPolicy() -> GET /policies/authenticationMethodsPolicy
   |
3. For each user (up to 50):
   +-- getAuthenticationMethodsForUser(userId) -> GET /users/{id}/authenticationMethods
   +-- getUserSignInActivity(userId)           -> GET /users/{id}/signInActivity
   +-- getUserMemberOf(userId)                 -> GET /users/{id}/memberOf
   |
4. For each device (up to 100):
   +-- getDeviceRegisteredOwners(deviceId)     -> GET /devices/{id}/registeredOwners
   |
5. analyzer.analyzeAll({users, devices, policies, apps, ...})
   |
   +-- analyzePasskeyReadiness()  -> per-user readiness
   +-- analyzeAppCompatibility()  -> per-app compatibility
   +-- analyzePolicies()          -> per-policy analysis
   +-- findToxicCombinations()    -> security risks
   +-- generateRecommendations()  -> prioritized actions
   +-- generateNarrative()        -> executive summary
   |
6. renderDashboard(results)       -> 5 tab views
```

---

## 3. Component Descriptions

### 3.1 `index.html` — Application Shell

| Aspect | Detail |
|---|---|
| **Purpose** | Single-page application shell with setup wizard and dashboard |
| **Sections** | Auth screen (4-step wizard), Dashboard (5 tabs), Loading overlay |
| **State** | Classes `hidden`/`active` to toggle visibility |
| **Key IDs** | `auth-screen`, `dashboard`, `tab-*`, `stats-grid`, etc. |

### 3.2 `main.js` — Application Orchestrator

| Function | Responsibility |
|---|---|
| `loadConfig()` | Reads user\'s App Registration config from sessionStorage or VITE env vars |
| `getMsalConfig()` | Builds MSAL configuration object |
| `showAuthScreen()` | Manages setup wizard flow |
| `window.signIn()` | Initiates MSAL PKCE redirect login |
| `window.signOut()` | Logs out and clears session |
| `initializeApp()` | Sets up MSAL, shows dashboard |
| `window.startScan()` | Orchestrates the full scan pipeline |
| `renderDashboard()` | Calls all render functions |

### 3.3 `graph.js` — GraphAPI Client

| Method | API Endpoint | Permission Needed |
|---|---|---|
| `getUsers()` | `GET /users` | User.Read.All |
| `getDevices()` | `GET /devices` | Device.Read.All |
| `getConditionalAccessPolicies()` | `GET /identity/conditionalAccess/policies` | Policy.Read.All |
| `getApplications()` | `GET /applications` | Application.Read.All |
| `getServicePrincipals()` | `GET /servicePrincipals` | Application.Read.All |
| `getOrganization()` | `GET /organization` | Organization.Read.All |
| `getAuthenticationMethodsForUser()` | `GET /users/{id}/authenticationMethods` | User.Read.All |
| `getUserSignInActivity()` | `GET /users/{id}/signInActivity` | AuditLog.Read.All |
| `getUserMemberOf()` | `GET /users/{id}/memberOf` | User.Read.All |
| `getDeviceRegisteredOwners()` | `GET /devices/{id}/registeredOwners` | Device.Read.All |
| `getAuthorizationPolicy()` | `GET /policies/authorizationPolicy` | Policy.Read.All |
| `getAuthenticationMethodsPolicy()` | `GET /policies/authenticationMethodsPolicy` | Policy.Read.All |

### 3.4 `analyzer.js` — Analysis Engine

| Method | Input | Output |
|---|---|---|
| `analyzePasskeyReadiness()` | users, devices, policies | Per-user readiness + breakdown |
| `analyzeAppCompatibility()` | apps, servicePrincipals | Per-app compatibility + fixes |
| `analyzePolicies()` | policies | Per-policy block/allow analysis |
| `findToxicCombinations()` | users, policies | Critical/high risk combos |
| `generateRecommendations()` | all analysis | Prioritized recommendations |
| `generateNarrative()` | all analysis | Executive summary text |

### 3.5 `infra/` — Deployment Templates

| File | Type | Purpose |
|---|---|---|
| `deploy-entrapass.ps1` | PowerShell script | One-command Cloud Shell deployment — creates App Registration + 7 Graph delegated permissions + outputs Client ID |
| `app-registration.json` | ARM JSON template | Azure Portal custom deployment reference (create via Portal blade instead) |
| `app-registration.bicep` | Bicep | CLI-based deployment via `az deployment group create` |
| `cleanup-entrapass.ps1` | PowerShell script | Remove the App Registration and revoke admin consent |

**Recommended deployment method:** Use the **Azure Portal App Registration creation blade** (linked from the setup wizard) or run the Cloud Shell script:

```powershell
irm https://raw.githubusercontent.com/arusso-aboutcloud/EntraPass/main/infra/deploy-entrapass.ps1 | iex
```

All templates create a **PKCE-only SPA** with no client secrets (`passwordCredentials: []`).

---

## 4. Authentication Flow

```
+----------+         +----------------+         +-------------------+
|  User    |         |  MSAL.js       |         |  Microsoft Entra  |
|  Browser |         |  (PKCE)        |         |  (User\'s Tenant)  |
+----+-----+         +-------+--------+         +--------+----------+
     |                       |                           |
     | 1. Click "Sign In"    |                           |
     |---------------------->|                           |
     |                       |                           |
     |                       | 2. PKCE Auth Request      |
     |                       | (code_challenge, S256)   |
     |                       |-------------------------->|
     |                       |                           |
     | 3. Redirect to login  |                           |
     |<----------------------|                           |
     |                       |                           |
     | 4. User authenticates |                           |
     |-------------------------------------------------->|
     |                       |                           |
     | 5. Auth code redirect |                           |
     |<--------------------------------------------------|
     |                       |                           |
     |                       | 6. Exchange code for      |
     |                       |    token (PKCE verified)  |
     |                       |-------------------------->|
     |                       |                           |
     |                       | 7. Access + ID Token      |
     |                       |<--------------------------|
     |                       |                           |
     | 8. API calls with     |                           |
     |    Bearer token       |                           |
     |-------------------------------------------------->|
     |                       |                           |
```

**Key properties:**
- **PKCE (Proof Key for Code Exchange)** — prevents authorization code interception
- **No client secret** — SPA apps cannot securely store secrets, so none are used
- **Delegated permissions** — the app acts on behalf of the signed-in user
- **Token scope** — limited to Microsoft Graph read operations

---

## 5. Scan Flow

```
+----------+   +----------+   +----------+   +----------+
|  main.js |   | graph.js |   | analyzer |   |   UI     |
|  (orche- |   | (fetch)  |   | (analyze)|   | (render) |
|  strator) |   |          |   |          |   |          |
+----+-----+   +----+-----+   +----+-----+   +----+-----+
     |              |              |              |
     | startScan()  |              |              |
     |------------->|              |              |
     |              |              |              |
     | Phase 1:     |              |              |
     | Promise.all( |              |              |
     |   getUsers,  |------------->|              |
     |   getDevices,|------------->|              |
     |   ...        |              |              |
     | )            |              |              |
     |<-------------|              |              |
     |              |              |              |
     | Phase 2:     |              |              |
     | Per-user     |------------->|              |
     | details      |              |              |
     |<-------------|              |              |
     |              |              |              |
     | Phase 3:     |              |              |
     | Device owners|------------->|              |
     |<-------------|              |              |
     |              |              |              |
     | analyzeAll() |              |              |
     |---------------------------->|              |
     |              |              |              |
     |              |              | Result       |
     |              |              |------------->|
     |              |              |              |
     | renderDash() |              |              |
     |------------------------------------------->|
     |              |              |              |
```

---

## 6. Security Model

### 6.1 Threat Model

| Threat | Mitigation |
|---|---|
| **Token interception** | PKCE (S256 code challenge), no client secret |
| **Cross-tenant access** | User\'s app reg in their own tenant, delegated permissions |
| **Data exfiltration** | All analysis happens in browser, no server calls |
| **XSS (stored)** | No user input stored — configuration is in sessionStorage only |
| **Supply chain** | Open-source (MIT), verifiable build from source |
| **Credential leak** | No service principal, no client secret, no API keys |

### 6.2 Required Permissions (Microsoft Graph, Delegated)

| Permission | Why needed |
|---|---|
| `User.Read` | Sign in and read profile |
| `User.Read.All` | List all users in the tenant |
| `Device.Read.All` | List all devices and their OS versions |
| `Policy.Read.All` | Read Conditional Access policies + auth methods policy |
| `Application.Read.All` | Read app registrations for compatibility check |
| `AuditLog.Read.All` | Read sign-in activity (last sign-in time) |
| `Organization.Read.All` | Read tenant display name |

### 6.3 Data Residency

```
Data at rest:    sessionStorage (browser memory)
Data in transit: HTTPS (TLS 1.3 to Graph API)
Data processing: Browser JavaScript (V8 engine)
Data deletion:   Session ends -> storage cleared
                 Clear Configuration -> storage cleared
                 Cleanup script -> app registration deleted
```



