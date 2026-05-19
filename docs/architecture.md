# EntraPass — Architecture Document

> **Version:** 1.0.0
> **License:** MIT
> **Published by:** [Aboutcloud](https://aboutcloud.io)
> **Last updated:** 2026-05-16

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
browser — no backend servers, no data storage, no telemetry of tenant data.

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
| **Cloudflare Workers AI** | Optional — only used if the AI Assistant is enabled in "Cloudflare" mode, via the Pages Function at `functions/ai/ask.js` |

### 1.3 Deployment topology

```
┌───────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   GitHub      │────▶│  Cloudflare      │────▶│  User's Browser  │
│  Repository   │     │  Pages (CDN)     │     │  (SPA app)       │
│  (source)     │     │  + Pages Fn      │     └────────┬─────────┘
└───────────────┘     │  (AI assistant)  │              │
                      └──────────────────┘              │
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
  analyzer.js              # Analysis engine (passkey readiness, apps, policies, score)
  style.css                # UI styling

functions/
  ai/
    ask.js                 # Cloudflare Pages Function — optional AI Assistant endpoint

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
  FAQ.md                   # Frequently asked questions
  diagrams/
    architecture.svg       # Architecture diagram (animated SVG)
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
   ├── getOrganization()                → GET /organization (incl. verifiedDomains)
   ├── getAuthorizationPolicy()         → GET /policies/authorizationPolicy
   └── getAuthenticationMethodsPolicy() → GET /policies/authenticationMethodsPolicy
   │
3. Bulk registration report (single call, all users):
   └── getUserRegistrationDetails()        → GET /reports/authenticationMethods/userRegistrationDetails
   │
4. For each user (up to 50):
   ├── getUserSignInActivity(id)           → GET /users/{id}?$select=signInActivity
   └── getUserMemberOf(id)                 → GET /users/{id}/memberOf
   │
5. For each device (up to 100):
   └── getDeviceRegisteredOwners(id)       → GET /devices/{id}/registeredOwners
   │
6. analyzer.analyzeAll({ users, devices, policies, apps, ... })
   ├── classifyAccountType()      → member / guest / personal / breakglass
   ├── analyzePasskeyReadiness()  → 5-tier per-user status (ready/capable/needsPrep/blocked/exempt/unknown)
   ├── analyzeAppCompatibility()  → per-app compatibility (App Identities tab); Microsoft-managed substrate SPs excluded; app registrations always included; returns flat array of custom apps only
   ├── analyzePolicies()          → per-policy analysis
   ├── findToxicCombinations()    → critical/high security risks
   ├── generateRecommendations()  → prioritized actions
   ├── generateNarrative()        → executive summary
   └── computeReadinessScore()    → 0–100 composite score
   │
7. renderDashboard(results)       → 5-tab view
```

---

## 3. Component descriptions

### 3.1 `index.html` — application shell

| Aspect | Detail |
|---|---|
| **Purpose** | Single-page application shell with the setup wizard and the dashboard |
| **Sections** | Auth screen (multi-step wizard), dashboard (5 tabs), loading overlay |
| **State** | `hidden` / `active` CSS classes toggle section visibility |
| **Key IDs** | `auth-screen`, `dashboard`, `tab-*`, `stats-grid`, `readiness-section`, etc. |

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
| `renderOverviewHero()` | Animated score ring, stat tiles, infrastructure chips, recommendations |
| `renderReadiness()` | 5-tier user cards, filter pills, search, phase planner |
| `renderUserCard()` | Per-user card with status badge, account badge, auth chips, recommended action |
| `exportReadinessCsv()` | 15-column CSV export of the readiness data |
| `renderApps()` | App Identities tab — stat tiles (Apps scanned / Need attention / Clean + conditional Expiring credentials), 3 filter pills, 2 sections (Needs Attention / Clean collapsible) |
| `exportAppsCsv()` | 15-column CSV export of the app identities data |

### 3.3 `src/graph.js` — Graph API client

| Method | API endpoint | Permission needed |
|---|---|---|
| `getUsers()` | `GET /users` | `User.Read.All` |
| `getDevices()` | `GET /devices` | `Device.Read.All` |
| `getConditionalAccessPolicies()` | `GET /identity/conditionalAccess/policies` | `Policy.Read.All` |
| `getApplications()` | `GET /applications` | `Application.Read.All` |
| `getServicePrincipals()` | `GET /servicePrincipals` | `Application.Read.All` |
| `getOrganization()` | `GET /organization?$select=id,displayName,verifiedDomains` | `Organization.Read.All` |
| `getUserRegistrationDetails()` | `GET /reports/authenticationMethods/userRegistrationDetails` | `AuditLog.Read.All` + Reports Reader role (see [Authentication Methods Activity: Permissions and licenses](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity)) |
| `getUserSignInActivity()` | `GET /users/{id}?$select=signInActivity` | `AuditLog.Read.All` |
| `getUserMemberOf()` | `GET /users/{id}/memberOf` | `User.Read.All` |
| `getDeviceRegisteredOwners()` | `GET /devices/{id}/registeredOwners` | `Device.Read.All` |
| `getAuthorizationPolicy()` | `GET /policies/authorizationPolicy` | `Policy.Read.All` |
| `getAuthenticationMethodsPolicy()` | `GET /policies/authenticationMethodsPolicy/...` | `Policy.Read.All` |

### 3.4 `src/analyzer.js` — analysis engine

| Method | Input | Output |
|---|---|---|
| `classifyAccountType()` | user object, tenant domain | `member` / `guest` / `personal` / `breakglass` |
| `classifyAuthMethods()` | `methodsRegistered` string array (from registration report) | Typed method list with labels |
| `analyzePasskeyReadiness()` | users, devices, policies, auth methods | Per-user 5-tier status + counts; `unknown` tier used when registration data unavailable |
| `generateRecommendedAction()` | user status, issues, auth methods | Single recommended next step string |
| `summarizeDevices()` | user device list | "Windows 10 · iOS 16 +N" compact string |
| `analyzeAppCompatibility()` | apps, servicePrincipals | Per-app compatibility + severity + fix |
| `analyzePolicies()` | policies | Per-policy block/allow analysis + gaps |
| `findToxicCombinations()` | users, policies | Critical / high-risk combinations |
| `generateRecommendations()` | all analysis | Prioritized recommendations list |
| `generateNarrative()` | all analysis | Executive summary text |
| `computeReadinessScore()` | passkeyReadiness, toxicCombos, policyResult | 0–100 composite score; `null` when `effective = 0` or `total = 0` (ring renders '—') |

#### 5-Tier Passkey Readiness Status

| Status | Criteria |
|---|---|
| `ready` | FIDO2 passkey already registered |
| `capable` | Has MFA + a modern device, no CA blocker |
| `needsPrep` | Exactly one gap (MFA missing, device OS outdated, or no modern device) |
| `blocked` | Multiple gaps, or a CA policy actively blocking passkey registration |
| `exempt` | Break-glass account, guest (#ext# or userType=Guest), or personal account |
| `unknown` | Registration report unavailable; excluded from score denominator |

#### Data-availability (tri-state) model

Both the registration report and per-user sign-in activity are modelled as tri-state objects to prevent unavailable data being silently misread as "bad":

| Field | Shape | Notes |
|---|---|---|
| `registrationData` | `{ available, reason, isMfaRegistered, methodsRegistered, ... }` | `available: false` when report returns 403/429/5xx or user is disabled |
| `signInActivity` | `{ available, reason, lastSuccessfulSignInDateTime, lastSignInDateTime, lastNonInteractiveSignInDateTime }` | `available: false` when permission denied, no P1/P2 licence, or field absent |

`reason` values: `ok` · `permission_denied` · `no_record` · `http_429` · `http_5xx` · `network_error`

Badge rules that depend on tri-state availability:
- **"No MFA registered"** badge emitted only when `registrationData.available === true` and `isMfaRegistered === false`.
- **"Inactive >90 days"** badge emitted only when `signInActivity.available === true` and the effective last sign-in is older than 90 days.
- **`isStale`** is `null` (never `true`) when sign-in activity is unavailable — null never drives a negative classification.

The effective last sign-in is `MAX(lastSuccessfulSignInDateTime, lastSignInDateTime, lastNonInteractiveSignInDateTime)` because `lastSuccessfulSignInDateTime` is only backfilled from December 2023 per the [signInActivity resource documentation](https://learn.microsoft.com/en-us/graph/api/resources/signinactivity).

#### Readiness Score formula

On tenants with more than 50 users, the score is computed from the first 50 users returned by Graph and is labelled as a sample score in the overview hero.

```
score = 100
score -= (blocked  / effective) * 35    // weighted penalty for blocked users
score -= (needsPrep / effective) * 12   // penalty for users needing prep
score -= (capable  / effective) * 3     // small penalty for capable (not yet enrolled)
score -= 20   if FIDO2 policy is not enabled
score -= 8    if TAP policy is not enabled
score -= min(critical_toxic_combos * 10, 15)
score -= min(critical_gaps * 8, 10)
score -= min(ca_blocking_policies * 4, 5)
score -= min(high_gaps * 2, 4)
score = clamp(score, 0, 100)

where: effective = total - exempt - unknown

When effective = 0 (all users are exempt or have unknown registration status)
or total = 0 (Graph returns no users at all), the function returns null and
the score ring renders '—' with verdict text 'No scorable users'. Both paths
prevent a misleading numeric score when no classifiable users exist.
```

#### Score penalty calibration

User-tier coefficients (`35` / `12` / `3`) and infrastructure direct penalties (`20` / `8`) are explained in source comments. The remaining constants:

| Stream | Per-unit | Cap | Rationale |
|---|---|---|---|
| Critical toxic combos | ×10 | 15 | A privileged admin with no MFA is a high org-wide risk. Cap at 15 prevents two or more combos from dominating the composite signal. |
| Critical policy gaps | ×8 | 10 | Critical gaps affect all users simultaneously. Cap treats "fundamentally broken in multiple ways" as a severity plateau — the third critical gap adds nothing. |
| Blocking CA policies | ×4 | 5 | A blocking policy is a correctable configuration fix. Cap reflects that a second blocking policy largely affects the same users as the first. |
| High-severity gaps | ×2 | 4 | Best-practice shortfalls, not critical failures. Cap treats two-or-more high gaps identically. |

**Double-counting (by design):** FIDO2 disabled contributes −20 directly (passkey enrollment impossible for all users) and adds `gap-fido2-disabled` as a critical gap (up to −8 more, shared with co-occurring critical gaps under the 10-point cap). TAP disabled contributes −8 directly and adds `gap-tap-disabled` as a high gap (up to −2 more). Both dual contributions are intentional — the cumulative effect ensures a completely disabled passkey infrastructure drives the score into the lower bands even when the user distribution is healthy.

#### App credential staleness thresholds

The `analyzeApp()` method classifies each `passwordCredential` into one of four states using an `else-if` chain — a credential can only be in one state at a time:

| State | Condition | Severity |
|---|---|---|
| `expired` | `endDateTime` is in the past | Critical |
| `expiring-soon` | `endDateTime` is within 30 days | Critical |
| `expiring` | `endDateTime` is 31–90 days away | High |
| `stale` | `startDateTime` is more than 365 days ago and `endDateTime` is more than 90 days away | Medium |

Credentials with no `endDateTime` are not flagged (Graph returns `null` for some legacy secrets — known limitation).

Certificate credentials (`keyCredentials`) follow the same `expired` / `expiring-soon` / `expiring` states but have no `stale` classification.

Date arithmetic uses `new Date(isoString)` which correctly parses ISO-8601 strings with UTC offsets. No division by zero is possible.

#### CA policy passkey-enforcement detection

`enrichPolicy()` classifies each CA policy by its role in the passkey deployment:

| Type | Trigger |
|---|---|
| `blocks-passkey` | Enabled; requires `password` as a grant control |
| `enforces-passkey` | Auth strength non-empty; every combination is phishing-resistant |
| `protects-registration` | Targets the `urn:user:registerSecurityInfo` user action |
| `legacy-block` | Targets Exchange ActiveSync + Other clients with a `block` grant |
| `risk-based` | Conditions include sign-in or user risk levels |
| `other` | Everything else |

A policy is classified as `enforces-passkey` when `authenticationStrength.allowedCombinations` is non-empty and **every** entry is in the phishing-resistant set `{fido2, windowsHelloForBusiness, x509CertificateMultiFactor}`.

**Why `every()` not `some()`:** The built-in Passwordless MFA strength lists `fido2`, `windowsHelloForBusiness`, `x509CertificateMultiFactor`, `microsoftAuthenticatorPush`, and `deviceBasedPush` as allowed combinations. Because `fido2` is present, a `some()` check incorrectly credits Passwordless MFA policies as phishing-resistant. The `every()` check rejects any strength that permits non-phishing-resistant methods alongside phishing-resistant ones.

**`isEnabled` excluded from `enforcesPasskey`:** The flag describes authentication requirements (configuration), not enforcement state. `detectPolicyGaps()` filters to the `enabled` subset independently — mixing state into the configuration flag creates entangled logic.

The `enforcesPasskey` flag feeds two gap checks in `detectPolicyGaps()`:
- `gap-enforce-phishing-resistant` (critical, −8): fires when no enabled policy has `enforcesPasskey = true` covering all users.
- `gap-privileged-roles` (high, −2): fires when no enabled `enforcesPasskey` policy targets directory roles (`p.includeRoles`).

### 3.5 `functions/ai/ask.js` — AI Assistant Pages Function

A Cloudflare Pages Function that provides the optional AI Assistant backend. It:

- Accepts `POST /ai/ask` with `{ question, results, history }`.
- Validates CORS (`ALLOWED_ORIGIN` env var), rate-limits by IP (20 req/min), and
  checks payload size (512 KB max).
- Applies prompt-injection, destructive-intent, and off-topic filters.
- Calls `@cf/meta/llama-3.1-8b-instruct` via the Workers AI binding.
- Falls back to a rule-based response if the AI binding is unavailable.
- Streams the response as Server-Sent Events (SSE).

**Microsoft Learn citation behavior**

The SYSTEM_PROMPT instructs the model to end relevant responses with 1 to 3 Microsoft
Learn reference links chosen from a fixed, curated list embedded in the prompt:

- A narrow single-topic question gets 1 URL; a multi-topic question gets 2 or 3.
- The model must not include any URL not in the list; invented or modified URLs are
  prohibited.
- URLs are formatted as `📖 Learn more: [Label](url) · [Label](url)`.

**URL list curation criteria**

All URLs in the list must satisfy:
1. Confirmed 200 response from `learn.microsoft.com` at the time of addition.
2. No `aka.ms` shortlinks (these can silently redirect to different destinations
   after the prompt is deployed).
3. No deprecated Azure AD content — only current Entra ID / Microsoft Entra
   documentation.

The URL list is maintained in the `## Documentation` section of the SYSTEM_PROMPT
constant in `functions/ai/ask.js`. Updates require a code commit and new deployment;
the model cannot modify or extend the list at runtime.

### 3.6 `infra/` — deployment templates

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
| **Stored XSS** | All dynamic content is HTML-escaped via `escapeHtml()` before DOM insertion |
| **Supply chain** | Open source (MIT); build verifiable from source; Trivy + Dependabot scanning |
| **Credential leak** | No service principal secret, no client secret, no API keys stored or transmitted |
| **AI prompt injection** | `functions/ai/ask.js` applies regex filters for injection, destructive, and off-topic inputs |
| **AI data exposure** | The AI endpoint receives only a non-identifying summary (counts + recommendation titles), never raw user data |
| **Analytics exposure** | Self-hosted Umami at `analytics.aboutcloud.io` counts anonymous page visits only; no scan results, UPNs, or Graph response data are passed to the script |

### 6.2 Required permissions (Microsoft Graph, delegated)

| Permission | Why it is needed |
|---|---|
| `User.Read` | Sign in and read the signed-in user's profile |
| `User.Read.All` | List all users in the tenant |
| `Device.Read.All` | List all devices and their OS versions |
| `Policy.Read.All` | Read Conditional Access policies and the authentication-methods policy |
| `Application.Read.All` | Read app registrations for the App Identities analysis |
| `AuditLog.Read.All` | Read sign-in activity (last sign-in time) |
| `Organization.Read.All` | Read the tenant display name and verified domains (used for account type classification) |

### 6.3 Data residency

```
Data at rest:    sessionStorage (browser, not persisted to disk)
Data in transit: HTTPS / TLS to the Microsoft Graph API
Data processing: Browser JavaScript (V8 engine)
Data deletion:   Tab close          → sessionStorage cleared
                 "Reset app" button → config + results cleared
                 Cleanup script     → App Registration deleted
```

> **AI Assistant note:** when the AI Assistant is enabled, a **non-identifying
> summary** (counts only, no names or UPNs) is sent to the configured AI endpoint.
> When the AI Assistant is **off** (the default), no data leaves the browser except
> Graph API calls. See the [Data Architecture](data-architecture.md) document for
> details.
