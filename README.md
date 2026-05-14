# ?? EntraPass — Passkey Migration Assistant

> **Assess your Microsoft Entra ID tenant\'s readiness for passkey (FIDO2) authentication.**  
> Open source (MIT) &bull; Browser-only &bull; No data leaves your machine

[![Deploy to Cloudflare](https://img.shields.io/badge/Deployed-Cloudflare%20Pages-f38020?logo=cloudflare)](https://entrapass.pages.dev)
[![Security Scan](https://github.com/arusso-aboutcloud/EntraPass/actions/workflows/trivy-scan.yml/badge.svg)](https://github.com/arusso-aboutcloud/EntraPass/actions/workflows/trivy-scan.yml)
[![CodeQL](https://github.com/arusso-aboutcloud/EntraPass/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/arusso-aboutcloud/EntraPass/security/code-scanning)
[![Dependabot](https://img.shields.io/badge/dependabot-enabled-025e8c?logo=dependabot)](https://github.com/arusso-aboutcloud/EntraPass/security/dependabot)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

---

## ?? Features

| Feature | Description |
|---|---|
| **?? User Readiness Scan** | Analyzes users, devices, and auth methods to determine passkey readiness |
| **?? Device Compatibility** | Checks OS versions (Windows 10+, iOS 16+, Android 14+, macOS 13+) |
| **?? CA Policy Advisor** | Identifies policies blocking passkey registration |
| **?? Toxic Combination Detector** | Flags privileged users without MFA/passkey |
| **?? Entra Tip: App Check** | Bonus analysis of app compatibility including substrate apps |
| **?? AI Assistant** | Optional AI chat (Cloudflare or BYOK) to analyze results |
| **?? Executive Summary** | Prioritized recommendations + rollout plan |
| **?? Security First** | PKCE auth, your own app reg, browser-only data |

### What it does NOT do

- ? **No account takeovers** — read-only Microsoft Graph access
- ? **No data storage** — everything stays in your browser\'s sessionStorage
- ? **No telemetry** — no analytics, no cookies, no tracking
- ? **No server** — zero backend, just static files on CDN

---

## ?? Architecture

![Architecture Diagram](docs/diagrams/architecture.svg)

### High-Level Flow

```
User's Browser (SPA)                    Microsoft Graph API
+---------------------+                 +-------------------+
|  Setup Wizard        |                 |  Users            |
|  -> T&C + Config     |                 |  Devices          |
|  -> MSAL PKCE Auth   |--- Bearer ---->|  CA Policies      |
|  -> GraphAPI Client  |    Token       |  Apps             |
|  -> Analysis Engine  |<-- JSON -------|  Auth Methods     |
|  -> Dashboard UI     |                 |  Sign-in Logs     |
|  -> sessionStorage   |                 |  Org Info         |
+---------------------+                 +-------------------+
```

See the full [Architecture Document](docs/architecture.md) and [Data Architecture](docs/data-architecture.md) for details.

---

## ? Quick Start

### 1. Open the Portal

Go to **[entrapass.pages.dev](https://entrapass.pages.dev)** (or your self-hosted URL).

### 2. Accept Terms & Conditions

Read and acknowledge the T&C — this is required before proceeding.

### 3. Deploy App Registration to YOUR Tenant

The scanner needs an App Registration in **your** Microsoft Entra ID tenant:

- **Recommended:** Click the **?? Deploy to Azure** button in the portal
- **CLI alternative:** `az deployment group create --template-file infra/app-registration.bicep`

This creates a **PKCE-only SPA** with 7 delegated Graph permissions. No client secrets.

### 4. Configure & Sign In

Enter your **Client ID** and **Tenant ID** from the deployment. Sign in with Microsoft.

### 5. Scan Your Tenant

Click **?? Scan Tenant Now** — all analysis happens in your browser.

### 6. Review & Act

| Tab | What to look for |
|---|---|
| **?? Overview** | Stats + recommendations + rollout plan |
| **? Readiness** | Per-user status and blockers |
| **?? Entra Tip: Apps** | App compatibility with descriptions & fixes |
| **?? Policies** | CA policies blocking passkeys |
| **?? AI Assistant** | Ask questions about your results |

### 7. Clean Up (Optional)

```powershell
.\infra\cleanup-entrapass.ps1 -ClientId "<your-client-id>" -RevokeConsent
```

---

## ?? Documentation

| Document | Description |
|---|---|
| [Architecture (HLD + LLD)](docs/architecture.md) | System architecture, components, flows |
| [Data Architecture](docs/data-architecture.md) | Data at each step, classification, lifecycle |
| [User Manual](docs/user-manual.md) | Full user guide with screenshots and workflows |
| [Installation Guide](docs/installation.md) | Self-hosting, local dev, verification checklist |

---

## ?? Trivy Security Scan Dashboard

The repository includes automated security scanning via **Trivy**:

| Scan Type | What it Checks | Frequency | Status |
|---|---|---|---|
| **Filesystem** | Vulns, secrets, misconfigurations | Every push | [![Security Scan](https://github.com/arusso-aboutcloud/EntraPass/actions/workflows/trivy-scan.yml/badge.svg)](https://github.com/arusso-aboutcloud/EntraPass/actions/workflows/trivy-scan.yml) |
| **NPM Dependencies** | CRITICAL & HIGH vulns only | Every push | Same workflow |
| **IaC (Dockerfile)** | Infrastructure misconfigs | Every push | When present |
| **CodeQL** | Code quality & security | Every push | [![CodeQL](https://github.com/arusso-aboutcloud/EntraPass/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/arusso-aboutcloud/EntraPass/security/code-scanning) |
| **Dependabot** | Supply chain vulns | Weekly (npm) + Monthly (GHA) | [View alerts](https://github.com/arusso-aboutcloud/EntraPass/security/dependabot) |

Results are uploaded to the **GitHub Security tab**:  
?? [github.com/arusso-aboutcloud/EntraPass/security/code-scanning](https://github.com/arusso-aboutcloud/EntraPass/security/code-scanning)

---

## ? Development

### Prerequisites

- **Node.js 18+**
- **npm 9+**
- **Azure CLI** (for Bicep deployment)
- **Modern browser** (Chrome, Edge, Firefox, Safari)

### Setup

```bash
# Clone
git clone https://github.com/arusso-aboutcloud/EntraPass.git
cd EntraPass

# Install dependencies
npm install

# Build
npm run build

# Dev server (with hot reload)
npm run dev
```

### Project Structure

```
src/
  index.html       # Entry point + setup wizard + dashboard UI
  main.js          # Application orchestration
  graph.js         # Microsoft Graph API client
  analyzer.js      # Business logic / analysis engine
  style.css        # UI styling

infra/
  app-registration.bicep   # Bicep template
  cleanup-entrapass.ps1    # Cleanup script

.github/workflows/
  deploy.yml               # Cloudflare Pages deployment
  trivy-scan.yml           # Security scanning

docs/
  architecture.md          # HLD + LLD
  data-architecture.md     # Data flow documentation
  installation.md          # Installation guide
  user-manual.md           # User manual
  diagrams/
    architecture.svg       # Architecture diagram
```

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `VITE_CLIENT_ID` | Optional | Client ID to skip setup wizard |
| `VITE_TENANT_ID` | Optional | Tenant ID to skip setup wizard |

If set, the setup wizard is bypassed and the app goes directly to sign-in.

---

## ?? Security

- **PKCE (S256)** — Authorization code flow with Proof Key for Code Exchange
- **No client secret** — SPA apps don\'t need one
- **Your own tenant** — App Registration deployed in YOUR tenant, not shared
- **Delegated permissions** — App acts on behalf of the signed-in user
- **Read-only scopes** — No write operations to Graph API
- **Browser-only data** — No servers, no databases, no analytics
- **No cookies** — sessionStorage only (cleared on tab close)
- **Open source** — Full transparency, verifiable build

### Required Permissions

| Permission | Type | Purpose |
|---|---|---|
| `User.Read` | Delegated | Sign in and read profile |
| `User.Read.All` | Delegated | List all users |
| `Device.Read.All` | Delegated | List all devices |
| `Policy.Read.All` | Delegated | Read CA policies |
| `Application.Read.All` | Delegated | Read app registrations |
| `AuditLog.Read.All` | Delegated | Read sign-in activity |
| `Organization.Read.All` | Delegated | Read tenant info |

---

## ?? License

MIT License — see [LICENSE](LICENSE) for details.

Copyright (c) 2026

---

## ?? Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## ?? Support

- **Issues**: [GitHub Issues](https://github.com/arusso-aboutcloud/EntraPass/issues)
- **Discussions**: [GitHub Discussions](https://github.com/arusso-aboutcloud/EntraPass/discussions)
- **Security**: Report vulnerabilities via GitHub Security Advisory

---

> *Built with ?? for the passkey community — because phishing-resistant authentication shouldn\'t be hard to adopt.*
