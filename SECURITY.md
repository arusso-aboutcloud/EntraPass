# Security Policy

## Supported Versions

EntraPass is a browser-only SPA deployed continuously to Cloudflare Pages.
There are no long-lived release branches — users always receive the latest
deployed version automatically. Security fixes are applied to `main` and
promoted to production within one business day.

| Version | Status |
|---------|--------|
| Latest deployed (`main`) | Supported |
| Any pinned or self-hosted fork | Not supported |

If you are self-hosting EntraPass, keep your fork in sync with `main` to
receive security fixes.

---

## Reporting a Vulnerability

**Please do not open a public GitHub Issue for security vulnerabilities.**

Report privately via
[GitHub Security Advisories](https://github.com/arusso-aboutcloud/EntraPass/security/advisories/new).
This lets us triage and patch before public disclosure.

Include as much of the following as possible:

- A clear description of the vulnerability and its impact
- Steps to reproduce (or a proof-of-concept)
- The browser, OS, and EntraPass version (URL + date is sufficient)
- Any relevant network traces or screenshots (redact tenant data)

### Response timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgement | Within 48 hours |
| Initial triage and severity assessment | Within 5 business days |
| Fix or mitigation in `main` | Dependent on severity (see below) |
| CVE / public disclosure | Coordinated with the reporter |

| Severity | Fix target |
|----------|------------|
| Critical (data exfiltration, token theft, auth bypass) | Within 24–48 hours |
| High (XSS, CSP bypass, credential leak) | Within 7 days |
| Medium (information disclosure, CORS misconfiguration) | Within 30 days |
| Low (hardening improvements, minor info leaks) | Next regular release |

We will keep you informed at each milestone. If a reported vulnerability is
declined we will explain why. Credit is given in the release notes unless
you prefer to remain anonymous.

---

## Security Architecture

Understanding the architecture helps scope valid reports.

### What EntraPass does

- Runs entirely in the **user's browser** — no server-side processing of tenant data
- Authenticates via **PKCE** (no client secret, no implicit flow)
- Makes **read-only** Microsoft Graph API calls using a delegated access token
- Stores state in **`sessionStorage`** only (cleared when the tab closes)
- Optionally sends a **count-only summary** to Cloudflare Workers AI (AI Assistant tab, off by default, no UPNs or user names)

### What EntraPass does not do

- Transmit, log, or persist any tenant data to Aboutcloud servers
- Store credentials, tokens, or tenant data beyond the browser session
- Use a backend API that holds tenant information
- Request write permissions to Microsoft Graph

### Trust boundaries

| Boundary | Notes |
|----------|-------|
| Browser ↔ Microsoft Graph API | TLS; bearer token issued by the user's own Entra ID tenant |
| Browser ↔ Cloudflare Pages | TLS; Cloudflare WAF + security headers enforced |
| Browser ↔ Cloudflare Workers AI | TLS; opt-in; count-only payload; rate-limited; CORS-restricted |
| GitHub Actions | Trivy filesystem scan + Dependabot on every push |

---

## AI Assistant Guardrails

The optional AI Assistant (`functions/ai/ask.js`) enforces the following controls to
prevent misuse and information leakage:

**No-invented-URLs rule (security control)**
The SYSTEM_PROMPT contains a fixed list of 22 verified `learn.microsoft.com` URLs.
The model is instructed that it must not include any URL not in that list and must
never invent or modify URLs. This prevents the model from hallucinating plausible-looking
but incorrect or malicious links that could be presented as official Microsoft
documentation.

Enforcement:
- Only `learn.microsoft.com` canonical URLs are permitted (no `aka.ms` shortlinks,
  which can silently redirect to different destinations after deployment).
- Every URL in the list was fetched and confirmed to return HTTP 200 with the
  expected Microsoft Learn page title before it was added to the list.
- The list is embedded in source code and can only be changed via a repository commit
  — the model cannot modify or extend it at runtime.

**Prompt injection and off-topic filters**
Requests containing prompt-injection patterns or destructive-intent keywords are
rejected before reaching the model.

**Payload size and rate limiting**
Requests larger than 512 KB or exceeding 20 requests per minute per IP are rejected.

**Count-only data policy**
When the AI Assistant is used in Cloudflare Free AI mode, only aggregate counts
(users by tier, app counts, policy counts) are included in the model context — no
UPNs, no display names, no tenant IDs, no credentials.

---

## In-Scope Vulnerabilities

The following are considered valid security reports:

- **XSS** — injecting arbitrary script into the dashboard from Graph API responses
- **CSP bypass** — circumventing the `Content-Security-Policy` header
- **Token exposure** — access tokens leaving `sessionStorage` or being sent to a third party
- **PKCE flow weaknesses** — state/nonce bypass, redirect URI manipulation
- **Data exfiltration** — tenant data sent to any host other than Microsoft Graph / Entra ID
- **AI payload leakage** — personally identifiable information included in the Workers AI request body
- **Supply chain** — malicious code introduced via an npm dependency
- **Cloudflare misconfiguration** — WAF rules or security headers that fail to block a known attack class
- **Sensitive data in source** — credentials, tokens, or operator-specific values committed to the public repository

---

## Out-of-Scope

The following are **not** considered valid reports for this project:

- Vulnerabilities in **Microsoft Graph API or Entra ID** itself — report those to [Microsoft MSRC](https://msrc.microsoft.com/report)
- Vulnerabilities in **Cloudflare's platform** — report those to [Cloudflare](https://www.cloudflare.com/disclosure/)
- Missing security headers that are already set by the Cloudflare Response Header Transform (verify against a live request, not the static `public/_headers` file)
- Rate limiting of the Graph API — this is governed by Microsoft's throttling policy
- Self-XSS (requires the user to paste code into the browser console)
- Attacks that require physical access to the user's device
- Social engineering of the user or the Aboutcloud team
- Scanner findings with no demonstrated impact (automated Nuclei/ZAP reports without a PoC)
- The fact that tenant data is visible in `sessionStorage` — this is by design and documented; the data is accessible only to the authenticated user in their own browser session

---

## Dependency Security

- **Dependabot** is enabled and opens PRs for outdated or vulnerable npm dependencies automatically.
- **Trivy** runs a filesystem vulnerability scan on every push and pull request (`.github/workflows/security-scan.yml`).
- Scan results are uploaded to GitHub Security → Code scanning alerts.

---

## Security Contact

For questions about this policy or the security model contact
[security@aboutcloud.io](mailto:security@aboutcloud.io) or open a
[private advisory](https://github.com/arusso-aboutcloud/EntraPass/security/advisories/new).
