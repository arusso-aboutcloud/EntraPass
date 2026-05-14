# EntraPass — Session Handoff

> Working note for picking the project back up. **Not part of the product** —
> delete it (or keep it updated) once the open items are closed.
> Written 2026-05-15.

---

## 1. TL;DR — where things stand

- Repo: <https://github.com/arusso-aboutcloud/EntraPass> — **now public**.
- `main` is at **`f1c2197`** and pushed. Two workflows trigger on push to `main`:
  `deploy.yml` (Cloudflare Pages) and `security-scan.yml` (Trivy).
- This session did four things: (1) rewrote all docs, (2) ran a code + security
  review, (3) implemented **every** review fix, (4) fixed the broken Cloud Shell
  deploy script.
- **Biggest open risk:** the code/security fixes were **never built or run** —
  there is no Node toolchain on this machine. See open item #1.

---

## 2. Project context

| Thing | Value |
|---|---|
| What it is | Browser-only SPA (Vite + vanilla JS + MSAL) that scans a Microsoft Entra ID tenant for passkey (FIDO2) readiness. No backend. |
| Hosting | Cloudflare Pages — `https://entrapass.pages.dev`. Optional Cloudflare AI worker (`workers/ai.js`). |
| Local path | `c:\Users\russo\OneDrive\Aboutcloud\EntraPass` |
| Git identity (set locally) | `Antonio Russo <arusso@aboutcloud.io>` |
| Commit convention | End messages with `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>` |
| User's test tenant | Tenant ID `0b259eac-5a5e-4c47-bc9f-f29ed875b165`, account `arusso@aboutcloud.io` |

### Environment quirks (important for the next session)
- **No `node` / `npm` / `gh` on this machine** (Windows 11, PowerShell). The
  Bash tool works but `npm` is not on PATH. Builds must be run by the user or
  in CI.
- The repo had a **systematic corruption pattern** in committed files: stripped
  backticks (broke `workers/ai.js`), stripped `$` (broke `graph.js` OData
  queries), mojibake emoji (`??`) and literal `\'` in all markdown. Most was
  fixed this session — if you touch an untouched file, watch for it.

---

## 3. Change log (commits this session, oldest first)

| Commit | Summary |
|---|---|
| `d605c47` | docs: rewrite documentation as clean UTF-8; add LICENSE and CONTRIBUTING |
| `f4c16b9` | fix: code & security review remediation (all C/H/M/L items) |
| `467f15b` | Merge branch 'fix/code-security-review' |
| `690cc68` | fix: make Cloud Shell deploy script reliable and frictionless |
| `f1c2197` | Merge branch 'fix/deploy-script' (current `main` HEAD) |

Local branches `fix/code-security-review` and `fix/deploy-script` are merged
but not deleted; they were never pushed (only `main` was). Safe to delete.

---

## 4. What was done — detail

### 4a. Documentation (`d605c47`)
- Rewrote `README.md` + `docs/{architecture,data-architecture,installation,user-manual}.md`
  as clean UTF-8 (were Windows-1252 mojibake).
- Fixed broken Security Scan badge (`trivy-scan.yml` → `security-scan.yml`).
- Replaced stale/broken Bicep deploy instructions with the 3 real methods.
- Corrected documented project structure (`index.html` at root, added `workers/`).
- Added `LICENSE` (MIT) and `CONTRIBUTING.md` — referenced by README but missing.
- Added `.claude/` to `.gitignore`.

### 4b. Code & security review remediation (`f4c16b9`)
All findings from the review were implemented. Severity → fix → file:

| ID | Fix | File(s) |
|---|---|---|
| **C1** | XSS: added `escapeHtml()`, applied to every `innerHTML` sink (Graph display names, AI output, user chat input) | `src/main.js` |
| **C2** | Reconstructed the **missing** `initializeApp()` / `showDashboard()` wiring; instantiate `graphApi` + `analyzer`, call `setActiveAccount()` | `src/main.js` |
| **H1** | Fixed malformed Graph OData queries (`$select`/`$top`), added `@odata.nextLink` paging (`fetchAll`), corrected `signInActivity` retrieval, interactive token fallback | `src/graph.js` |
| **H2** | Restored stripped template literals so the worker parses | `workers/ai.js` |
| **H3** | Deploy only on push to `main`, not on PRs | `.github/workflows/deploy.yml` |
| **M1** | `hasMfa` now counts only strong (MFA-grade) methods, not password | `src/analyzer.js` |
| **M2** | Inline `onclick`/`onchange` → `addEventListener` (`setupEventListeners()`); added CSP + hardening headers | `index.html`, `src/main.js`, `public/_headers` |
| **M3** | Per-source fetch-error tracking + "partial results / sampled" banner | `src/main.js`, `index.html`, `src/style.css` |
| **M4** | AI worker: origin allowlist (`ALLOWED_ORIGIN`), body-size cap, summary-only payload | `workers/ai.js`, `wrangler.toml` |
| **L1** | Invalid `\U` unicode escapes → `\u{...}` | `src/analyzer.js` |
| **L2** | Fixed newline/bold regex in AI answer formatting | `src/main.js` |
| **L4** | Detect Microsoft-managed apps via first-party tenant IDs | `src/analyzer.js` |
| **L5** | Stop leaking raw Graph error bodies to the UI | `src/graph.js` |
| **L6** | Security scan fails CI on fixable CRITICAL deps | `.github/workflows/security-scan.yml` |
| **L7** | Default redirect URI to `window.location.origin` | `index.html`, `src/main.js` |

### 4c. Deploy script fix (`690cc68`)
The shipped `infra/deploy-entrapass.ps1` was broken: it installed only
`Microsoft.Graph.Authentication`, so `New-MgApplication` (in
`Microsoft.Graph.Applications`) failed with an **assembly version conflict** —
the app registration was never created, yet the script printed a false
"created!" with a blank Client ID. Rewrote it:
- Install/import `Microsoft.Graph.Applications` (pulls a version-matched
  `Authentication`); **import before connecting**; detect the
  "assembly already loaded" conflict and tell the user to use a fresh session.
- `$ErrorActionPreference = Stop`, wrapped in a function.
- Portal URL **defaults to `https://entrapass.pages.dev`** (press Enter).
- **Idempotent** find-or-create; ensures redirect URI present.
- Creates the service principal and **grants admin consent automatically**.
- Prints the real Client ID / Tenant ID.

Also cleaned mojibake + added the module guard to `infra/cleanup-entrapass.ps1`,
and updated `docs/installation.md`, `docs/user-manual.md`, `index.html` to match.

---

## 5. Deploy troubleshooting recap (resolved)

The user hit a chain of issues deploying the scanner app registration:
1. **404** on `raw.githubusercontent.com` → repo was **private**. User made it
   public. Resolved.
2. **AADSTS50011 redirect URI mismatch** → user had pasted Microsoft's Graph
   PowerShell client ID (`14d82eec-204b-4c2f-b7e8-296a70dab67e`, from
   `Get-MgContext`) into EntraPass instead of their own app's Client ID.
3. Real root cause → the deploy script's module bug (see 4c). Fixed.

**Reminder for the user:** `14d82eec-204b-4c2f-b7e8-296a70dab67e` is *not* their
app — it's "Microsoft Graph Command Line Tools". The real Client ID comes from
the `entrapass-scanner` app registration.

---

## 6. Open items / next steps (in priority order)

1. **Verify the build.** `npm install && npm run build` was never run (no Node
   toolchain here). The big `src/main.js` rewrite and the **C2 reconstruction**
   are unverified. Check the latest run at
   <https://github.com/arusso-aboutcloud/EntraPass/actions>. If the build step
   is red, the Cloudflare deploy did **not** happen (build precedes deploy in
   the same job — a natural safety net).
2. **C2 caveat:** `initializeApp()` / `showDashboard()` were **reconstructed
   from intent** because the repo's `main.js` was truncated/corrupted. Confirm
   they match real runtime behavior (sign-in → dashboard → scan).
3. **Re-test the Cloud Shell deploy** with the fixed script — in **Azure Cloud
   Shell** (`https://shell.azure.com`), *not* local PowerShell (that caused the
   module conflict):
   ```powershell
   irm https://raw.githubusercontent.com/arusso-aboutcloud/EntraPass/main/infra/deploy-entrapass.ps1 | iex
   ```
   Press Enter at the prompt. Expect a clean summary with a real Client ID and
   "Admin consent granted".
4. **Smoke-test the live app** after deploy: EntraPass → **Reset app** → enter
   the real Client ID + Tenant ID → sign in → scan. Watch the browser console
   for **CSP violations** from `public/_headers` — if sign-in breaks, the likely
   culprit is `connect-src` / `frame-src` for MSAL (`login.microsoftonline.com`).
5. **AI worker:** for "Cloudflare AI" mode to work, the deployed worker needs
   the `ALLOWED_ORIGIN` env var. It's in `wrangler.toml [vars]`, but the worker
   deploy step in `deploy.yml` is commented out — it's deployed manually.
6. **Dependabot:** 3 moderate vulns on `main` (pre-existing, unrelated to this
   work). Clear at <https://github.com/arusso-aboutcloud/EntraPass/security/dependabot>.
7. Delete the merged local branches: `git branch -d fix/code-security-review fix/deploy-script`.

---

## 7. Key files changed this session

```
README.md                              docs rewrite
CONTRIBUTING.md                        new
LICENSE                                new
.gitignore                             + .claude/
docs/architecture.md                   docs rewrite
docs/data-architecture.md              docs rewrite
docs/installation.md                   docs rewrite + deploy-script updates
docs/user-manual.md                    docs rewrite + deploy-script updates
index.html                             inline handlers removed, IDs added, L7
src/main.js                            C1, C2, M2, M3, L2, L7  (largest change)
src/graph.js                           H1, L5
src/analyzer.js                        M1, L1, L4
src/style.css                          M2/M3 styles (.notice, .recommendation.critical)
workers/ai.js                          H2, M4
wrangler.toml                          + ALLOWED_ORIGIN var
public/_headers                        new — CSP + security headers (M2)
.github/workflows/deploy.yml           H3
.github/workflows/security-scan.yml    L6
infra/deploy-entrapass.ps1             rewritten — module fix, idempotent, auto-consent
infra/cleanup-entrapass.ps1            mojibake cleaned, module guard
```
