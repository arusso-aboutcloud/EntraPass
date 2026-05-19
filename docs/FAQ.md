# EntraPass — Frequently Asked Questions

> **Product:** EntraPass — Passkey Migration Assistant
> **Published by:** [Aboutcloud](https://aboutcloud.io)

---

## Table of contents

1. [General](#general)
2. [Privacy and Security](#privacy-and-security)
3. [Setup and App Registration](#setup-and-app-registration)
4. [Scan Results and Readiness Tiers](#scan-results-and-readiness-tiers)
5. [Readiness Score](#readiness-score)
6. [Passkey Technology](#passkey-technology)
7. [Troubleshooting](#troubleshooting)
8. [Commercial and Licensing](#commercial-and-licensing)

---

## General

### Is EntraPass a Microsoft product?

No. EntraPass is an **open-source community tool** built by
[Aboutcloud](https://aboutcloud.io) and licensed under MIT. It is not affiliated
with or endorsed by Microsoft.

### What does EntraPass actually do?

EntraPass scans your Microsoft Entra ID tenant and tells you, per user, how ready
your organization is for passkey (FIDO2) authentication. It identifies:

- Which users already have passkeys registered (Ready)
- Which users can self-register with no IT help (Capable)
- Which users need a device update or MFA setup (Needs Prep)
- Which users are blocked by a Conditional Access policy (Blocked)
- Which accounts should be excluded from passkey targets (Exempt — break-glass, guests, MSA)

It also audits CA policies, app identities, and generates a prioritized rollout plan.

### Does EntraPass make changes to my tenant?

**No.** EntraPass is **read-only**. It only reads data from Microsoft Graph — it
cannot create users, change policies, modify configurations, or register passkeys.

### How many users can it scan?

EntraPass fetches per-user detail (auth methods, sign-in activity, group membership)
for up to **50 users** in a single scan, for performance and API rate-limit reasons.
If your tenant has more than 50 users, the first 50 returned by the Graph API are
used. Use the filter pills and CSV export to work with the data.

### Does it work with any Entra ID tenant?

Yes — free, P1, P2, and any tenant size. Some analysis (e.g. Conditional Access
reviews) is more actionable on P1/P2 tenants, but the tool works on all tiers.

---

## Privacy and Security

### Where is my tenant data stored?

**In your browser only.** No tenant data is sent to any EntraPass server. The only
network calls EntraPass makes are to the Microsoft Graph API (to read your tenant
data) and, optionally, to an AI endpoint if you explicitly enable the AI Assistant.

Technical detail: data is held in browser memory during the scan and written to
`sessionStorage` when the scan completes. `sessionStorage` is cleared automatically
when you close the browser tab.

### Does EntraPass send data to Aboutcloud?

Scan content does not. Self-hosted **Umami** at `analytics.aboutcloud.io` receives
anonymous page-visit signals only — URL visited, browser, OS, and IP-derived country.
It never receives scan content, UPNs, tenant IDs, Microsoft Graph responses, or AI
chat text. There is no EntraPass backend that stores tenant data. See the
[Data Architecture](data-architecture.md) document for a precise inventory.

### Is EntraPass safe to use in a production tenant?

Yes. EntraPass is read-only and requires only delegated permissions (it acts on behalf
of the signed-in user). Review the code yourself at
[github.com/arusso-aboutcloud/EntraPass](https://github.com/arusso-aboutcloud/EntraPass)
— we encourage it. We also recommend testing in a dev or staging tenant first if you
want to be thorough.

### What permissions does EntraPass require?

Seven read-only delegated Microsoft Graph permissions:

| Permission | Why |
|---|---|
| `User.Read` | Sign in and read the signed-in user's profile |
| `User.Read.All` | List all users in the tenant |
| `Device.Read.All` | List all devices and their OS versions |
| `Policy.Read.All` | Read Conditional Access and authentication-method policies |
| `Application.Read.All` | Read app registrations for the App Identities analysis |
| `AuditLog.Read.All` | Read sign-in activity (last sign-in time) |
| `Organization.Read.All` | Read the tenant display name and verified domains |

All permissions require admin consent — no permission is granted silently.

### Why do I need to create my own App Registration?

By creating the App Registration **in your own tenant**, you retain full control:

| Aspect | Your own App Registration | Shared third-party app |
|---|---|---|
| **Control** | You own it; delete it anytime | A third party controls it |
| **Audit** | Full audit trail in your tenant | No visibility |
| **Permissions** | You review and grant consent | Pre-consented by the vendor |
| **Lifecycle** | You control creation and deletion | Persistent until vendor removes it |

There is no shared "EntraPass app" that connects to your tenant — the App
Registration is created by you, for you, in your tenant.

---

## Setup and App Registration

### How do I create the App Registration?

The setup wizard offers three options:

1. **Azure Portal blade** (recommended) — the wizard links directly to the registration
   blade; you add 7 permissions and grant admin consent.
2. **Azure Cloud Shell script** — a one-line command creates the app and all permissions:
   ```powershell
   irm https://raw.githubusercontent.com/arusso-aboutcloud/EntraPass/main/infra/deploy-entrapass.ps1 | iex
   ```
3. **Manual PowerShell** — for advanced users who want full step-by-step control.

See the [Installation Guide](installation.md) for detailed instructions for each option.

### What redirect URI do I need?

The redirect URI must exactly match the URL you are using to access EntraPass. If
you use the hosted version, set it to `https://entrapass.aboutcloud.io`. If you
self-host, use your own URL. The App Registration type must be **Single-page
application (SPA)**.

### Can I skip the setup wizard?

Yes, when self-hosting. Set `VITE_CLIENT_ID` and `VITE_TENANT_ID` as build-time
environment variables. The wizard is skipped and the app goes straight to sign-in.
You still need an App Registration in your tenant.

### How do I clean up after scanning?

Run the cleanup script to remove the App Registration:

```powershell
.\infra\cleanup-entrapass.ps1 -ClientId "<your-client-id>" -RevokeConsent
```

Or simply click **Reset app** in the dashboard header to clear browser data without
deleting the App Registration (useful if you plan to scan again).

---

## Scan Results and Readiness Tiers

### What are the five readiness tiers?

| Tier | Criteria | What to do |
|---|---|---|
| **Ready** | FIDO2 passkey already registered | Start a pilot — this user can use passkeys now |
| **Capable** | Has MFA + a modern device, no CA blocker | Self-registration ready — guide user to register |
| **Needs Prep** | One gap: missing MFA, no modern device, or stale sign-in | Fix the single gap; user can become Capable |
| **Blocked** | Multiple gaps, or a CA policy actively blocking registration | Resolve the CA policy or address multiple blockers |
| **Exempt** | Break-glass, guest, or personal account | Do not target for passkeys — by design |

### Why are my break-glass accounts shown as Exempt?

Break-glass (emergency admin) accounts are deliberately excluded from passkey targets.
They typically have no MFA by design (to ensure emergency access even if the
authentication infrastructure is down), and pushing them through passkey enrollment
would be counterproductive and potentially dangerous.

EntraPass detects break-glass accounts by name patterns (common patterns like
"breakglass", "emergency", "bga") and excludes them from the readiness metrics.

### Why are my guests shown as Exempt?

Guest accounts (`#ext#` in the UPN or `userType = Guest`) and personal accounts
(consumer email domains: outlook.com, gmail.com, icloud.com, proton.me, and others)
are excluded from passkey targets because:

- Guest passkey support depends on the **home tenant**, not your tenant.
- Personal accounts are governed by an external identity provider and cannot be managed through your Entra ID policies.

### Why does a user appear twice?

EntraPass never deduplicates by display name. A user with the same display name but
different UPNs (e.g. `user@company.io` and `user@outlook.com`) is correctly treated
as two separate accounts — because they are. The UPN is always shown prominently on
each user card.

### What does "stale sign-in (>90 days)" mean?

This flag appears when a user has not signed in within the last 90 days. Stale
accounts are flagged because enrolling passkeys for users who are no longer active
may not be worthwhile, and they may indicate accounts that should be reviewed or
disabled.

### What does the recommended action for each user mean?

Each user card shows one specific recommended next step:

- **Register your passkey** — user is ready, no blockers; just needs to enroll.
- **Self-register a passkey** — user is capable; direct them to aka.ms/mfasetup.
- **Register an MFA method first** — user needs an authenticator before passkeys.
- **Update your device OS** — OS version is too old for passkeys.
- **Register a modern device** — no compatible device registered yet.
- **Review CA policy** — a specific CA policy is blocking registration.

### Which CA policy configurations does EntraPass count as "enforcing passkeys"?

EntraPass credits a CA policy as enforcing passkeys only when **every** entry in its
`authenticationStrength.allowedCombinations` list is phishing-resistant:

| Phishing-resistant | Not phishing-resistant |
|---|---|
| `fido2` | `microsoftAuthenticatorPush` |
| `windowsHelloForBusiness` | `deviceBasedPush` |
| `x509CertificateMultiFactor` | `sms`, `voice`, `softwareOath`, … |

The built-in **Passwordless MFA** strength includes `deviceBasedPush` and
`microsoftAuthenticatorPush` alongside the phishing-resistant methods. Because those
non-phishing-resistant combinations are present, a Passwordless MFA policy does not
qualify — only the built-in **Phishing-resistant MFA** strength (or a custom strength
containing exclusively phishing-resistant combinations) is credited.

This classification feeds two score signals:

- A critical gap (−8) is raised if no enabled policy enforces phishing-resistant auth
  for all users.
- A high gap (−2) is raised if no enabled phishing-resistant policy targets privileged
  directory roles.

---

## Readiness Score

### How is the score calculated?

The readiness score (0–100) is derived from the actual user breakdown and
infrastructure state:

1. Start at 100.
2. Subtract penalties for blocked users (up to −35 points, scaled by proportion).
3. Subtract penalties for needsPrep users (up to −12 points, scaled).
4. Subtract a small penalty for capable users (up to −3 points, scaled).
5. Subtract −20 if the FIDO2 authentication method policy is disabled.
6. Subtract −8 if Temporary Access Pass (TAP) policy is disabled.
7. Subtract up to −15 for critical toxic combinations.
8. Subtract up to −10 for critical policy gaps.
9. Subtract up to −5 for CA policies blocking passkey registration.
10. Subtract up to −4 for high-severity policy gaps.
11. Clamp to [0, 100].

When no scorable users exist (all scanned users are exempt or have unknown registration status), the formula returns no score. The ring displays '—' and the verdict reads 'No scorable users'.

### What does the score mean in practice?

| Score | Reading |
|---|---|
| **85–100** | Very strong. Most users are Ready or Capable; infrastructure is healthy. |
| **65–84** | Good progress. Some users need attention; minor infrastructure gaps. |
| **40–64** | Needs work. Significant portion blocked or unprepped; review policies. |
| **0–39** | Significant gaps. FIDO2 likely disabled; many blocked users. |

The score reflects your **current** state — not a commitment or a grade. Re-scan
after you make changes to see your progress.

### Why did my score change between scans?

The score is computed live from each scan's results. Changes can result from:
- Users registering MFA or passkeys between scans.
- Policy changes (enabling FIDO2, updating CA policies).
- Device enrollments.
- Different users returned by the Graph API (if you have many users).

### Why did my score drop on a re-scan when nothing in my tenant changed?

The score formula is computed live on each scan from data read directly from the
Microsoft Graph API. Detection improvements landed in EntraPass change how that
data is interpreted — which can change the gap and policy signals fed into the
formula.

**CA policy passkey-enforcement detection**

The previous detector credited a CA policy as "enforcing passkeys" if any of its
allowed authentication combinations included FIDO2 — including built-in Passwordless
MFA strength, which also permits `microsoftAuthenticatorPush` and `deviceBasedPush`.
These are strong credentials but not phishing-resistant.

The corrected detector requires every allowed combination to be phishing-resistant
(`fido2`, `windowsHelloForBusiness`, or `x509CertificateMultiFactor`). If your
tenant has a CA policy using Passwordless MFA strength that was previously credited,
the corrected reading adds:

- −8 for `gap-enforce-phishing-resistant` (critical — no policy forces phishing-resistant auth for all users)
- −2 for `gap-privileged-roles` (high — no phishing-resistant policy covers privileged roles)

Maximum score reduction from this fix: **−10 points.**

**Privileged user detection**

The earlier rule identified privileged users by display-name pattern matching on
group membership. The corrected detector uses the `@odata.type` discriminator in
`/memberOf` responses as its primary signal, which reliably distinguishes directory
roles from groups. If newly-detected privileged users have no MFA registered, each
such account adds a critical toxic-combo penalty (−10 per occurrence, capped at
−15 across all critical combos).

A score decrease on a re-scan means a gap that existed in your tenant before is now
correctly detected — not that your tenant got worse. Re-scan after addressing each
gap to track your real progress.

---

## Passkey Technology

### What is a passkey?

A passkey is a phishing-resistant, passwordless credential based on the FIDO2 / WebAuthn
standard. Instead of a password, the user authenticates with a biometric (fingerprint,
face) or a hardware security key. Passkeys cannot be phished because the credential
is tied to the specific website origin.

### What devices support passkeys?

- **Windows 10+** (Windows Hello)
- **iOS 16+** (iCloud Keychain passkeys)
- **Android 14+** (Google Password Manager passkeys)
- **macOS 13+** (Safari, Chrome, Edge with Touch ID or hardware key)

FIDO2 hardware security keys (YubiKey, etc.) work on any modern OS.

### What is the difference between a FIDO2 security key and a passkey in Microsoft Authenticator?

Both are FIDO2 credentials and both work with Entra ID. The difference is storage:

- **Hardware security key** — the private key lives on the physical key device (e.g. YubiKey).
- **Microsoft Authenticator passkey** — the private key lives in Microsoft Authenticator on
  the user's phone, synchronized across their devices.

Both are phishing-resistant. Hardware keys offer the highest assurance; Authenticator
passkeys are more convenient for most users.

### What is Temporary Access Pass (TAP)?

TAP is a time-limited, multi-use passcode issued by an admin that allows a user to
sign in and bootstrap their first strong authentication method — including registering
a passkey. EntraPass checks whether TAP is enabled because it is the recommended
onboarding mechanism for passkey registration at scale.

---

## Troubleshooting

### Sign-in fails immediately

1. Check that your Client ID and Tenant ID GUIDs are correct.
2. Check that the redirect URI in the App Registration matches the URL you are using.
3. Ensure the App Registration type is **Single-page application (SPA)**, not "Web".

### Scan returns no users / permissions error

1. In the Azure Portal, go to **App registrations → API permissions**.
2. Confirm all 7 Graph permissions are listed.
3. Click **Grant admin consent** if the status shows a pending (yellow) icon.

### Some users are missing from the scan

EntraPass analyzes per-user detail for the first 50 users returned by the Graph API
(`GET /users?$top=999`). If a specific user is not appearing, they may have been
outside the first 50 results. This limit is a performance optimization.

### How does the AI Assistant decide which Microsoft documentation to link to?

The AI Assistant ends relevant responses with 1 to 3 `learn.microsoft.com` links
chosen from a fixed list of 22 curated URLs embedded in the system prompt. Selection
is based on which topics the question touches — a narrow single-topic question gets
1 link; a question spanning CA policies, authentication strengths, and passkey
enrollment gets 2 or 3.

Every URL in the list was verified to return a `200` response from
`learn.microsoft.com` before it was added. The list contains no `aka.ms` shortlinks
(those can silently change destinations) and no deprecated Azure AD content. The
model cannot invent or modify URLs — it can only choose from the fixed list. The
list itself lives in the `functions/ai/ask.js` source file and can only be updated
via a repository commit.

### AI Assistant is not responding

- In **Cloudflare Free AI** mode: the free tier has a daily usage limit. Switch to
  **Bring Your Own Key** mode and enter your own API key for uninterrupted access.
- In **BYOK** mode: check your API key and endpoint URL are correct.
- The AI works even without scan results — you can ask general passkey questions.

### The score shows 50 after a fresh install

A score of 50 is the default when no scan data is present. Run a scan to get a
real score.

---

## Commercial and Licensing

### What is the license?

EntraPass is licensed under the **MIT License**. You are free to use, modify, fork,
and distribute it for personal and non-commercial purposes.

### Can I use EntraPass commercially?

EntraPass is MIT-licensed and broadly permissive. However, if you plan to incorporate
it into a **commercial product, paid service, or consulting engagement**, we kindly
ask that you reach out to us first. See the [LICENSE](../LICENSE) file for the full
note and contact details.

### Can I self-host EntraPass?

Yes. Clone the repository, run `npm install && npm run build`, and deploy the `dist/`
folder to any static web host (Cloudflare Pages, Azure Static Web Apps, GitHub Pages,
S3, etc.). See the [Installation Guide](installation.md) for full instructions.

### Can I contribute?

Absolutely. Contributions are very welcome. Please read
[CONTRIBUTING.md](../CONTRIBUTING.md) and open a Pull Request. Bug reports and
feature ideas are also welcome via
[GitHub Issues](https://github.com/arusso-aboutcloud/EntraPass/issues).
