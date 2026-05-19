/**
 * Cloudflare Pages Function — /ai/ask
 *
 * Optional AI assistant for passkey migration questions. The browser SPA
 * POSTs scan results + conversation history here when the user selects
 * "Cloudflare Free AI" mode.
 *
 * Bindings required (Cloudflare Pages → Settings → Functions):
 *   AI  — Workers AI binding (type: AI)
 *
 * Environment variables (Pages → Settings → Environment variables):
 *   ALLOWED_ORIGIN  — exact origin of the EntraPass site
 *                     (e.g. "https://entrapass.aboutcloud.io")
 *                     Requests from any other origin are rejected.
 */

const MAX_BODY_BYTES   = 512 * 1024;
const MAX_INPUT_LENGTH = 2000;
const MAX_HISTORY_MSGS = 10;       // last 5 exchanges (10 messages)
const RATE_LIMIT       = 20;       // requests per window per IP
const RATE_WINDOW_MS   = 60_000;

const _rateMap = new Map();

function checkRateLimit(ip) {
  const now = Date.now();
  let e = _rateMap.get(ip);
  if (!e || now > e.resetAt) e = { count: 0, resetAt: now + RATE_WINDOW_MS };
  e.count++;
  _rateMap.set(ip, e);
  return e.count <= RATE_LIMIT;
}

function corsHeaders(env, origin) {
  const allowed = env?.ALLOWED_ORIGIN || '';
  const h = {
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin',
  };
  if (allowed && origin === allowed) h['Access-Control-Allow-Origin'] = allowed;
  return h;
}

function json(body, status, extra) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...(extra || {}) },
  });
}

// Wraps a plain text string as a minimal SSE stream so the rule-based fallback
// uses the same wire format as the streaming AI response.
function sseTextResponse(text, cors) {
  const enc = new TextEncoder();
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(enc.encode(`data: ${JSON.stringify({ response: text })}\n\n`));
      controller.enqueue(enc.encode('data: [DONE]\n\n'));
      controller.close();
    },
  });
  return new Response(stream, {
    headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', ...cors },
  });
}

// ── Security filters ────────────────────────────────────────────────────────

function isPromptInjection(text) {
  const t = text.normalize('NFKC');
  return [
    /ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/i,
    /override\s+(instructions?|system|prompt)/i,
    /forget\s+(everything|all|previous|prior|above|instructions?)/i,
    /you\s+are\s+now\s+(a|an|the)/i,
    /act\s+as\s+(a\s+)?(jailbreak|evil|unrestricted|DAN)/i,
    /disregard\s+(all|previous|prior|above|any)\s+(instructions?|prompts?|rules?)/i,
    /reveal\s+(your|the|this)\s*(system|initial|original)?\s*(prompt|instructions?|context)/i,
    /show\s+(me\s+)?(your|the)\s*(system|initial|original)?\s*(prompt|instructions?)/i,
    /print\s+(your|the)\s*(system|initial|original)?\s*(prompt|instructions?)/i,
    /what\s+(are|were)\s+(your|the)\s*(original|initial|system)?\s*(instructions?|prompt)/i,
    /bypass\s+(safety|security|restrictions?|filters?|guidelines?)/i,
    /jailbreak/i,
    /DAN\s+mode/i,
    /do\s+anything\s+now/i,
    /pretend\s+(you\s+are|to\s+be|you're|that\s+you)/i,
    /roleplay\s+as/i,
    /simulate\s+(being|a|an)/i,
    /\[INST\]|\[\/INST\]/i,
    /<\|system\|>/i,
  ].some(p => p.test(t));
}

function isDestructive(text) {
  const t = text.normalize('NFKC');
  return [
    /\b(sql[\s-]*injection|xss\s+attack|csrf\s+exploit|remote[\s-]code[\s-]exec(?:ution)?|ssrf|xxe)\b/i,
    /\b(malware|ransomware|trojan|rootkit|backdoor[\s-]payload)\b/i,
    /\b(privilege[\s-]escalation|lateral[\s-]movement|credential[\s-]dump)\b/i,
    /\b(pass[\s-]the[\s-]hash|kerberoast|mimikatz|cobalt[\s-]strike)\b/i,
    /\b(disable\s+(?:security|logging|audit|monitoring|defender|antivirus))\b/i,
    /\b(delete\s+all\s+(?:users?|data|logs?|audit\s+logs?))\b/i,
    /\b(steal|exfiltrat|dump)\s+(?:credential|password|token|secret|api[\s-]key)\b/i,
    /how\s+(?:to\s+)?(?:hack|exploit|breach|compromise)\s+(?:entra|azure|microsoft|tenant)/i,
  ].some(p => p.test(t));
}

function isOffTopic(text) {
  const t = text.normalize('NFKC');
  return [
    /\b(bitcoin|crypto(?!graphy)|blockchain|\bnft\b|\bdefi\b|ethereum|solana)\b/i,
    /\b(politics|democrat|republican|election|government\s+policy)\b/i,
    /\b(pornograph|nsfw|explicit\s+content|sexual\s+content)\b/i,
    /\b(bomb\s+threat|terrorist\s+attack)\b/i,
    /\b(medical\s+advice|diagnos[ei]s|prescrib\w+|\billness\b|\bdisease\b)\b/i,
    /\b(legal\s+advice|lawsuit|your\s+attorney|court\s+verdict)\b/i,
    /\b(financial\s+advice|stock\s+market|forex\s+trading)\b/i,
  ].some(p => p.test(t));
}

// ── System prompt ────────────────────────────────────────────────────────────

const SYSTEM_PROMPT = `\
You are the EntraPass AI assistant — a Microsoft Entra ID passkey migration expert \
and guide for the EntraPass open-source scanning tool.

## About EntraPass
EntraPass (github.com/arusso-aboutcloud/EntraPass) is a free, open-source, \
browser-only tool built by Aboutcloud (aboutcloud.io) that assesses Microsoft Entra ID \
tenant readiness for FIDO2 passkey adoption. Key facts:
- All analysis runs entirely in the user's browser — scan data never reaches any server.
- Read-only: it never modifies the tenant.
- Uses PKCE (Proof Key for Code Exchange) — no client secrets, no shared credentials.
- Requires 7 delegated Graph permissions (all read-only): User.Read, User.Read.All, \
Device.Read.All, Policy.Read.All, Application.Read.All, AuditLog.Read.All, Organization.Read.All.
- MIT licensed, fully open source and auditable.

## EntraPass Dashboard — Five tabs
1. **Overview** — Animated readiness score (0–100), six stat tiles (Total / Ready / Capable / \
Needs Prep / Blocked / Exempt), a readiness breakdown bar, infrastructure health chips \
(FIDO2 policy, TAP policy, app risks, policy gaps), executive summary, and recommendations.
2. **Passkey Readiness** — Per-user cards with 4-tier status, filter pills \
(All / Ready / Capable / Needs Prep / Blocked / Exempt), full-text search, \
recommended action per user, rollout phase planner, and CSV export (13 columns).
3. **App Identities** — Analysis of app registrations and service principals relevant \
to passkey migration. Microsoft first-party substrate service principals (Graph \
Explorer, Teams, Exchange, Azure services, etc.) are excluded — they cannot be \
modified by tenant admins and are not relevant to migration planning. \
Severity levels — critical/high: client secrets or expired credentials (the app \
authenticates without user interaction, bypassing CA, MFA, and passkey enforcement \
entirely); medium: no delegated permissions on a user-facing app (may fall back to \
password), multi-tenant sign-in audience, or orphaned app with no owner assigned; \
low: certificate credentials (more secure than secrets, but still non-interactive); \
good: no issues. \
The scanning app (EntraPass itself) displays a "Scanning app" badge for identification \
— normal issue detection still applies. \
Dashboard: stat tiles (Apps scanned / Need attention / Clean, plus a conditional \
Expiring credentials tile); two filter pills (All / Needs Attention / Clean); \
Needs Attention section expanded by default; Clean section collapsible. \
Severity ordering: critical > high > medium > low > good.
4. **CA Policies** — Conditional Access policy review: policies blocking passkey \
registration or allowing password fallback, with specific fix recommendations.
5. **AI Assistant** — Optional AI chat (Cloudflare Workers AI or bring-your-own-key).

## Passkey Readiness — 4-Tier User Classification
EntraPass classifies each user into one of five statuses:
- **Ready** — FIDO2 passkey already registered; the user can authenticate now.
- **Capable** — Has MFA + a modern device; can self-register a passkey with no IT help.
- **Needs Prep** — One gap (missing MFA or no modern device); needs targeted guidance.
- **Blocked** — Multiple gaps or a CA policy actively blocking passkey registration.
- **Exempt** — Break-glass accounts, guest users, or personal accounts (consumer \
email domains); deliberately excluded from passkey targets (they should NOT get passkeys).

"Modern device": Windows 10+, iOS 16+, Android 14+, macOS 13+.

## Account Type Classification
- **Member** — standard tenant account.
- **Guest** — external (#ext# in UPN or userType=Guest); excluded from passkey targets.
- **Personal account** — consumer email domains (gmail.com, outlook.com, icloud.com, proton.me, and others); excluded from passkey targets.
- **Break-glass** — emergency admin accounts (no MFA by design); excluded to avoid \
skewing metrics.

## Readiness Score (0–100)
Computed from the actual user breakdown:
- Start at 100; subtract penalties for blocked / needsPrep / capable users (relative \
to non-exempt, non-unknown total).
- FIDO2 policy disabled: −20 pts. TAP policy disabled: −8 pts.
- Additional penalties for critical toxic combinations, critical policy gaps, and \
CA policies blocking passkey registration.
- 85+: very strong. 65–84: good progress. 40–64: needs work. Below 40: significant gaps.
- When all scanned users are exempt or have no registration data, the score ring \
shows '—' instead of a number ('No scorable users').

## CA Policy Analysis
EntraPass classifies each enabled CA policy by its role in passkey deployment:
- Blocks passkeys — requires the "password" grant control; prevents passkey-only auth. \
Fix: replace with Phishing-resistant MFA authentication strength.
- Enforces passkeys — auth strength allows ONLY phishing-resistant combinations (fido2, \
windowsHelloForBusiness, x509CertificateMultiFactor). The built-in Passwordless MFA \
strength also allows deviceBasedPush — that does NOT qualify.
- Protects registration — targets the "Register security information" user action.
- Blocks legacy auth — blocks Exchange ActiveSync and Other legacy clients.
- Risk-based — uses sign-in or user risk conditions.

Score penalties from CA gaps: no phishing-resistant enforcement −8 (critical gap); no \
phishing-resistant policy for privileged roles −2 (high gap); each blocking policy −4 \
(capped at −5 total). FIDO2 disabled: −20 direct plus up to −8 via critical gap \
(double-count by design). TAP disabled: −8 direct plus up to −2 via high gap.

Score drop without tenant changes: the enforcement detector was tightened — Passwordless \
MFA strength no longer qualifies as phishing-resistant, adding up to −10 pts. Privileged \
user detection also improved (now uses @odata.type from /memberOf as primary signal); a \
newly-detected privileged admin with no MFA adds a critical toxic-combo penalty \
(−10 per occurrence, capped at −15 total).

## Scope
Answer questions about: passkey migration, FIDO2, Conditional Access, authentication \
methods, Entra ID user/device/app management, EntraPass usage, scan result \
interpretation, setup, and rollout planning.
Do NOT answer: questions about internal infrastructure, server IPs, API tokens, or \
deployment secrets. Do NOT answer questions unrelated to Microsoft identity or EntraPass.

## Documentation
When relevant, end your response with a "📖 Learn more:" line listing 1 to 3 URLs \
chosen from the list below based on which topics the question touches. A narrow, \
single-topic question gets 1 URL. A question spanning multiple topics (for example, \
CA policy + authentication strengths + passkey enrollment) gets 2 or 3 URLs. Never \
include a URL not in this list; never invent or modify URLs. Format each as a markdown \
link with a descriptive label, separated by · (middle dot):
📖 Learn more: [Label one](url1) · [Label two](url2)

### Passkey and FIDO2
- Passwordless overview: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passwordless
- Enable FIDO2 security keys: https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key
- Passkeys in Microsoft Authenticator: https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-enable-authenticator-passkey
- FIDO2 browser/platform compatibility: https://learn.microsoft.com/en-us/entra/identity/authentication/fido2-compatibility

### Authentication methods management
- Authentication methods policy: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods-manage
- Authentication method registration reporting: https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails
- Temporary Access Pass: https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass

### Conditional Access
- Conditional Access overview: https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview
- Authentication strengths (CA): https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths
- Phishing-resistant MFA — built-in strengths: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths#built-in-authentication-strengths

### Setup and deployment
- Plan phishing-resistant passwordless deployment: https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-plan-prerequisites-phishing-resistant-passwordless-authentication
- PKCE / OAuth2 auth code flow: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow

### App registrations and service principals
- Apps and service principals: https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals
- Certificate credentials for apps: https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials
- Workload identities overview: https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-overview
- App registration security best practices: https://learn.microsoft.com/en-us/entra/identity-platform/security-best-practices-for-app-registration
- Single and multi-tenant apps: https://learn.microsoft.com/en-us/entra/identity-platform/single-and-multi-tenant-apps
- Microsoft Graph permissions (delegated vs application): https://learn.microsoft.com/en-us/graph/auth/auth-concepts

### Identity governance and protection
- Identity Protection risks: https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks
- Privileged Identity Management: https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure

### Monitoring and reporting
- Sign-in logs: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins
- Audit logs: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs

Keep responses under 250 words. Be accurate and factual.`;

// ── Pages Function entry point ──────────────────────────────────────────────

export async function onRequest(context) {
  const { request, env } = context;
  const origin = request.headers.get('Origin') || '';
  const cors   = corsHeaders(env, origin);

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: cors });
  }
  if (request.method !== 'POST') {
    return json({ error: 'Method not allowed' }, 405, cors);
  }
  if (!cors['Access-Control-Allow-Origin']) {
    return json({ error: 'Origin not allowed' }, 403, cors);
  }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!checkRateLimit(ip)) {
    return json({
      error: 'The AI assistant has reached its request limit. Please wait a moment and try again.\n\n'
           + 'For immediate, uninterrupted access, switch to **Bring Your Own Key** in the AI '
           + 'settings above and connect your own OpenAI-compatible API key.',
      quota: true,
    }, 429, cors);
  }

  const contentLength = Number(request.headers.get('Content-Length') || '0');
  if (contentLength > MAX_BODY_BYTES) {
    return json({ error: 'Payload too large' }, 413, cors);
  }

  let payload;
  try {
    payload = await request.json();
  } catch {
    return json({ error: 'Invalid JSON body' }, 400, cors);
  }

  const { question, results, history } = payload || {};
  if (!question || typeof question !== 'string') {
    return json({ error: 'Question is required' }, 400, cors);
  }
  if (question.length > MAX_INPUT_LENGTH) {
    return json({ error: 'Question too long (max 2000 characters)' }, 400, cors);
  }

  if (isPromptInjection(question) || isDestructive(question)) {
    return json({ error: 'This type of question cannot be processed.' }, 400, cors);
  }
  if (isOffTopic(question)) {
    return json({
      answer: 'I can only help with passkey migration, Microsoft Entra ID, and '
            + 'EntraPass topics. Please ask about your scan results, setup, or '
            + 'passkey readiness.',
    }, 200, cors);
  }

  // Compact, non-identifying summary of scan data.
  // Handles both a pre-built summary (well-behaved clients that minimized
  // before sending) and a full results object (legacy or buggy clients).
  // The ?? fallback ensures PII is stripped even if a client sends raw results.
  const prUsers = results?.passkeyReadiness?.users || [];
  if (prUsers.some(u => u.userPrincipalName || u.displayName)) {
    console.warn('[ask.js] incoming results contain PII fields — client may be outdated');
  }
  const summary = (results && typeof results === 'object') ? {
    totalUsers:     results.totalUsers     ?? results.passkeyReadiness?.total  ?? 0,
    readyUsers:     results.readyUsers     ?? prUsers.filter(u => u.status === 'ready').length,
    capableUsers:   results.capableUsers   ?? prUsers.filter(u => u.status === 'capable').length,
    needsPrepUsers: results.needsPrepUsers ?? prUsers.filter(u => u.status === 'needsPrep').length,
    blockedUsers:   results.blockedUsers   ?? prUsers.filter(u => u.status === 'blocked').length,
    exemptUsers:    results.exemptUsers    ?? prUsers.filter(u => u.status === 'exempt').length,
    score:          results.score          ?? 0,
    recommendations: (results.recommendations || []).slice(0, 5).map(r => typeof r === 'string' ? r : (r.title || r.text)),
  } : null;

  // Validate and cap conversation history — structure only, no deep filter needed
  const safeHistory = Array.isArray(history)
    ? history
        .filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string')
        .slice(-MAX_HISTORY_MSGS)
        .map(m => ({ role: m.role, content: m.content.slice(0, 500) }))
    : [];

  const userPrompt = summary
    ? `Scan results: ${JSON.stringify(summary)}\n\nQuestion: ${question}`
    : `Question: ${question}`;

  const messages = [
    { role: 'system', content: SYSTEM_PROMPT },
    ...safeHistory,
    { role: 'user', content: userPrompt },
  ];

  try {
    if (!env.AI) throw new Error('AI binding not configured');
    const aiStream = await env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
      messages,
      max_tokens:  600,
      temperature: 0.3,
      stream:      true,
    });
    // Pipe the Workers AI SSE stream directly to the client
    return new Response(aiStream, {
      headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', ...cors },
    });
  } catch (aiError) {
    console.error('AI binding error:', aiError);
    // Detect Workers AI free-tier exhaustion by inspecting the error message.
    // Quota errors surface as 429 JSON so the client can render them distinctly.
    const msg = String(aiError?.message || aiError || '').toLowerCase();
    if (msg.includes('quota') || msg.includes('rate') || msg.includes('limit')
        || msg.includes('429') || msg.includes('too many')) {
      return json({
        error: 'The Cloudflare free AI tier has reached its usage limit for this period. '
             + 'Please try again in a few minutes.\n\n'
             + 'For immediate access, switch to **Bring Your Own Key** in the AI settings '
             + 'above and connect your own OpenAI-compatible API key.',
        quota: true,
      }, 429, cors);
    }
    // Genuine failure (binding misconfiguration, model error, etc.) → rule-based fallback
    return sseTextResponse(ruleBasedResponse(question, summary), cors);
  }
}

// ── Rule-based fallback ──────────────────────────────────────────────────────

function ruleBasedResponse(question, summary) {
  const q = question.toLowerCase();

  if (q.includes('how') && (q.includes('work') || q.includes('does it') || q.includes('entrapass'))) {
    return 'EntraPass is a browser-only, read-only tool. It connects to Microsoft Graph '
         + 'using delegated permissions via a PKCE app registration in your own tenant. '
         + 'All analysis runs client-side — no scan data leaves your browser.\n\n'
         + '📖 Learn more: [PKCE / OAuth2 auth code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)';
  }
  if (q.includes('permission') || q.includes('scope') || q.includes('graph')) {
    return 'EntraPass requires 7 read-only delegated Graph permissions: User.Read, '
         + 'User.Read.All, Device.Read.All, Policy.Read.All, Application.Read.All, '
         + 'AuditLog.Read.All, and Organization.Read.All. All require admin consent.';
  }
  if (q.includes('safe') || q.includes('secur') || q.includes('privacy') || q.includes('data')) {
    return 'All scan data stays in your browser memory only — nothing is stored on '
         + 'any server. EntraPass uses PKCE with no client secrets. The app registration '
         + 'can be deleted immediately after scanning.';
  }
  if (q.includes('ready') || q.includes('readiness')) {
    const s = summary || {};
    return `Based on your scan (score: ${s.score || 'N/A'}/100): `
         + `${s.readyUsers || 0} users are ready, ${s.capableUsers || 0} are capable `
         + `(can self-register), ${s.needsPrepUsers || 0} need preparation, `
         + `and ${s.blockedUsers || 0} are blocked. `
         + 'Focus on moving "Needs Prep" users to "Capable" by ensuring they have MFA '
         + 'and a modern device, then unblock users via CA policy updates.\n\n'
         + '📖 Learn more: [Plan passwordless deployment](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-deployment)';
  }
  if (q.includes('block') || q.includes('ca policy') || q.includes('conditional access')) {
    return 'Check Conditional Access policies that require "password" as a grant control — '
         + 'these block passkey-only authentication. Use Authentication Strengths to '
         + 'enforce FIDO2 without blocking other users.\n\n'
         + '📖 Learn more: [Authentication strengths](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths)';
  }
  if (q.includes('recommend') || q.includes('first') || q.includes('start')) {
    const recs = summary?.recommendations;
    if (recs?.length > 0) return 'Top recommendation: ' + recs[0];
    return 'Start with: 1) Enable the FIDO2 authentication method policy, '
         + '2) Run EntraPass to identify ready users, 3) Pilot with the IT team, '
         + '4) Create a CA Authentication Strength to enforce passkeys for sensitive apps.\n\n'
         + '📖 Learn more: [Enable FIDO2 security keys](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key)';
  }
  if (q.includes('pilot') || q.includes('rollout') || q.includes('deploy')) {
    return 'Recommended phased rollout: 1) Pilot with the IT team (ready users), '
         + '2) Enable passkey registration for all users, '
         + '3) Gradually enforce passkey for sensitive apps via CA, '
         + '4) Monitor sign-in logs for failures.\n\n'
         + '📖 Learn more: [Plan passwordless deployment](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-deployment)';
  }
  if (q.includes('fido2') || q.includes('passkey') || q.includes('authenticator')) {
    return 'FIDO2 passkeys in Entra ID can be hardware security keys (YubiKey, etc.) '
         + 'or device passkeys via Microsoft Authenticator. Both are phishing-resistant '
         + 'and eliminate password risk.\n\n'
         + '📖 Learn more: [Passkeys in Microsoft Authenticator](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-enable-authenticator-passkey)';
  }
  return 'I can help with passkey readiness, Conditional Access analysis, app '
       + 'compatibility, rollout planning, and EntraPass setup. '
       + 'Ask me something specific about your scan results or passkey migration.\n\n'
       + '📖 Learn more: [Passwordless overview](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passwordless)';
}
