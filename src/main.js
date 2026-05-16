import { PublicClientApplication } from '@azure/msal-browser';
import { GraphAPI } from './graph.js';
import { Analyzer } from './analyzer.js';

// ============================================
// Security helper
// ============================================
// Escapes untrusted strings before they are placed into innerHTML.
// Microsoft Graph data (display names, app names, group names, etc.) and
// user-typed input must never be interpolated into HTML unescaped.
function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[c]));
}

// ============================================
// Configuration
// ============================================
// Configuration is loaded from sessionStorage (user-supplied via the setup
// wizard) or from Vite build-time env vars for self-hosted deployments.
function loadConfig() {
  try {
    const saved = JSON.parse(sessionStorage.getItem('entrapass_config'));
    if (saved && saved.clientId && saved.tenantId) return saved;
  } catch (e) { /* ignore malformed config */ }

  const envClientId = import.meta.env.VITE_CLIENT_ID;
  const envTenantId = import.meta.env.VITE_TENANT_ID;
  if (envClientId && envTenantId) {
    return { clientId: envClientId, tenantId: envTenantId, redirectUri: window.location.origin };
  }
  return null;
}

function getMsalConfig() {
  const config = loadConfig();
  if (!config) return null;
  return {
    auth: {
      clientId: config.clientId,
      authority: 'https://login.microsoftonline.com/' + config.tenantId,
      redirectUri: config.redirectUri || window.location.origin,
    },
    cache: { cacheLocation: 'sessionStorage', storeAuthStateInCookie: false },
  };
}

const loginRequest = {
  scopes: [
    'User.Read', 'User.Read.All', 'Device.Read.All',
    'Policy.Read.All', 'Application.Read.All',
    'AuditLog.Read.All', 'Organization.Read.All',
  ],
};

let graphApi = null;
let analyzer = null;
let scanResults = null;
let chatHistory = [];   // [{role, content}] — last N exchanges sent to the model

// ============================================
// Microsoft documentation references
// ============================================
const MS_DOCS = [
  { icon: '🗺️', title: 'Plan a passwordless deployment', desc: 'Step-by-step guide for rolling out passkeys across your tenant', url: 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-deployment' },
  { icon: '🔑', title: 'Enable FIDO2 security keys', desc: 'Configure the FIDO2 authentication method policy in Entra ID', url: 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key' },
  { icon: '🛡️', title: 'Authentication strengths (CA)', desc: 'Enforce passkey-only sign-in via Conditional Access policies', url: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-strengths' },
  { icon: '📱', title: 'Passkeys in Microsoft Authenticator', desc: 'Enable and manage passkeys in Microsoft Authenticator (preview)', url: 'https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-enable-authenticator-passkey' },
  { icon: '🖥️', title: 'FIDO2 compatibility matrix', desc: 'Supported browsers, platforms, and device OS requirements', url: 'https://learn.microsoft.com/en-us/entra/identity/authentication/fido2-compatibility' },
  { icon: '📚', title: 'Passwordless authentication overview', desc: "Microsoft's complete passwordless strategy and available methods", url: 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passwordless' },
];

const CATEGORY_DOCS = {
  'Security Risk': 'https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks',
  'Policy':        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-strengths',
  'Blocked':       'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-deployment',
  'Attention':     'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-hardware-vendor',
  'Apps':          'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps',
  'Ready':         'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-deployment',
  'All Clear':     'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-deployment',
};

const EFFORT = {
  critical: { cls: 'immediate', label: 'Immediate' },
  high:     { cls: 'short',     label: '1–2 hrs'   },
  medium:   { cls: 'medium',    label: '1–2 days'  },
  low:      { cls: 'long',      label: '2–4 hrs'   },
};

// ============================================
// Bootstrap
// ============================================
window.addEventListener('DOMContentLoaded', async () => {
  setupEventListeners();
  renderOverviewReferences();

  const msalConfig = getMsalConfig();
  if (!msalConfig) {
    showAuthScreen('setup-tc');
    return;
  }
  try {
    window.msalInstance = new PublicClientApplication(msalConfig);
    await window.msalInstance.initialize();
    await window.msalInstance.handleRedirectPromise().catch(() => null);
    const accounts = window.msalInstance.getAllAccounts();
    if (accounts.length > 0) await initializeApp(accounts[0]);
    else showAuthScreen('setup-tc');
  } catch (err) {
    console.error('MSAL init failed:', err);
    showAuthScreen('setup-tc');
  }
});

// Wires every UI control to its handler. Replaces the previous inline
// onclick/onchange attributes so the app can run under a strict CSP
// (script-src 'self', no 'unsafe-inline').
function setupEventListeners() {
  const on = (id, event, handler) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener(event, handler);
  };

  // Setup wizard
  on('tc-checkbox', 'change', (e) => {
    document.getElementById('setup-deploy-btn').disabled = !e.target.checked;
  });
  on('setup-deploy-btn', 'click', showDeployStep);
  on('btn-deployed', 'click', showConfigStep);
  on('btn-back-to-tc', 'click', showTcStep);
  on('btn-save-config', 'click', saveConfiguration);
  on('btn-back-to-deploy', 'click', showDeployStep);

  // Dashboard header
  on('btn-signout', 'click', signOut);
  on('btn-reset', 'click', clearConfiguration);

  // Tabs
  document.querySelectorAll('.tab').forEach((tab) => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
  });

  // Scan + AI
  on('scan-btn', 'click', startScan);
  on('ai-mode', 'change', toggleAiMode);
  on('btn-send-chat', 'click', sendChat);
  on('chat-input', 'keydown', (e) => { if (e.key === 'Enter') sendChat(); });
}

// ============================================
// Setup wizard
// ============================================
function showAuthScreen(section) {
  document.getElementById('auth-screen').classList.remove('hidden');
  document.getElementById('dashboard').classList.add('hidden');
  ['setup-tc', 'setup-deploy', 'setup-config', 'setup-loading']
    .forEach((id) => document.getElementById(id).classList.add('hidden'));
  if (section) document.getElementById(section).classList.remove('hidden');
}

function showTcStep() { showAuthScreen('setup-tc'); }

function showDeployStep() {
  showAuthScreen('setup-deploy');
  // Link to the Azure Portal "Register an application" blade.
  const portalUrl = 'https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/CreateApplicationBlade';
  document.getElementById('deploy-to-azure-link').href = portalUrl;
  document.getElementById('current-url-display').textContent = window.location.origin;
}

function showConfigStep() {
  showAuthScreen('setup-config');
  // Default the redirect URI to this deployment's origin (not a hardcoded URL).
  const redirectInput = document.getElementById('config-redirect-uri');
  if (redirectInput && !redirectInput.value) redirectInput.value = window.location.origin;
}

function saveConfiguration() {
  const clientId = document.getElementById('config-client-id').value.trim();
  const tenantId = document.getElementById('config-tenant-id').value.trim();
  const redirectUri = document.getElementById('config-redirect-uri').value.trim() || window.location.origin;
  const errorEl = document.getElementById('config-error');
  errorEl.classList.add('hidden');

  const guidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!guidPattern.test(clientId)) {
    errorEl.textContent = 'Invalid Client ID format. Expected a GUID (e.g., 11111111-2222-3333-4444-555555555555).';
    errorEl.classList.remove('hidden');
    return;
  }
  if (!guidPattern.test(tenantId)) {
    errorEl.textContent = 'Invalid Tenant ID format. Expected a GUID.';
    errorEl.classList.remove('hidden');
    return;
  }

  showAuthScreen('setup-loading');
  document.getElementById('setup-loading-text').textContent = 'Validating configuration...';

  try {
    sessionStorage.setItem('entrapass_config', JSON.stringify({ clientId, tenantId, redirectUri }));

    const msalConfig = getMsalConfig();
    window.msalInstance = new PublicClientApplication(msalConfig);
    window.msalInstance.initialize().then(() => {
      document.getElementById('setup-loading-text').textContent = 'Configuration saved! Redirecting to sign in...';
      signIn();
    }).catch((err) => {
      errorEl.textContent = 'Failed to initialize: ' + err.message;
      errorEl.classList.remove('hidden');
      showAuthScreen('setup-config');
    });
  } catch (err) {
    errorEl.textContent = 'Error saving configuration: ' + err.message;
    errorEl.classList.remove('hidden');
    showAuthScreen('setup-config');
  }
}

function clearConfiguration() {
  sessionStorage.removeItem('entrapass_config');
  sessionStorage.removeItem('entrapass_results');
  location.reload();
}

// ============================================
// Authentication
// ============================================
async function signIn() {
  const msalConfig = getMsalConfig();
  if (!msalConfig) { showAuthScreen('setup-tc'); return; }
  try {
    if (!window.msalInstance) {
      window.msalInstance = new PublicClientApplication(msalConfig);
      await window.msalInstance.initialize();
    }
    await window.msalInstance.loginRedirect(loginRequest);
  } catch (err) {
    console.error('Sign-in failed:', err);
    alert('Sign-in failed. Check your Client ID and Tenant ID.');
  }
}

function signOut() {
  if (window.msalInstance) {
    window.msalInstance.logoutRedirect({ postLogoutRedirectUri: window.location.origin });
  }
}

// Sets the active MSAL account, wires up the Graph client and analyzer, shows
// the dashboard, and restores any cached scan results for this session.
async function initializeApp(account) {
  window.msalInstance.setActiveAccount(account);
  graphApi = new GraphAPI(window.msalInstance, loginRequest.scopes);
  analyzer = new Analyzer();
  showDashboard(account);

  try {
    const cached = JSON.parse(sessionStorage.getItem('entrapass_results'));
    if (cached && cached.passkeyReadiness) {
      scanResults = cached;
      renderDashboard(scanResults);
    }
  } catch (e) { /* no usable cached results */ }
}

function showDashboard(account) {
  document.getElementById('auth-screen').classList.add('hidden');
  document.getElementById('dashboard').classList.remove('hidden');

  const userBadge = document.getElementById('user-info');
  if (userBadge) userBadge.textContent = account.name || account.username || '';

  const tenantBadge = document.getElementById('tenant-name');
  const cfg = loadConfig();
  if (tenantBadge && cfg) tenantBadge.textContent = 'Tenant: ' + cfg.tenantId;
}

// ============================================
// Scan
// ============================================
async function startScan() {
  if (!graphApi || !analyzer) {
    alert('Not signed in. Please sign in before scanning.');
    return;
  }
  const btn = document.getElementById('scan-btn');
  btn.disabled = true;
  btn.textContent = 'Scanning...';
  showLoading('Fetching users, devices, policies, apps, auth methods...');

  // Track failures of the top-level data sources so partial results are not
  // silently presented as a clean bill of health.
  const errors = [];
  const track = (source, promise, fallback) => promise.catch((e) => {
    console.error(`Graph fetch failed (${source}):`, e);
    errors.push({ source, message: e.message });
    return fallback;
  });

  try {
    // Phase 1: tenant-wide data
    const [users, devices, policies, apps, org, sps, authPolicy, authMethodsConfig] = await Promise.all([
      track('Users', graphApi.getUsers(), []),
      track('Devices', graphApi.getDevices(), []),
      track('Conditional Access policies', graphApi.getConditionalAccessPolicies(), []),
      track('Applications', graphApi.getApplications(), []),
      track('Organization', graphApi.getOrganization(), null),
      track('Service principals', graphApi.getServicePrincipals(), []),
      track('Authorization policy', graphApi.getAuthorizationPolicy(), {}),
      track('Authentication methods policy', graphApi.getAuthenticationMethodsPolicy(), []),
    ]);

    showLoading('Analyzing authentication methods and device ownership...');

    // Phase 2: per-user detail (sampled for performance)
    const userSample = users.slice(0, 50);
    const userDetails = await Promise.all(
      userSample.map(async (u) => {
        const [authMethods, activity, groups] = await Promise.all([
          graphApi.getAuthenticationMethodsForUser(u.id).catch(() => []),
          graphApi.getUserSignInActivity(u.id).catch(() => ({})),
          graphApi.getUserMemberOf(u.id).catch(() => []),
        ]);
        return { ...u, authMethods, signInActivity: activity, groups };
      })
    );

    // Phase 3: device ownership (sampled for performance)
    const deviceSample = devices.slice(0, 100);
    const deviceDetails = await Promise.all(
      deviceSample.map(async (d) => {
        const owners = await graphApi.getDeviceRegisteredOwners(d.id).catch(() => []);
        return { ...d, registeredOwners: owners };
      })
    );

    showLoading('Running analysis...');

    scanResults = analyzer.analyzeAll({
      users: userDetails,
      devices: deviceDetails,
      policies,
      apps,
      org,
      servicePrincipals: sps,
      authorizationPolicy: authPolicy,
      authMethodsConfig,
    });

    // Record sampling + fetch errors so the UI can be honest about coverage.
    scanResults.meta = {
      usersFound: users.length,
      usersAnalyzed: userDetails.length,
      devicesFound: devices.length,
      devicesAnalyzed: deviceDetails.length,
      errors,
    };

    sessionStorage.setItem('entrapass_results', JSON.stringify(scanResults));

    if (org && org.displayName) {
      const tenantBadge = document.getElementById('tenant-name');
      if (tenantBadge) tenantBadge.textContent = org.displayName;
    }

    renderDashboard(scanResults);
  } catch (err) {
    console.error('Scan failed:', err);
    alert('Scan failed: ' + err.message);
  } finally {
    hideLoading();
    btn.disabled = false;
    btn.textContent = 'Scan Tenant Now';
  }
}

function switchTab(tabName) {
  document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach((t) => t.classList.add('hidden'));
  document.querySelector(`.tab[data-tab='${tabName}']`).classList.add('active');
  document.getElementById(`tab-${tabName}`).classList.remove('hidden');
}

// ============================================
// AI Assistant
// ============================================
function toggleAiMode() {
  const mode = document.getElementById('ai-mode').value;
  document.getElementById('byok-config').classList.toggle('hidden', mode !== 'byok');
  document.getElementById('ai-chat').classList.toggle('hidden', mode === 'off');
  // Clear history when switching modes so context doesn't bleed across providers
  chatHistory = [];
  document.getElementById('chat-messages').innerHTML = '';
}

// Parses a Workers AI SSE stream, calling onChunk(accumulatedText) per token.
// Returns the fully assembled response string.
async function readSseStream(body, onChunk) {
  const reader  = body.getReader();
  const decoder = new TextDecoder();
  let buffer   = '';
  let fullText = '';
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() ?? '';
      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const data = line.slice(6).trim();
        if (data === '[DONE]') return fullText;
        try {
          const token = JSON.parse(data).response ?? '';
          if (token) { fullText += token; onChunk(fullText); }
        } catch { /* ignore malformed SSE */ }
      }
    }
  } finally {
    reader.releaseLock();
  }
  return fullText;
}

async function sendChat() {
  const input = document.getElementById('chat-input');
  const q = input.value.trim();
  if (!q) return;

  const m = document.getElementById('chat-messages');
  m.innerHTML += `<div class='message user'>${escapeHtml(q)}</div>`;
  input.value = '';

  const botEl = document.createElement('div');
  botEl.className = 'message bot';
  botEl.textContent = 'Thinking…';
  m.appendChild(botEl);

  try {
    const a = await getAiAnswer(q, scanResults, chatHistory, (partial) => {
      botEl.innerHTML = formatAiAnswer(partial);
      m.scrollTop = m.scrollHeight;
    });
    m.scrollTop = m.scrollHeight;
    chatHistory.push({ role: 'user', content: q }, { role: 'assistant', content: a });
    if (chatHistory.length > 10) chatHistory = chatHistory.slice(-10);
  } catch (err) {
    if (err.quota) {
      // Quota / rate-limit — render as a soft notice, not a red error
      botEl.innerHTML = formatAiAnswer(err.message);
    } else {
      botEl.innerHTML = `<span class="error">Error: ${escapeHtml(err.message)}</span>`;
    }
  }
}

async function getAiAnswer(question, results, history = [], onChunk = () => {}) {
  const mode = document.getElementById('ai-mode').value;

  if (mode === 'cloudflare') {
    const r = await fetch('/ai/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question, results: results || {}, history }),
    });
    if (!r.ok) {
      let msg = 'AI request failed';
      let quota = r.status === 429;
      try { const b = await r.json(); msg = b.error || msg; quota = quota || !!b.quota; } catch { /* ignore */ }
      throw Object.assign(new Error(msg), { quota });
    }
    return readSseStream(r.body, onChunk);
  }

  if (mode === 'byok') {
    const ep    = document.getElementById('ai-endpoint').value.trim().replace(/\/+$/, '');
    const k     = document.getElementById('ai-key').value;
    const model = document.getElementById('ai-model').value;
    if (!ep || !k) throw new Error('Configure the endpoint and API key in BYOK settings');
    const systemMsg = 'You are the EntraPass AI assistant — an expert in Microsoft Entra ID '
      + 'passkey migration and the EntraPass open-source scanning tool. '
      + 'Answer concisely and factually, under 200 words. '
      + 'When relevant, end your response with a "📖 Learn more:" line citing one '
      + 'official Microsoft documentation URL (learn.microsoft.com). '
      + 'Do not answer questions unrelated to Microsoft identity or EntraPass.';
    const userMsg = results
      ? `Scan results: ${JSON.stringify(results)}\n\nQuestion: ${question}`
      : `Question: ${question}`;
    const r = await fetch(ep + '/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + k },
      body: JSON.stringify({
        model: model || 'gpt-4o-mini',
        messages: [
          { role: 'system', content: systemMsg },
          ...history,
          { role: 'user', content: userMsg },
        ],
      }),
    });
    if (!r.ok) throw new Error('BYOK API returned ' + r.status);
    const answer = (await r.json()).choices?.[0]?.message?.content || 'No response';
    onChunk(answer);
    return answer;
  }

  const offMsg = 'AI is off.';
  onChunk(offMsg);
  return offMsg;
}

// Escapes the model output first, then applies a safe markdown subset.
// Escaping MUST happen before formatting so model output cannot inject markup.
// Links are only rendered for known-safe domains (learn.microsoft.com, github.com).
function formatAiAnswer(text) {
  return escapeHtml(text)
    .replace(/\n/g, '<br>')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(
      /\[([^\]]{1,120})\]\((https?:\/\/(?:learn\.microsoft\.com|github\.com|docs\.microsoft\.com)[^\s)]{0,400})\)/g,
      (_, label, url) => `<a href="${url}" target="_blank" rel="noopener noreferrer">${label}</a>`,
    );
}

// ============================================
// CSV Export
// ============================================
function downloadCsv(filename, headers, rows) {
  const esc = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';
  const csv = [headers, ...rows].map(r => r.map(esc).join(',')).join('\n');
  const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8;' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

function exportReadinessCsv() {
  if (!scanResults?.passkeyReadiness?.users) return;
  const ts = new Date().toISOString().slice(0, 10);
  downloadCsv(
    `entrapass-readiness-${ts}.csv`,
    ['Display Name', 'UPN', 'Status', 'Issues', 'Last Sign-In', 'Devices', 'Auth Methods'],
    scanResults.passkeyReadiness.users.map(u => [
      u.displayName, u.userPrincipalName, u.status,
      u.issues.join('; '), u.lastSignIn || '', u.deviceCount, u.authMethodCount,
    ]),
  );
}

function exportAppsCsv() {
  if (!scanResults?.apps) return;
  const ts = new Date().toISOString().slice(0, 10);
  downloadCsv(
    `entrapass-apps-${ts}.csv`,
    ['App Name', 'Microsoft-Managed', 'Compatible', 'Severity', 'Issues', 'Fix Guide'],
    scanResults.apps.map(a => [
      a.displayName, a.isSubstrate ? 'Yes' : 'No',
      a.passkeyCompatible ? 'Yes' : 'No', a.severity || '',
      a.issues.join('; '), a.fixGuide || '',
    ]),
  );
}

function exportPoliciesCsv() {
  if (!scanResults?.policies) return;
  const ts = new Date().toISOString().slice(0, 10);
  downloadCsv(
    `entrapass-policies-${ts}.csv`,
    ['Policy Name', 'State', 'Blocks Passkeys', 'Fix Guide'],
    scanResults.policies.map(p => [
      p.displayName, p.state || '',
      p.blocksPasskeyRegistration ? 'Yes' : 'No', p.fixGuide || '',
    ]),
  );
}

// ============================================
// Loading overlay
// ============================================
function showLoading(text) {
  document.getElementById('loading-text').textContent = text || 'Loading...';
  document.getElementById('loading-overlay').classList.remove('hidden');
}

function hideLoading() {
  document.getElementById('loading-overlay').classList.add('hidden');
}

// ============================================
// Rendering
// ============================================
function renderDashboard(r) {
  renderScanNotices(r);
  renderOverviewHero(r);
  renderOverviewAlerts(r);
  renderOverviewActions(r);
  renderReadiness(r);
  renderApps(r);
  renderPolicies(r);
}

function renderOverviewReferences() {
  const el = document.getElementById('overview-references');
  if (!el) return;
  el.innerHTML = `
    <div class="references-section">
      <div class="references-header">
        <span>📖</span>
        <h3>Microsoft Documentation</h3>
        <span class="ms-logo">learn.microsoft.com</span>
      </div>
      <div class="ref-grid">
        ${MS_DOCS.map((d) => `
          <a class="ref-item" href="${d.url}" target="_blank" rel="noopener noreferrer">
            <div class="ref-icon">${d.icon}</div>
            <div>
              <div class="ref-title">${escapeHtml(d.title)}</div>
              <div class="ref-desc">${escapeHtml(d.desc)}</div>
              <div class="ref-source">learn.microsoft.com</div>
            </div>
          </a>`).join('')}
      </div>
    </div>`;
}

function renderOverviewHero(r) {
  const hero = document.getElementById('overview-hero');
  const prescan = document.getElementById('overview-prescan');
  if (!hero) return;

  const { total, ready, needsAttention, blocked } = r.passkeyReadiness;
  const score = r.readinessScore ?? 0;
  const scoreClass = score >= 70 ? 'score-good' : score >= 40 ? 'score-warn' : 'score-danger';
  const verdictClass = score >= 70 ? 'good' : score >= 40 ? 'warn' : 'danger';
  const verdictText = score >= 70 ? 'Ready to roll out' : score >= 40 ? 'Needs preparation' : 'Action required';
  const ringColor = score >= 70 ? 'var(--good)' : score >= 40 ? 'var(--accent)' : 'var(--danger)';
  const circ = 2 * Math.PI * 50;
  const targetOffset = circ * (1 - score / 100);
  const sampled = r.meta && r.meta.usersFound > total;

  hero.innerHTML = `
    <div class="score-ring-card">
      <div class="ring-label">Readiness Score</div>
      <div class="ring-svg-wrapper">
        <svg width="128" height="128" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="50" fill="none" stroke="var(--border-subtle)" stroke-width="10" stroke-linecap="round"/>
          <circle cx="60" cy="60" r="50" fill="none" stroke="${ringColor}" stroke-width="10"
            stroke-dasharray="${circ.toFixed(1)}" stroke-dashoffset="${circ.toFixed(1)}"
            stroke-linecap="round" class="ring-progress" id="ring-arc"/>
        </svg>
        <div class="ring-center-text">
          <span class="ring-score-number ${scoreClass}">${score}</span>
          <span class="ring-score-sub">/ 100</span>
        </div>
      </div>
      <span class="score-verdict ${verdictClass}">${verdictText}</span>
    </div>
    <div class="stat-tiles">
      <div class="stat-tile total">
        <div class="stat-tile-value">${escapeHtml(String(total))}</div>
        <div class="stat-tile-label">Users scanned</div>
        <div class="stat-tile-sub">${sampled ? `of ${escapeHtml(String(r.meta.usersFound))} total (sampled)` : 'full coverage'}</div>
      </div>
      <div class="stat-tile good">
        <div class="stat-tile-value">${escapeHtml(String(ready))}</div>
        <div class="stat-tile-label">Ready for passkeys</div>
        <div class="stat-tile-sub">${total > 0 ? Math.round(ready / total * 100) : 0}% of scanned users</div>
      </div>
      <div class="stat-tile warn">
        <div class="stat-tile-value">${escapeHtml(String(needsAttention))}</div>
        <div class="stat-tile-label">Need preparation</div>
        <div class="stat-tile-sub">Device or MFA update required</div>
      </div>
      <div class="stat-tile danger">
        <div class="stat-tile-value">${escapeHtml(String(blocked))}</div>
        <div class="stat-tile-label">Blocked</div>
        <div class="stat-tile-sub">CA policy or device blockers</div>
      </div>
    </div>`;

  hero.classList.remove('hidden');
  if (prescan) prescan.classList.add('hidden');

  requestAnimationFrame(() => requestAnimationFrame(() => {
    const arc = document.getElementById('ring-arc');
    if (arc) arc.style.strokeDashoffset = targetOffset.toFixed(1);
  }));
}

function renderOverviewAlerts(r) {
  const el = document.getElementById('overview-alerts');
  if (!el) return;

  const alerts = [];
  (r.toxicCombos || []).forEach((t) => {
    alerts.push({
      cls: t.severity === 'critical' ? 'critical' : 'high',
      icon: t.severity === 'critical' ? '🚨' : '🔴',
      title: t.displayName || 'Security risk detected',
      desc: t.description || '',
      fix: t.fix || null,
      docUrl: 'https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks',
    });
  });
  (r.policies || []).filter((p) => p.blocksPasskeyRegistration).forEach((p) => {
    alerts.push({
      cls: 'high',
      icon: '🛡️',
      title: `CA policy blocks passkeys: ${p.displayName}`,
      desc: p.warning || 'This policy prevents passkey registration.',
      fix: p.fixGuide || null,
      docUrl: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-strengths',
    });
  });

  if (alerts.length === 0) { el.classList.add('hidden'); return; }
  el.classList.remove('hidden');
  el.innerHTML = `
    <div class="section-heading">⚠️ Findings requiring attention</div>
    ${alerts.map((a) => `
      <div class="alert-card ${escapeHtml(a.cls)}">
        <span class="alert-icon">${a.icon}</span>
        <div class="alert-body">
          <div class="alert-title">${escapeHtml(a.title)}</div>
          ${a.desc ? `<div class="alert-desc">${escapeHtml(a.desc)}</div>` : ''}
          ${a.fix ? `<div class="alert-fix">→ ${escapeHtml(a.fix)}</div>` : ''}
          <div style="margin-top:0.4rem;">
            <a class="doc-link" href="${a.docUrl}" target="_blank" rel="noopener">📄 Microsoft guidance ↗</a>
          </div>
        </div>
      </div>`).join('')}`;
}

function renderOverviewActions(r) {
  const el = document.getElementById('overview-actions');
  if (!el) return;

  const recs = (r.recommendations || []).filter((rec) => rec.severity === 'critical' || rec.severity === 'high' || rec.severity === 'medium');
  if (recs.length === 0) { el.classList.add('hidden'); return; }

  el.classList.remove('hidden');
  el.innerHTML = `
    <div class="actions-section">
      <div class="actions-header"><span>⚡</span><h3>Priority Actions</h3></div>
      ${recs.map((rec, i) => {
        const effort = EFFORT[rec.severity] || EFFORT.low;
        const docUrl = CATEGORY_DOCS[rec.category] || CATEGORY_DOCS['Ready'];
        return `
          <div class="action-item">
            <span class="action-number">${i + 1}</span>
            <div class="action-body">
              <div class="action-title">${escapeHtml(rec.title || rec.text)}</div>
              ${rec.text && rec.title && rec.text !== rec.title ? `<div class="action-detail">${escapeHtml(rec.text)}</div>` : ''}
              ${rec.fix ? `<div class="action-detail" style="color:var(--primary);margin-top:0.15rem;">→ ${escapeHtml(rec.fix)}</div>` : ''}
              <div class="action-meta">
                <span class="effort-badge ${effort.cls}">⏱ ${effort.label}</span>
                <a class="doc-link" href="${docUrl}" target="_blank" rel="noopener">Microsoft docs ↗</a>
              </div>
            </div>
          </div>`;
      }).join('')}
    </div>`;
}

// Surfaces sampling limits and failed data sources so partial results are
// never mistaken for a complete, clean scan.
function renderScanNotices(r) {
  const el = document.getElementById('scan-notices');
  if (!el) return;
  const meta = r.meta;
  if (!meta) { el.classList.add('hidden'); el.innerHTML = ''; return; }

  let html = '';
  if (meta.errors && meta.errors.length > 0) {
    html += '<div class="notice notice-error"><strong>Partial results.</strong> '
      + escapeHtml(String(meta.errors.length))
      + ' data source(s) could not be read (often a missing permission or admin consent): '
      + meta.errors.map((e) => escapeHtml(e.source)).join(', ')
      + '.</div>';
  }
  if (meta.usersFound > meta.usersAnalyzed) {
    html += '<div class="notice notice-info">Analyzed the first '
      + escapeHtml(String(meta.usersAnalyzed)) + ' of '
      + escapeHtml(String(meta.usersFound)) + ' users (sampled for performance).</div>';
  }
  if (html) { el.innerHTML = html; el.classList.remove('hidden'); }
  else { el.classList.add('hidden'); el.innerHTML = ''; }
}



function renderReadiness(r) {
  const { users } = r.passkeyReadiness;
  let h = '<table><thead><tr><th>User</th><th>Status</th><th>Issues</th></tr></thead><tbody>';
  users.forEach((u) => {
    const ic = u.status === 'ready' ? '\u{1F7E2}'
      : u.status === 'attention' ? '\u{1F7E1}' : '\u{1F534}';
    h += `<tr>
      <td>${escapeHtml(u.displayName)}</td>
      <td>${ic} ${escapeHtml(u.status)}</td>
      <td>${escapeHtml(u.issues.join(', ') || 'None')}</td>
    </tr>`;
  });
  h += '</tbody></table>';
  document.getElementById('readiness-table').innerHTML = h;

  const btn = document.getElementById('btn-export-readiness');
  if (btn) { btn.classList.remove('hidden'); btn.onclick = exportReadinessCsv; }
}

function renderApps(r) {
  const compatible = r.apps.filter((a) => a.passkeyCompatible).length;
  const total  = r.apps.length;
  const flagged = total - compatible;
  const container = document.getElementById('apps-table');

  let h = '<div style="margin-bottom:0.75rem;font-size:0.9rem;color:var(--text-secondary);">';
  h += '<span style="color:var(--good);">\u{1F7E2} ' + escapeHtml(String(compatible)) + ' compatible</span>';
  if (flagged > 0) h += ' <span style="color:var(--danger);margin-left:0.5rem;">\u{1F534} ' + escapeHtml(String(flagged)) + ' need review</span>';
  h += ' <span style="margin-left:0.5rem;">of ' + escapeHtml(String(total)) + ' apps</span>';
  h += '</div>';

  h += '<div style="overflow-x:auto;">';
  h += '<table><thead><tr><th>App</th><th>Status</th><th>Issues</th><th>Description &amp; Fix</th></tr></thead><tbody>';

  const order = { high: 0, medium: 1, low: 2, good: 3, info: 4 };
  const sorted = [...r.apps].sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));

  sorted.forEach((a) => {
    let badge, statusText;
    if (a.isSubstrate && !a.passkeyCompatible) {
      badge = '\u{1F4C4}'; statusText = 'Info';
    } else if (a.passkeyCompatible) {
      badge = '\u{1F7E2}'; statusText = 'OK';
    } else {
      badge = '\u{1F534}'; statusText = 'Flagged';
    }
    const issueText = a.issues.length > 0 ? a.issues.join('; ') : 'None';
    const descBg     = a.severity === 'high' ? '#fff0f0' : a.severity === 'medium' ? '#fff8f0' : '#f8f8f8';
    const descBorder = a.severity === 'high' ? 'var(--danger)' : a.severity === 'medium' ? 'var(--warn)' : 'var(--border)';
    h += '<tr>';
    h += '<td><strong>' + escapeHtml(a.displayName) + '</strong>'
      + (a.isSubstrate ? '<br><span style="font-size:0.75rem;color:#888;">Microsoft-managed</span>' : '') + '</td>';
    h += '<td>' + badge + ' ' + statusText + '</td>';
    h += '<td>' + escapeHtml(issueText) + '</td>';
    h += '<td style="font-size:0.85rem;background:' + descBg + ';border-left:3px solid ' + descBorder + ';padding:0.5rem 0.75rem;">';
    h += '<p style="margin-bottom:0.3rem;">' + escapeHtml(a.description) + '</p>';
    if (a.fixGuide) h += '<p style="margin-top:0.3rem;color:var(--primary);"><strong>Fix:</strong> ' + escapeHtml(a.fixGuide) + '</p>';
    h += '</td></tr>';
  });

  h += '</tbody></table></div>';
  container.innerHTML = h;

  const btn = document.getElementById('btn-export-apps');
  if (btn) { btn.classList.remove('hidden'); btn.onclick = exportAppsCsv; }
}

function renderPolicies(r) {
  let h = '<table><thead><tr><th>Policy</th><th>Blocks Passkeys?</th><th>Action</th></tr></thead><tbody>';
  r.policies.forEach((p) => {
    const blk = p.blocksPasskeyRegistration ? '\u{1F534} Yes' : '\u{1F7E2} No';
    h += `<tr>
      <td>${escapeHtml(p.displayName)}</td>
      <td>${blk}</td>
      <td>${escapeHtml(p.fixGuide || p.recommendation || 'None')}</td>
    </tr>`;
  });
  h += '</tbody></table>';
  document.getElementById('policies-table').innerHTML = h;

  const btn = document.getElementById('btn-export-policies');
  if (btn) { btn.classList.remove('hidden'); btn.onclick = exportPoliciesCsv; }
}
