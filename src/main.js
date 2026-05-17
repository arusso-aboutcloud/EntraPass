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
  { icon: '🛡️', title: 'Authentication strengths (CA)', desc: 'Enforce passkey-only sign-in via Conditional Access policies', url: 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths' },
  { icon: '📱', title: 'Passkeys in Microsoft Authenticator', desc: 'Enable and manage passkeys in Microsoft Authenticator (preview)', url: 'https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-enable-authenticator-passkey' },
  { icon: '🖥️', title: 'FIDO2 compatibility matrix', desc: 'Supported browsers, platforms, and device OS requirements', url: 'https://learn.microsoft.com/en-us/entra/identity/authentication/fido2-compatibility' },
  { icon: '📚', title: 'Passwordless authentication overview', desc: "Microsoft's complete passwordless strategy and available methods", url: 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passwordless' },
];

const CATEGORY_DOCS = {
  'Security Risk': 'https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks',
  'Policy':        'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths',
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

// Well-known FIDO2 authenticator AAGUIDs — used to resolve the raw GUIDs
// returned by the FIDO2 authentication method configuration into human-readable
// device names in the policy inspector.
const KNOWN_AAAGUIDS = {
  // Yubico
  'cb69481e-8ff7-4039-93ec-0a2729a154a8': { name: 'YubiKey 5 Series',                     vendor: 'Yubico',     type: 'hardware' },
  'ee882879-721c-4913-9775-3dfcce97072a': { name: 'YubiKey 5 NFC',                         vendor: 'Yubico',     type: 'hardware' },
  'fa2b99dc-9e39-4257-8f92-4a30d23c4118': { name: 'YubiKey 5 NFC FIPS',                    vendor: 'Yubico',     type: 'hardware' },
  'c1f9a0bc-1dd2-404a-b27f-8e29047a43fd': { name: 'YubiKey 5 FIPS Series',                 vendor: 'Yubico',     type: 'hardware' },
  'f8a011f3-8c0a-4d15-8006-17111f9edc7d': { name: 'Security Key by Yubico',                vendor: 'Yubico',     type: 'hardware' },
  'b92c3f9a-c014-4056-887f-140a2501163b': { name: 'Security Key 2 by Yubico',              vendor: 'Yubico',     type: 'hardware' },
  '6d44ba9b-f6ec-2e49-b930-0c8fe920cb73': { name: 'Security Key NFC by Yubico',            vendor: 'Yubico',     type: 'hardware' },
  '149a2021-8ef6-4133-96b8-81f8d5b7f1f5': { name: 'Security Key NFC by Yubico (Enterprise)', vendor: 'Yubico',  type: 'hardware' },
  '34f5766d-1536-4a24-9033-0e294e510fb0': { name: 'YubiKey 5 Nano',                        vendor: 'Yubico',     type: 'hardware' },
  '2fc0579f-8113-47ea-b116-bb5a8db9202a': { name: 'YubiKey 5Ci',                           vendor: 'Yubico',     type: 'hardware' },
  '73bb0cd4-e502-49b8-9c6f-b59445bf720b': { name: 'YubiKey 5C NFC',                        vendor: 'Yubico',     type: 'hardware' },
  '85203421-48f9-4355-9bc8-8a53846e5083': { name: 'YubiKey 5Ci FIPS',                      vendor: 'Yubico',     type: 'hardware' },
  'c5ef55ff-ad9a-4b9f-b580-adebafe026d0': { name: 'YubiKey 5 NFC FIPS (Enterprise)',       vendor: 'Yubico',     type: 'hardware' },
  // Windows Hello
  '08987058-cadc-4b81-b6e1-30de50dcbe96': { name: 'Windows Hello Hardware',                vendor: 'Microsoft',  type: 'platform' },
  '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': { name: 'Windows Hello Software',                vendor: 'Microsoft',  type: 'platform' },
  '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': { name: 'Windows Hello VBS Hardware',            vendor: 'Microsoft',  type: 'platform' },
  'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': { name: 'Windows Hello (TPM 2.0)',               vendor: 'Microsoft',  type: 'platform' },
  // Apple
  'adce0002-35bc-c60a-648b-0b25f1f05503': { name: 'Apple iCloud Keychain (passkey)',        vendor: 'Apple',      type: 'platform' },
  // Google
  '42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3': { name: 'Google Titan Security Key v2',          vendor: 'Google',     type: 'hardware' },
  'de503f9c-21a4-4f76-b4b7-558eb55c6f89': { name: 'Google Password Manager',               vendor: 'Google',     type: 'platform' },
  'b5397666-4885-aa6b-cebf-e52262a439a2': { name: 'Chrome on macOS / ChromeOS',            vendor: 'Google',     type: 'platform' },
  // Feitian
  '12ded745-4bed-47d4-abaa-e713f51d6393': { name: 'Feitian BioPass FIDO2',                 vendor: 'Feitian',    type: 'hardware' },
  '77010bd7-212a-4fc9-b236-d2ca5e9d4084': { name: 'Feitian BioPass FIDO2 Pro',             vendor: 'Feitian',    type: 'hardware' },
  'ee041bce-25e5-4cdb-8f86-897fd6418464': { name: 'Feitian ePass FIDO2-NFC',               vendor: 'Feitian',    type: 'hardware' },
  'b6ede29c-3772-412c-8a78-539c1f4c62d2': { name: 'Feitian FIDO2 Key',                     vendor: 'Feitian',    type: 'hardware' },
  // HID Global
  '692db549-7ae5-44d5-a1e5-dd20a493b723': { name: 'HID Crescendo Key',                     vendor: 'HID Global', type: 'hardware' },
  'c80dbd9a-533f-4a17-b941-1a2f1c7cedff': { name: 'HID Crescendo C2300',                   vendor: 'HID Global', type: 'hardware' },
  // Swissbit
  'e13c7ba3-0868-4b91-b7b1-f73b6de301af': { name: 'Swissbit iShield Key',                  vendor: 'Swissbit',   type: 'hardware' },
  // Ensurity
  '454e5346-4944-4ffd-6c93-8e9267193e9a': { name: 'Ensurity ThinC',                        vendor: 'Ensurity',   type: 'hardware' },
  // eWBM
  '87dbc5a1-4c94-4dc8-8a47-97d800fd1f3c': { name: 'eWBM Goldengate FIDO2',                 vendor: 'eWBM',       type: 'hardware' },
  // OneSpan
  '30b5035e-d297-4fc1-875f-961a05e33e90': { name: 'OneSpan FIDO Touch',                    vendor: 'OneSpan',    type: 'hardware' },
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

    showLoading('Enriching app registration data...');

    // Phase 1b: app registration owner enrichment (capped at 50 for performance)
    const appSample50 = apps.slice(0, 50);
    const appsEnriched = await Promise.all(
      appSample50.map(async (app) => {
        const owners = await graphApi.getApplicationOwners(app.id).catch(() => []);
        return { ...app, owners };
      })
    );

    showLoading('Fetching authentication registration report...');

    // Phase 2a: bulk registration report (single call, requires AuditLog.Read.All +
    // Reports Reader or equivalent role — see
    // https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails).
    // getUserRegistrationDetails() returns a tri-state object and never throws.
    const regReport = await graphApi.getUserRegistrationDetails();
    const regByUserId = new Map(
      (regReport.records || []).map(rec => [rec.id, rec])
    );

    showLoading('Analyzing sign-in activity and device ownership...');

    // Phase 2b: per-user sign-in activity + group membership (sampled for performance).
    // getUserSignInActivity() returns tri-state and never throws.
    const userSample = users.slice(0, 50);
    const userDetails = await Promise.all(
      userSample.map(async (u) => {
        const [activity, groups] = await Promise.all([
          graphApi.getUserSignInActivity(u.id),
          graphApi.getUserMemberOf(u.id).catch(() => []),
        ]);
        const regRec = regByUserId.get(u.id);
        const registrationData = regReport.available
          ? (regRec
              ? { available: true, reason: 'ok', ...regRec }
              : { available: false, reason: 'no_record' })  // disabled users not returned by report
          : { available: false, reason: regReport.reason };
        return { ...u, registrationData, signInActivity: activity, groups };
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
      apps: appsEnriched,
      org,
      servicePrincipals: sps,
      authorizationPolicy: authPolicy,
      authMethodsConfig,
    });

    // Record sampling + fetch errors so the UI can be honest about coverage.
    scanResults.meta = {
      usersFound:                   users.length,
      usersAnalyzed:                userDetails.length,
      devicesFound:                 devices.length,
      devicesAnalyzed:              deviceDetails.length,
      registrationReportAvailable:  regReport.available,
      registrationReportReason:     regReport.reason,
      partialDataCount:             scanResults.passkeyReadiness?.partialDataCount ?? 0,
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

  // Minimize before any data leaves the browser: only counts + recommendation
  // titles, no user names, UPNs, tenant identifiers, or Graph response bodies.
  const prUsers = results?.passkeyReadiness?.users || [];
  const summary = results ? {
    totalUsers:     results.passkeyReadiness?.total  || 0,
    readyUsers:     prUsers.filter(u => u.status === 'ready').length,
    capableUsers:   prUsers.filter(u => u.status === 'capable').length,
    needsPrepUsers: prUsers.filter(u => u.status === 'needsPrep').length,
    blockedUsers:   prUsers.filter(u => u.status === 'blocked').length,
    exemptUsers:    prUsers.filter(u => u.status === 'exempt').length,
    score:          results.score || 0,
    recommendations: (results.recommendations || []).slice(0, 5).map(r => r.title || r.text),
  } : null;

  if (mode === 'cloudflare') {
    const r = await fetch('/ai/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question, results: summary || {}, history }),
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
    const userMsg = summary
      ? `Scan results: ${JSON.stringify(summary)}\n\nQuestion: ${question}`
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
// Links are only rendered for known-safe domains (learn.microsoft.com, github.com, aboutcloud.io).
const TRUSTED_LINK_DOMAINS = 'learn\\.microsoft\\.com|docs\\.microsoft\\.com|github\\.com|entrapass\\.aboutcloud\\.io|aboutcloud\\.io';
const BARE_URL_RE = new RegExp(
  '(?<!href=")(https?:\\/\\/(?:' + TRUSTED_LINK_DOMAINS + ')[^\\s<>"]{0,400})',
  'g',
);
const MD_LINK_RE = new RegExp(
  '\\[([^\\]]{1,120})\\]\\((https?:\\/\\/(?:' + TRUSTED_LINK_DOMAINS + ')[^\\s)]{0,400})\\)',
  'g',
);
function formatAiAnswer(text) {
  return escapeHtml(text)
    .replace(/\n/g, '<br>')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(MD_LINK_RE, (_, label, url) => `<a href="${url}" target="_blank" rel="noopener noreferrer">${label}</a>`)
    .replace(BARE_URL_RE, url => `<a href="${url}" target="_blank" rel="noopener noreferrer">${url}</a>`);
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
    ['Display Name', 'UPN', 'Account Type', 'Status', 'Privileged', 'Stale (>90d)', 'Reg Data Available', 'Sign-in Data Available', 'Issues', 'Recommended Action', 'Auth Methods', 'Device Count', 'Device Summary', 'Groups', 'Last Sign-In'],
    scanResults.passkeyReadiness.users.map(u => [
      u.displayName,
      u.userPrincipalName,
      u.accountType,
      u.status,
      u.isPrivileged ? 'Yes' : 'No',
      u.isStale === true ? 'Yes' : u.isStale === false ? 'No' : 'N/A',
      u.registrationDataAvailable ? 'Yes' : 'No',
      u.signInActivityAvailable   ? 'Yes' : 'No',
      u.issues.join('; '),
      u.recommendedAction || '',
      (u.authMethodTypes || []).map(m => m.label).join('; '),
      u.deviceCount,
      u.deviceSummary || '',
      (u.groups || []).join('; '),
      u.lastSignIn || '',
    ]),
  );
}

function exportAppsCsv() {
  if (!scanResults?.apps) return;
  const ts = new Date().toISOString().slice(0, 10);
  const rows = scanResults.apps.map(a => {
    const earliestExpiry = (a.credentialAlerts || [])
      .filter(c => c.expiryDate)
      .map(c => c.expiryDate)
      .sort()[0] || '';
    return [
      a.displayName,
      a.source === 'registration' ? 'App Registration' : 'Service Principal',
      a.appType || '',
      a.signInAudience || '',
      a.passkeyCompatible ? 'Yes' : 'No',
      a.severity || '',
      a.issues.join('; '),
      a.secretCount || 0,
      a.certCount || 0,
      earliestExpiry,
      a.ownerCount ?? '',
      a.isOrphaned ? 'Yes' : 'No',
      a.multiTenant ? 'Yes' : 'No',
      a.createdDateTime ? a.createdDateTime.slice(0, 10) : '',
      a.fixGuide || '',
    ];
  });
  // Append expiry-sorted credential alerts as a separate block
  const credRows = [];
  scanResults.apps.forEach(a => {
    (a.credentialAlerts || []).forEach(c => {
      credRows.push([a.displayName, c.label, c.type, c.severity, c.expiryDate || '', c.daysLeft ?? '', c.ageDays ?? '']);
    });
  });
  if (credRows.length > 0) {
    rows.push([]);
    rows.push(['--- CREDENTIAL EXPIRY DETAIL ---']);
    rows.push(['App', 'Credential', 'Type', 'Severity', 'Expiry Date', 'Days Left', 'Age (days)']);
    rows.push(...credRows.sort((a, b) => String(a[4]).localeCompare(String(b[4]))));
  }
  downloadCsv(
    `entrapass-apps-${ts}.csv`,
    ['App Name', 'Source', 'App Type', 'Sign-in Audience', 'Compatible', 'Severity', 'Issues', 'Secrets', 'Certs', 'Earliest Expiry', 'Owner Count', 'Orphaned', 'Multi-tenant', 'Created', 'Fix Guide'],
    rows,
  );
}

function exportPoliciesCsv() {
  if (!scanResults?.policies) return;
  const ts = new Date().toISOString().slice(0, 10);
  const rows = [
    ...scanResults.policies.map(p => [
      p.displayName, p.state || '', p.type || '',
      p.enforcesPasskey ? 'Yes' : 'No',
      p.blocksPasskeyRegistration ? 'Yes' : 'No',
      p.protectsRegistration ? 'Yes' : 'No',
      p.strengthName || '',
      p.allUsers ? 'All Users' : (p.includeRoles ? 'Roles' : p.includeGroups ? 'Groups' : 'Specific'),
      p.fixGuide || '',
    ]),
  ];
  if ((scanResults.policyGaps || []).length > 0) {
    rows.push([]);
    rows.push(['--- GAPS & RECOMMENDATIONS ---']);
    rows.push(['Severity', 'Title', 'Recommendation', 'Doc URL']);
    (scanResults.policyGaps || []).forEach(g =>
      rows.push([g.severity, g.title, g.recommendation, g.docUrl || ''])
    );
  }
  downloadCsv(
    `entrapass-policies-${ts}.csv`,
    ['Policy Name', 'State', 'Role', 'Enforces Passkey', 'Blocks Passkey', 'Protects Registration', 'Auth Strength', 'Scope', 'Fix Guide'],
    rows,
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
  const hero    = document.getElementById('overview-hero');
  const prescan = document.getElementById('overview-prescan');
  if (!hero) return;

  // Always derive counts from the actual user list.
  // Pre-computed summary fields (pr.capable etc.) can be 0 from stale sessionStorage
  // even when the users[] have real statuses — so never trust the summaries.
  const pr    = r.passkeyReadiness;
  const users = pr.users || [];
  const cnt   = s => users.filter(u => u.status === s).length;
  const total    = users.length;
  const ready    = cnt('ready');
  const capable  = cnt('capable');
  const needsPrep = cnt('needsPrep');
  const blocked  = cnt('blocked');
  const exempt   = cnt('exempt');

  const scoreRaw    = r.readinessScore;          // null when no scorable users exist
  const score       = scoreRaw ?? 0;             // used for arc geometry only when null
  const noScore     = scoreRaw === null;
  const scoreClass  = noScore ? 'score-neutral' : (score >= 70 ? 'score-good' : score >= 40 ? 'score-warn' : 'score-danger');
  const sampled     = r.meta && r.meta.usersFound > total;
  const verdictCls  = (noScore || sampled) ? 'neutral' : (score >= 70 ? 'good' : score >= 40 ? 'warn' : 'danger');
  const verdictText = noScore
    ? ('No scorable users' + (sampled ? ' (sampled)' : ''))
    : ((score >= 70
        ? (ready > 0 ? 'Passkeys in use · rolling out' : 'Infrastructure ready · start rollout')
        : score >= 40 ? 'Preparation underway' : 'Action required') + (sampled ? ' (sampled)' : ''));
  const ringColor   = noScore ? 'var(--border-subtle)' : (score >= 70 ? 'var(--good)' : score >= 40 ? 'var(--accent)' : 'var(--danger)');
  const circ        = 2 * Math.PI * 50;
  const targetOff   = noScore ? circ : circ * (1 - score / 100);

  // Infrastructure status signals for ring card
  const fido2Ok  = r.fido2Config?.state === 'enabled';
  const tapOk    = r.tapConfig?.state   === 'enabled';
  const appRisks = (r.apps || []).filter(a => !a.passkeyCompatible).length;
  const critGaps = (r.policyGaps || []).filter(g => g.severity === 'critical' || g.severity === 'high').length;

  // Breakdown bar proportions — avoid division by zero
  const B = total > 0 ? total : 1;
  const barSegs = [
    { cls: 'rbar-ready',     val: ready,     tip: `Ready: ${ready}`          },
    { cls: 'rbar-capable',   val: capable,   tip: `Capable: ${capable}`      },
    { cls: 'rbar-needsprep', val: needsPrep, tip: `Needs Prep: ${needsPrep}` },
    { cls: 'rbar-blocked',   val: blocked,   tip: `Blocked: ${blocked}`      },
    { cls: 'rbar-exempt',    val: exempt,    tip: `Exempt: ${exempt}`        },
  ].filter(s => s.val > 0);
  const barHtml = barSegs.map(s =>
    `<div class="rbar-seg ${s.cls}" style="flex:${Math.round(s.val / B * 100)}" title="${s.tip}"></div>`
  ).join('');

  hero.innerHTML = `
    <div class="score-ring-card">
      <div class="ring-brand">
        <img src="/aboutcloud_logo.png" alt="Aboutcloud" class="ring-brand-logo">
        <span class="ring-brand-name">Aboutcloud EntraPass</span>
      </div>
      <div class="ring-label">${(sampled && !noScore) ? 'Sample Readiness Score' : 'Readiness Score'}</div>
      ${sampled ? `<div class="sample-notice">Score is computed on the first 50 users returned by Graph. The figure is indicative on tenants with more than 50 users; the CSV export captures the per-user detail for the analysed sample.</div>` : ''}
      <div class="ring-svg-wrapper">
        <svg width="128" height="128" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="50" fill="none" stroke="var(--border-subtle)" stroke-width="9" stroke-linecap="round"/>
          <circle cx="60" cy="60" r="50" fill="none" stroke="${ringColor}" stroke-width="9"
            stroke-dasharray="${circ.toFixed(1)}" stroke-dashoffset="${circ.toFixed(1)}"
            stroke-linecap="round" class="ring-progress" id="ring-arc"
            style="filter:drop-shadow(0 0 7px ${ringColor})"/>
        </svg>
        <div class="ring-center-text">
          <span class="ring-score-number ${scoreClass}" id="ring-score-num">${noScore ? '—' : '0'}</span>
          <span class="ring-score-sub">${noScore ? '' : '/ 100'}</span>
        </div>
      </div>
      <span class="score-verdict ${verdictCls}">${verdictText}</span>
      <div class="score-infra-chips">
        <span class="infra-chip ${fido2Ok ? 'chip-good' : 'chip-danger'}">${fido2Ok ? '✓' : '✗'} FIDO2</span>
        <span class="infra-chip ${tapOk   ? 'chip-good' : 'chip-warn'}">${tapOk   ? '✓' : '⚠'} TAP</span>
        ${appRisks > 0 ? `<span class="infra-chip chip-warn">⚠ ${appRisks} app risk${appRisks !== 1 ? 's' : ''}</span>` : ''}
        ${critGaps > 0 ? `<span class="infra-chip chip-danger">✗ ${critGaps} gap${critGaps !== 1 ? 's' : ''}</span>` : ''}
      </div>
    </div>

    <div class="hero-right">
      <div class="stat-tiles stat-tiles-5">
        <div class="stat-tile total">
          <div class="stat-tile-value">${escapeHtml(String(total))}</div>
          <div class="stat-tile-label">Users scanned</div>
          <div class="stat-tile-sub">${sampled ? `of ${escapeHtml(String(r.meta.usersFound))} (sampled)` : 'full coverage'}</div>
        </div>
        <div class="stat-tile good">
          <div class="stat-tile-value">${escapeHtml(String(ready))}</div>
          <div class="stat-tile-label">Passkey registered</div>
          <div class="stat-tile-sub">${total > 0 ? Math.round(ready / total * 100) : 0}% of users</div>
        </div>
        <div class="stat-tile capable">
          <div class="stat-tile-value">${escapeHtml(String(capable))}</div>
          <div class="stat-tile-label">Capable</div>
          <div class="stat-tile-sub">Can self-register today</div>
        </div>
        <div class="stat-tile warn">
          <div class="stat-tile-value">${escapeHtml(String(needsPrep))}</div>
          <div class="stat-tile-label">Needs prep</div>
          <div class="stat-tile-sub">One gap to resolve</div>
        </div>
        <div class="stat-tile danger">
          <div class="stat-tile-value">${escapeHtml(String(blocked))}</div>
          <div class="stat-tile-label">Blocked</div>
          <div class="stat-tile-sub">Admin action required</div>
        </div>
        ${exempt > 0 ? `<div class="stat-tile exempt">
          <div class="stat-tile-value">${escapeHtml(String(exempt))}</div>
          <div class="stat-tile-label">Exempt</div>
          <div class="stat-tile-sub">Break-glass / guest / MSA</div>
        </div>` : ''}
      </div>
      ${total > 0 ? `<div class="readiness-bar-block">
        <div class="readiness-breakdown-bar">${barHtml}</div>
        <div class="rbar-legend">
          ${ready    > 0 ? `<span class="rbl ready">✅ Ready (${ready})</span>`          : ''}
          ${capable  > 0 ? `<span class="rbl capable">🟢 Capable (${capable})</span>`   : ''}
          ${needsPrep > 0 ? `<span class="rbl needsprep">🟡 Prep (${needsPrep})</span>` : ''}
          ${blocked  > 0 ? `<span class="rbl blocked">🔴 Blocked (${blocked})</span>`   : ''}
          ${exempt   > 0 ? `<span class="rbl exempt">⚪ Exempt (${exempt})</span>`       : ''}
        </div>
      </div>` : ''}
    </div>`;

  hero.classList.remove('hidden');
  if (prescan) prescan.classList.add('hidden');

  // Animate arc fill + counter together
  requestAnimationFrame(() => requestAnimationFrame(() => {
    const arc     = document.getElementById('ring-arc');
    const scoreEl = document.getElementById('ring-score-num');
    if (arc) arc.style.strokeDashoffset = targetOff.toFixed(1);
    if (scoreEl && !noScore) {
      const start    = performance.now();
      const duration = 1100;
      (function tick(now) {
        const t     = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - t, 3);
        scoreEl.textContent = Math.round(score * eased);
        if (t < 1) requestAnimationFrame(tick);
      })(performance.now());
    }
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
      docUrl: 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths',
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
  if (meta.registrationReportAvailable === false) {
    const reason = meta.registrationReportReason || 'unknown';
    const detail = reason === 'permission_denied'
      ? ' — ensure the scanning account has the Reports Reader role (or equivalent). '
        + 'See <a href="https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity" target="_blank" rel="noopener noreferrer">Authentication Methods Activity: Permissions and licenses</a>.'
      : ` (${escapeHtml(reason)}).`;
    html += '<div class="notice notice-warn"><strong>Registration data unavailable.</strong> '
      + 'The authentication methods activity report could not be read' + detail
      + ' Users are classified as "Unknown" and excluded from the readiness score.</div>';
  } else if (meta.partialDataCount > 0) {
    html += '<div class="notice notice-info">'
      + escapeHtml(String(meta.partialDataCount))
      + ' user(s) have incomplete sign-in or registration data. '
      + 'Their status is shown as "Unknown" and excluded from the readiness score.</div>';
  }
  if (html) { el.innerHTML = html; el.classList.remove('hidden'); }
  else { el.classList.add('hidden'); el.innerHTML = ''; }
}



function renderUserCard(u) {
  const STATUS_CFG = {
    ready:     { cls: 'ready',      label: 'Ready',       icon: '✅' },
    capable:   { cls: 'capable',    label: 'Capable',     icon: '🟢' },
    needsPrep: { cls: 'needs-prep', label: 'Needs Prep',  icon: '🟡' },
    blocked:   { cls: 'blocked',    label: 'Blocked',     icon: '🔴' },
    exempt:    { cls: 'exempt',     label: 'Exempt',      icon: '⚪' },
    unknown:   { cls: 'unknown',    label: 'Unknown',     icon: '❓' },
  };
  const ACCT_CFG = {
    member:          { label: 'Member',        cls: 'member' },
    guest:           { label: 'Guest',         cls: 'guest'  },
    personal:        { label: 'Personal',       cls: 'msa'    },
    breakglass:      { label: 'Break-glass',   cls: 'bg'     },
  };

  const sc = STATUS_CFG[u.status]     || { cls: 'blocked', label: u.status || 'Unknown', icon: '❓' };
  const ac = ACCT_CFG[u.accountType]  || { label: u.accountType, cls: '' };

  const authChips = (u.authMethodTypes || []).map(m =>
    `<span class="auth-chip auth-chip-${escapeHtml(m.type)}">${escapeHtml(m.label)}</span>`
  ).join('');

  const issueChips = u.issues
    .filter(i => !i.includes('Passkey / FIDO2 registered'))
    .map(i => `<span class="user-issue-chip">${escapeHtml(i)}</span>`)
    .join('');

  const namedGroups = (u.groups || []).filter(Boolean);
  const groupsSummary = namedGroups.length > 0
    ? namedGroups.slice(0, 3).join(', ') + (namedGroups.length > 3 ? ` +${namedGroups.length - 3}` : '')
    : null;

  const lastSignInDisplay = u.signInActivityAvailable === false
    ? 'Data unavailable'
    : (u.lastSignIn
        ? new Date(u.lastSignIn).toLocaleDateString('en-GB', { year: 'numeric', month: 'short', day: 'numeric' })
        : 'Not recorded');

  const searchText = `${(u.displayName || '').toLowerCase()} ${(u.userPrincipalName || '').toLowerCase()}`;

  const actionBoxCls = u.status === 'ready'  ? 'user-action-box-ready'
    : u.status === 'exempt' ? 'user-action-box-exempt'
    : '';

  return `<div class="user-card user-card-${escapeHtml(sc.cls)}"
              data-status="${escapeHtml(u.status)}"
              data-search-text="${escapeHtml(searchText)}">
    <div class="user-card-header">
      <div class="user-card-identity">
        <span class="user-card-upn">${escapeHtml(u.userPrincipalName || u.displayName || '')}</span>
        ${u.displayName && u.displayName !== u.userPrincipalName
          ? `<span class="user-card-name">${escapeHtml(u.displayName)}</span>` : ''}
      </div>
      <div class="user-card-badges">
        <span class="user-status-badge user-status-${escapeHtml(sc.cls)}">${sc.icon} ${sc.label}</span>
        <span class="user-account-badge acct-${escapeHtml(ac.cls)}">${escapeHtml(ac.label)}</span>
        ${u.isPrivileged    ? `<span class="user-flag-badge flag-privileged">⚡ Privileged</span>` : ''}
        ${u.isStale === true ? `<span class="user-flag-badge flag-stale">⏰ Stale</span>`         : ''}
      </div>
    </div>
    ${issueChips ? `<div class="user-issue-chips">${issueChips}</div>` : ''}
    ${u.recommendedAction ? `<div class="user-action-box ${actionBoxCls}">
      <span class="user-action-label">${u.status === 'ready' ? 'Next step' : u.status === 'exempt' ? 'Guidance' : 'Recommended action'}</span>
      <span class="user-action-text">${escapeHtml(u.recommendedAction)}</span>
    </div>` : ''}
    <div class="user-card-meta">
      <div class="user-meta-chips">
        ${authChips
          ? authChips
          : u.registrationDataAvailable === false
            ? '<span class="user-meta-empty meta-unavailable">Registration data unavailable</span>'
            : '<span class="user-meta-empty">No auth methods recorded</span>'}
      </div>
      <div class="user-meta-info">
        ${u.deviceSummary
          ? `<span class="user-meta-item">💻 ${escapeHtml(u.deviceSummary)}</span>`
          : `<span class="user-meta-item meta-missing">No device</span>`}
        <span class="user-meta-item${u.isStale ? ' meta-stale' : ''}">🕐 ${escapeHtml(lastSignInDisplay)}</span>
        ${groupsSummary ? `<span class="user-meta-item">👥 ${escapeHtml(groupsSummary)}</span>` : ''}
      </div>
    </div>
  </div>`;
}

function renderReadiness(r) {
  const pr    = r.passkeyReadiness;
  const users = pr.users || [];
  const el    = document.getElementById('readiness-table');
  if (!el) return;

  // Always derive from the actual user list — pre-computed summaries can be stale.
  const cnt = (s) => users.filter(u => u.status === s).length;
  const total     = users.length;
  const ready     = cnt('ready');
  const capable   = cnt('capable');
  const needsPrep = cnt('needsPrep');
  const blocked   = cnt('blocked');
  const exempt    = cnt('exempt');
  const unknown   = cnt('unknown');

  // ── Narrative ──────────────────────────────────────────────────────────────
  let h = `<div class="readiness-narrative">
    <div class="readiness-narrative-icon">🔑</div>
    <div class="readiness-narrative-body">
      <strong>Passkey readiness is personal.</strong>
      Every identity sits at a different point on the passkey journey — shaped by which MFA methods are registered,
      which devices are enrolled, and which Conditional Access policies apply to them.
      This view classifies each user so you know exactly <em>who</em> can self-enroll today, <em>who</em> needs one thing fixed first,
      and <em>who</em> requires a direct admin action before onboarding can begin.
      Break-glass, guest, and personal Microsoft accounts are classified separately — they follow a different guidance path
      and should never be mixed into passkey rollout metrics.
      <span class="readiness-narrative-tip">Showing ${escapeHtml(String(total))} user${total !== 1 ? 's' : ''} (sampled).${unknown > 0 ? ` ${escapeHtml(String(unknown))} user${unknown !== 1 ? 's' : ''} could not be scored — verify the scanning account has the Reports Reader role so the authentication methods activity report can be fetched.` : ''}</span>
    </div>
  </div>`;

  // ── Summary strip ──────────────────────────────────────────────────────────
  h += `<div class="policy-summary readiness-summary">
    <div class="policy-stat-item" role="button" tabindex="0" data-filter="all" title="Show all users">
      <span class="psi-value">${escapeHtml(String(total))}</span>
      <span class="psi-label">Total users</span>
    </div>
    <div class="policy-stat-item ${ready > 0 ? 'good' : ''}" role="button" tabindex="0" data-filter="ready" title="Filter: Ready">
      <span class="psi-value">${escapeHtml(String(ready))}</span>
      <span class="psi-label">Ready</span>
    </div>
    <div class="policy-stat-item ${capable > 0 ? 'good' : ''}" role="button" tabindex="0" data-filter="capable" title="Filter: Capable">
      <span class="psi-value">${escapeHtml(String(capable))}</span>
      <span class="psi-label">Capable</span>
    </div>
    <div class="policy-stat-item ${needsPrep > 0 ? 'warn' : ''}" role="button" tabindex="0" data-filter="needsPrep" title="Filter: Needs Prep">
      <span class="psi-value">${escapeHtml(String(needsPrep))}</span>
      <span class="psi-label">Needs Prep</span>
    </div>
    <div class="policy-stat-item ${blocked > 0 ? 'danger' : ''}" role="button" tabindex="0" data-filter="blocked" title="Filter: Blocked">
      <span class="psi-value">${escapeHtml(String(blocked))}</span>
      <span class="psi-label">Blocked</span>
    </div>
    ${exempt > 0 ? `<div class="policy-stat-item" role="button" tabindex="0" data-filter="exempt" title="Filter: Exempt">
      <span class="psi-value">${escapeHtml(String(exempt))}</span>
      <span class="psi-label">Exempt</span>
    </div>` : ''}
    ${unknown > 0 ? `<div class="policy-stat-item" role="button" tabindex="0" data-filter="unknown" title="Filter: Unknown (data unavailable)">
      <span class="psi-value">${escapeHtml(String(unknown))}</span>
      <span class="psi-label">Unknown</span>
    </div>` : ''}
  </div>`;

  // ── Suggested rollout order ────────────────────────────────────────────────
  // (This is an EntraPass rollout recommendation — not an official Microsoft framework.)
  h += `<div class="phase-planner">
    <div class="phase-planner-label">Suggested rollout order — based on your scan data</div>
    <div class="phase-planner-track">
      <div class="phase-item phase-1">
        <div class="phase-num">Start here</div>
        <div class="phase-name">Capable users</div>
        <div class="phase-detail">Have MFA + compatible device. Can self-register at <strong>aka.ms/mysecurityinfo</strong> today — no admin prep required.</div>
        <div class="phase-count ${capable > 0 ? 'good' : ''}">${escapeHtml(String(capable))} user${capable !== 1 ? 's' : ''}</div>
      </div>
      <div class="phase-connector">→</div>
      <div class="phase-item phase-2">
        <div class="phase-num">Then</div>
        <div class="phase-name">Needs Prep</div>
        <div class="phase-detail">One gap blocks self-registration. Admin: issue a <strong>Temporary Access Pass</strong> or enrol a compatible device first.</div>
        <div class="phase-count ${needsPrep > 0 ? 'warn' : ''}">${escapeHtml(String(needsPrep))} user${needsPrep !== 1 ? 's' : ''}</div>
      </div>
      <div class="phase-connector">→</div>
      <div class="phase-item phase-3">
        <div class="phase-num">Last</div>
        <div class="phase-name">Blocked</div>
        <div class="phase-detail">Multiple gaps or CA policy blocker. Admin must resolve each issue before passkey registration is possible.</div>
        <div class="phase-count ${blocked > 0 ? 'danger' : ''}">${escapeHtml(String(blocked))} user${blocked !== 1 ? 's' : ''}</div>
      </div>
    </div>
  </div>`;

  // ── Filter pills + search ─────────────────────────────────────────────────
  h += `<div class="readiness-filter-bar">
    <button class="readiness-pill active" data-filter="all">All (${escapeHtml(String(total))})</button>
    <button class="readiness-pill" data-filter="ready">✅ Ready (${escapeHtml(String(ready))})</button>
    <button class="readiness-pill" data-filter="capable">🟢 Capable (${escapeHtml(String(capable))})</button>
    <button class="readiness-pill" data-filter="needsPrep">🟡 Needs Prep (${escapeHtml(String(needsPrep))})</button>
    <button class="readiness-pill" data-filter="blocked">🔴 Blocked (${escapeHtml(String(blocked))})</button>
    ${exempt  > 0 ? `<button class="readiness-pill" data-filter="exempt">⚪ Exempt (${escapeHtml(String(exempt))})</button>` : ''}
    ${unknown > 0 ? `<button class="readiness-pill" data-filter="unknown">❓ Unknown (${escapeHtml(String(unknown))})</button>` : ''}
    <input type="text" id="readiness-search" class="readiness-search" placeholder="Search by name or UPN…" autocomplete="off">
  </div>`;

  // ── User cards ────────────────────────────────────────────────────────────
  if (users.length === 0) {
    h += `<div class="readiness-empty">No users found. Run a full scan to populate readiness data.</div>`;
  } else {
    const SORT = { blocked: 0, needsPrep: 1, capable: 2, ready: 3, unknown: 4, exempt: 5 };
    const sorted = [...users].sort((a, b) => {
      const d = (SORT[a.status] ?? 5) - (SORT[b.status] ?? 5);
      if (d !== 0) return d;
      return (b.isPrivileged ? 1 : 0) - (a.isPrivileged ? 1 : 0);
    });
    h += `<div id="readiness-user-list">`;
    sorted.forEach(u => { h += renderUserCard(u); });
    h += `</div>`;
  }

  el.innerHTML = h;

  // Wire filter pills + search
  const pills   = el.querySelectorAll('.readiness-pill');
  const searchEl = document.getElementById('readiness-search');
  const listEl  = document.getElementById('readiness-user-list');

  function applyFilter() {
    const active = el.querySelector('.readiness-pill.active')?.dataset.filter || 'all';
    const q = (searchEl?.value || '').toLowerCase().trim();
    listEl?.querySelectorAll('.user-card')?.forEach(card => {
      const matchFilter = active === 'all' || card.dataset.status === active;
      const matchSearch = !q || (card.dataset.searchText || '').includes(q);
      card.classList.toggle('hidden', !(matchFilter && matchSearch));
    });
  }

  pills.forEach(pill => {
    pill.addEventListener('click', () => {
      pills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      applyFilter();
      syncReadinessTiles(pill.dataset.filter);
    });
  });
  if (searchEl) searchEl.addEventListener('input', applyFilter);

  // Wire summary tiles → filter pills
  const readinessTiles = el.querySelectorAll('.readiness-summary .policy-stat-item[data-filter]');
  function syncReadinessTiles(f) {
    readinessTiles.forEach(t => t.classList.toggle('active', t.dataset.filter === f));
  }
  readinessTiles.forEach(tile => {
    tile.addEventListener('click', () => {
      const f = tile.dataset.filter;
      pills.forEach(p => p.classList.remove('active'));
      const target = el.querySelector(`.readiness-pill[data-filter="${f}"]`);
      if (target) { target.classList.add('active'); applyFilter(); }
      syncReadinessTiles(f);
    });
    tile.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); tile.click(); } });
  });
  syncReadinessTiles('all');

  const btn = document.getElementById('btn-export-readiness');
  if (btn) { btn.classList.remove('hidden'); btn.onclick = exportReadinessCsv; }
}

function renderAppTypeBadge(type) {
  const labels = { spa: 'SPA', web: 'Web App', daemon: 'Daemon / Service', api: 'API', native: 'Native / Mobile' };
  return `<span class="app-type-badge ${escapeHtml(type || 'api')}">${escapeHtml(labels[type] || type || 'Unknown')}</span>`;
}

function renderAppCard(app) {
  const issueChips = app.issues.map(issue => {
    const isCred = /secret|certif|expir|expired/i.test(issue);
    return `<span class="app-issue-chip ${isCred ? 'cred' : 'config'}">${escapeHtml(issue)}</span>`;
  }).join('');

  let credHtml = '';
  if (app.credentialAlerts && app.credentialAlerts.length > 0) {
    credHtml = `<div class="app-cred-alerts">`;
    app.credentialAlerts.forEach(c => {
      const icon = c.type === 'expired' ? '⛔' : c.type === 'expiring-soon' ? '🔴' : c.type === 'expiring' ? '🟡' : '⚪';
      const msg = c.type === 'expired'
        ? `${c.label}: expired`
        : c.type === 'stale'
          ? `${c.label}: ${Math.floor(c.ageDays / 365)}yr old — rotate recommended`
          : `${c.label}: expires in ${c.daysLeft} day${c.daysLeft !== 1 ? 's' : ''}`;
      credHtml += `<span class="app-cred-alert ${escapeHtml(c.severity)}">${icon} ${escapeHtml(msg)}</span>`;
    });
    credHtml += `</div>`;
  }

  const metaParts = [];
  metaParts.push(app.source === 'registration' ? 'App registration' : 'Service principal');
  if (app.source === 'registration') {
    metaParts.push(app.isOrphaned ? '⚠ No owners' : `${app.ownerCount} owner${app.ownerCount !== 1 ? 's' : ''}`);
  }
  if (app.createdDateTime) {
    const d = new Date(app.createdDateTime);
    metaParts.push(`Created ${d.toLocaleDateString('en-GB', { year: 'numeric', month: 'short' })}`);
  }

  const multiTag = app.multiTenant
    ? `<span class="app-audience-badge multi">Multi-tenant</span>` : '';

  return `<div class="app-card ${escapeHtml(app.severity)}">
    <div class="app-card-header">
      <div class="app-card-title">
        <span class="app-card-name">${escapeHtml(app.displayName)}</span>
        ${renderAppTypeBadge(app.appType)}${multiTag}
      </div>
      <span class="app-sev-badge ${escapeHtml(app.severity)}">${escapeHtml(app.severity.toUpperCase())}</span>
    </div>
    ${issueChips ? `<div class="app-card-issues">${issueChips}</div>` : ''}
    ${credHtml}
    <p class="app-card-desc">${escapeHtml(app.description)}</p>
    ${app.fixGuide ? `<div class="app-card-fix"><strong>Fix:</strong> ${escapeHtml(app.fixGuide)}</div>` : ''}
    <div class="app-card-meta">${metaParts.map(p => `<span>${escapeHtml(p)}</span>`).join('<span class="app-meta-dot">·</span>')}</div>
  </div>`;
}

function renderApps(r) {
  const apps     = r.apps || [];
  const excluded = r.appsExcludedCount || 0;

  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, good: 4 };
  const flagged  = [...apps].filter(a => !a.passkeyCompatible)
    .sort((a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5));
  const clean    = apps.filter(a => a.passkeyCompatible);

  const critCount   = flagged.filter(a => a.severity === 'critical').length;
  const credExpiry  = apps.filter(a => (a.credentialAlerts || []).some(c => c.severity === 'critical')).length;
  const defaultFilter = flagged.length > 0 ? 'flagged' : 'all';

  // ── Narrative ────────────────────────────────────────────────────────────
  let h = `<div class="app-identity-narrative">
    <div class="app-narrative-icon">🔐</div>
    <div class="app-narrative-body">
      <strong>Every app registration is a non-human identity.</strong>
      Apps can authenticate autonomously — holding their own permissions and accessing tenant data independently of any user.
      When an app uses a <strong>client secret or certificate credential</strong>, it authenticates via the OAuth 2.0 client credentials flow,
      which <strong>bypasses Conditional Access, MFA, and passkey enforcement entirely</strong> — those controls only apply to interactive user sign-ins.
      A leaked app secret is a separate, persistent attack vector that passkeys alone cannot close.
      <span class="app-narrative-tip">This scan covers only custom and third-party apps. Microsoft platform service principals are excluded — they are managed by Microsoft.</span>
    </div>
  </div>`;

  // ── Summary strip ─────────────────────────────────────────────────────────
  h += `<div class="policy-summary app-summary">
    <div class="policy-stat-item" role="button" tabindex="0" data-filter="all" title="Show all apps">
      <span class="psi-value">${apps.length}</span>
      <span class="psi-label">Custom apps scanned</span>
    </div>
    <div class="policy-stat-item ${flagged.length > 0 ? (critCount > 0 ? 'danger' : 'warn') : 'good'}" role="button" tabindex="0" data-filter="flagged" title="Filter: Need attention">
      <span class="psi-value">${flagged.length}</span>
      <span class="psi-label">Need attention</span>
    </div>
    ${credExpiry > 0 ? `<div class="policy-stat-item danger" role="button" tabindex="0" data-filter="flagged" title="Filter: Expiring credentials (in flagged)">
      <span class="psi-value">${credExpiry}</span>
      <span class="psi-label">Expiring credentials</span>
    </div>` : ''}
    <div class="policy-stat-item good" role="button" tabindex="0" data-filter="clean" title="Filter: Clean apps">
      <span class="psi-value">${clean.length}</span>
      <span class="psi-label">Clean</span>
    </div>
  </div>`;

  // ── Filter pills ───────────────────────────────────────────────────────────
  h += `<div class="app-filter-bar">
    <button class="app-filter-pill${defaultFilter === 'all' ? ' active' : ''}" data-filter="all">All (${apps.length})</button>
    <button class="app-filter-pill${defaultFilter === 'flagged' ? ' active' : ''}" data-filter="flagged">Needs Attention (${flagged.length})</button>
    <button class="app-filter-pill" data-filter="clean">Clean (${clean.length})</button>
  </div>`;

  // ── Flagged section ────────────────────────────────────────────────────────
  h += `<div id="apps-flagged"${defaultFilter === 'clean' ? ' class="hidden"' : ''}>`;
  if (flagged.length === 0) {
    h += `<div class="app-empty-state">✅ No issues found across custom app registrations. App credential risk is not blocking your passkey rollout.</div>`;
  } else {
    flagged.forEach(app => { h += renderAppCard(app); });
  }
  h += `</div>`;

  // ── Clean section ─────────────────────────────────────────────────────────
  h += `<div id="apps-clean"${defaultFilter === 'flagged' ? ' class="hidden"' : ''}>`;
  if (clean.length > 0) {
    h += `<div class="apps-section-header">
      <span>✅ Clean apps (${clean.length})</span>
      <span class="apps-section-sub">No credential or compatibility issues detected</span>
    </div>
    <div class="app-clean-list">`;
    clean.forEach(app => {
      h += `<div class="app-clean-row">
        <span class="app-clean-name">${escapeHtml(app.displayName)}</span>
        ${renderAppTypeBadge(app.appType)}
        ${app.multiTenant ? `<span class="app-audience-badge multi">Multi-tenant</span>` : ''}
        <span class="app-clean-source">${app.source === 'registration' ? 'App reg' : 'Service principal'}</span>
      </div>`;
    });
    h += `</div>`;
  } else {
    h += `<div class="app-empty-state">No clean apps to display.</div>`;
  }
  h += `</div>`;

  // ── Excluded footnote ──────────────────────────────────────────────────────
  if (excluded > 0) {
    h += `<div class="app-excluded-note">
      📌 ${excluded} Microsoft platform service principal${excluded !== 1 ? 's' : ''} excluded — managed by Microsoft, not configurable by tenant admins.
    </div>`;
  }

  document.getElementById('apps-table').innerHTML = h;

  // Wire filter pills (post-render)
  const appPills = document.querySelectorAll('.app-filter-pill');
  function applyAppFilter(f) {
    appPills.forEach(p => p.classList.toggle('active', p.dataset.filter === f));
    const flaggedEl = document.getElementById('apps-flagged');
    const cleanEl   = document.getElementById('apps-clean');
    if (flaggedEl) flaggedEl.classList.toggle('hidden', f === 'clean');
    if (cleanEl)   cleanEl.classList.toggle('hidden', f === 'flagged');
  }
  appPills.forEach(pill => {
    pill.addEventListener('click', () => {
      applyAppFilter(pill.dataset.filter);
      syncAppTiles(pill.dataset.filter);
    });
  });

  // Wire app summary tiles → filter pills
  const appTiles = document.querySelectorAll('.app-summary .policy-stat-item[data-filter]');
  function syncAppTiles(f) {
    appTiles.forEach(t => t.classList.toggle('active', t.dataset.filter === f));
  }
  appTiles.forEach(tile => {
    tile.addEventListener('click', () => {
      applyAppFilter(tile.dataset.filter);
      syncAppTiles(tile.dataset.filter);
    });
    tile.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); tile.click(); } });
  });
  syncAppTiles(defaultFilter);

  const btn = document.getElementById('btn-export-apps');
  if (btn) { btn.classList.remove('hidden'); btn.onclick = exportAppsCsv; }
}

const FIDO2_DOCS = {
  setup:        'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key',
  settings:     'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key#fido2-security-key-optional-settings',
  aaguid:       'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-hardware-vendor',
  attestation:  'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key#fido2-security-key-optional-settings',
  tap:          'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass',
  strengths:    'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths',
};

function docLink(url, label) {
  return `<a href="${url}" target="_blank" rel="noopener" class="inspector-doc-link">${label} →</a>`;
}

function renderFido2Inspector(cfg) {
  if (!cfg) {
    return `<div class="fido2-inspector fido2-disabled">
      <div class="fido2-inspector-header">
        <span class="fido2-inspector-title">FIDO2 / Passkey Method Configuration</span>
        <span class="fido2-state-chip disabled">Not configured</span>
      </div>
      <div class="fido2-notice-row">
        <p class="fido2-notice">The FIDO2 security key authentication method was not found in your tenant's Authentication Methods policy. Passkeys cannot be registered or used until it is enabled — this is the prerequisite for all passkey work.</p>
        <div class="inspector-doc-links">
          ${docLink(FIDO2_DOCS.setup, 'Enable FIDO2 security keys')}
          ${docLink(FIDO2_DOCS.aaguid, 'Supported hardware vendors')}
        </div>
      </div>
    </div>`;
  }

  const enabled     = cfg.state === 'enabled';
  const attested    = cfg.isAttestationEnforced === true;
  const kr          = cfg.keyRestrictions || {};
  const isEnforced  = kr.isEnforced === true;
  const enforceType = (kr.enforcementType || 'allow').toLowerCase();
  const aaGuids     = (kr.aaGuids || []).map(g => g.toLowerCase());

  // Covered users label
  const targets   = cfg.includeTargets || [];
  const coversAll = targets.some(t => t.id === 'all_users' || t.id === 'AllUsers');
  const userCoverage = targets.length === 0 ? 'All users (default)'
    : coversAll ? 'All users'
    : `${targets.length} group(s)`;

  // Key restrictions label
  let krLabel = 'None — all authenticators accepted';
  if (isEnforced && aaGuids.length > 0) {
    krLabel = enforceType === 'allow'
      ? `Allow list (${aaGuids.length} AAGUID${aaGuids.length !== 1 ? 's' : ''})`
      : `Block list (${aaGuids.length} AAGUID${aaGuids.length !== 1 ? 's' : ''})`;
  } else if (isEnforced && aaGuids.length === 0) {
    krLabel = enforceType === 'allow' ? 'Allow list (empty — all blocked)' : 'Block list (empty — all allowed)';
  }

  let h = `<div class="fido2-inspector ${enabled ? '' : 'fido2-disabled'}">
    <div class="fido2-inspector-header">
      <span class="fido2-inspector-title">FIDO2 / Passkey Method Configuration</span>
      <div style="display:flex;align-items:center;gap:0.75rem">
        <span class="fido2-state-chip ${enabled ? 'enabled' : 'disabled'}">${enabled ? 'Enabled' : 'Disabled'}</span>
        ${!enabled ? docLink(FIDO2_DOCS.setup, 'How to enable') : docLink(FIDO2_DOCS.settings, 'Settings guide')}
      </div>
    </div>`;

  if (!enabled) {
    h += `<div class="fido2-notice-row">
      <p class="fido2-notice">FIDO2 is disabled in your Authentication Methods policy. Re-enable it to allow passkey registration and authentication in this tenant.</p>
      <div class="inspector-doc-links">
        ${docLink(FIDO2_DOCS.setup, 'Enable FIDO2 security keys')}
        ${docLink(FIDO2_DOCS.aaguid, 'Supported hardware vendors')}
      </div>
    </div>`;
  }

  h += `<div class="fido2-config-row">
    <div class="fido2-config-cell">
      <span class="fido2-config-label">Attestation enforcement</span>
      <span class="fido2-config-value ${attested ? 'good' : 'warn'}">${attested ? '✓ Enforced' : '✗ Not enforced'}</span>
      ${!attested ? `<span class="fido2-config-hint">${docLink(FIDO2_DOCS.attestation, 'Configure attestation')}</span>` : ''}
    </div>
    <div class="fido2-config-cell">
      <span class="fido2-config-label">Key restrictions</span>
      <span class="fido2-config-value ${isEnforced && aaGuids.length > 0 ? 'good' : ''}">${escapeHtml(krLabel)}</span>
      ${!isEnforced ? `<span class="fido2-config-hint">${docLink(FIDO2_DOCS.aaguid, 'Browse certified hardware')}</span>` : ''}
    </div>
    <div class="fido2-config-cell">
      <span class="fido2-config-label">Covered users</span>
      <span class="fido2-config-value">${escapeHtml(userCoverage)}</span>
    </div>
  </div>`;

  if (isEnforced && aaGuids.length > 0) {
    const listLabel = enforceType === 'allow' ? 'Allowed Authenticators' : 'Blocked Authenticators';
    const unknownCount = aaGuids.filter(g => !KNOWN_AAAGUIDS[g]).length;
    h += `<div class="aaguid-section">
      <div class="aaguid-section-header">
        <span class="aaguid-section-label">${listLabel} (${aaGuids.length})</span>
        <span class="aaguid-section-sub">Matched against ${Object.keys(KNOWN_AAAGUIDS).length} known device models${unknownCount > 0 ? ` · ${unknownCount} unrecognised — verify with vendor` : ''}</span>
        ${docLink(FIDO2_DOCS.aaguid, 'AAGUID reference')}
      </div>
      <div class="aaguid-list">`;
    aaGuids.forEach(guid => {
      const known = KNOWN_AAAGUIDS[guid];
      const icon  = known?.type === 'platform' ? '💻' : known ? '🔑' : '❓';
      const name  = known?.name || 'Unknown authenticator';
      const badge = known?.type === 'platform'
        ? `<span class="aaguid-type-badge platform">Platform</span>`
        : known
          ? `<span class="aaguid-type-badge hardware">Hardware</span>`
          : `<span class="aaguid-type-badge unknown">Unrecognised</span>`;
      const vendor = known?.vendor ? `<span class="aaguid-vendor">${escapeHtml(known.vendor)}</span>` : '';
      h += `<div class="aaguid-row">
        <span class="aaguid-icon">${icon}</span>
        <span class="aaguid-name">${escapeHtml(name)}</span>
        ${vendor}${badge}
        <span class="aaguid-guid">${escapeHtml(guid)}</span>
      </div>`;
    });
    h += `</div></div>`;
  } else if (!isEnforced) {
    h += `<div class="fido2-notice-row">
      <p class="fido2-notice">No AAGUID restrictions — any FIDO2-compliant device can be enrolled. For enterprise environments, consider building an allow list from your approved hardware vendor AAGUIDs.</p>
      <div class="inspector-doc-links">
        ${docLink(FIDO2_DOCS.aaguid, 'Browse FIDO2-certified hardware')}
        ${docLink(FIDO2_DOCS.settings, 'Configure key restrictions')}
      </div>
    </div>`;
  } else if (isEnforced && aaGuids.length === 0 && enforceType === 'allow') {
    h += `<div class="fido2-notice-row">
      <p class="fido2-notice warn">Allow list is enforced but empty — no authenticator can currently be enrolled. Add at least one AAGUID to restore passkey registration.</p>
      <div class="inspector-doc-links">
        ${docLink(FIDO2_DOCS.aaguid, 'Find your hardware AAGUID')}
        ${docLink(FIDO2_DOCS.settings, 'Key restriction settings')}
      </div>
    </div>`;
  }

  h += `</div>`;
  return h;
}

function renderTapInspector(cfg) {
  if (!cfg) {
    return `<div class="fido2-inspector tap-inspector fido2-disabled">
      <div class="fido2-inspector-header">
        <span class="fido2-inspector-title">Temporary Access Pass (TAP) Configuration</span>
        <span class="fido2-state-chip disabled">Not configured</span>
      </div>
      <div class="fido2-notice-row">
        <p class="fido2-notice">Temporary Access Pass was not found in your Authentication Methods policy. TAP is required to bootstrap passkey enrollment for users who have no existing MFA method — new hire onboarding, lost credential recovery, and initial registration flows all depend on it.</p>
        <div class="inspector-doc-links">
          ${docLink(FIDO2_DOCS.tap, 'Enable Temporary Access Pass')}
        </div>
      </div>
    </div>`;
  }

  const enabled        = cfg.state === 'enabled';
  const isUsableOnce   = cfg.isUsableOnce === true;
  const defaultLife    = cfg.defaultLifetimeInMinutes  ?? 60;
  const minLife        = cfg.minimumLifetimeInMinutes  ?? 60;
  const maxLife        = cfg.maximumLifetimeInMinutes  ?? 480;
  const targets        = cfg.includeTargets || [];
  const coversAll      = targets.length === 0 || targets.some(t => t.id === 'all_users' || t.id === 'AllUsers');
  const userCoverage   = coversAll ? 'All users' : `${targets.length} group(s)`;
  const longLifetime   = maxLife > 480;

  let h = `<div class="fido2-inspector tap-inspector ${enabled ? '' : 'fido2-disabled'}">
    <div class="fido2-inspector-header">
      <span class="fido2-inspector-title">Temporary Access Pass (TAP) Configuration</span>
      <div style="display:flex;align-items:center;gap:0.75rem">
        <span class="fido2-state-chip ${enabled ? 'enabled' : 'disabled'}">${enabled ? 'Enabled' : 'Disabled'}</span>
        ${docLink(FIDO2_DOCS.tap, enabled ? 'TAP settings guide' : 'How to enable TAP')}
      </div>
    </div>`;

  if (!enabled) {
    h += `<div class="fido2-notice-row">
      <p class="fido2-notice">Temporary Access Pass is disabled. Without TAP, users who have no existing MFA method cannot satisfy a registration CA policy on day one — blocking passkey onboarding for new hires and lost-credential recovery flows.</p>
      <div class="inspector-doc-links">
        ${docLink(FIDO2_DOCS.tap, 'Enable Temporary Access Pass')}
      </div>
    </div>`;
  } else {
    h += `<div class="fido2-config-row">
      <div class="fido2-config-cell">
        <span class="fido2-config-label">Usage policy</span>
        <span class="fido2-config-value ${isUsableOnce ? 'good' : 'warn'}">${isUsableOnce ? '✓ One-time use' : '⚠ Multi-use'}</span>
        ${!isUsableOnce ? `<span class="fido2-config-hint">${docLink(FIDO2_DOCS.tap, 'TAP security guidance')}</span>` : ''}
      </div>
      <div class="fido2-config-cell">
        <span class="fido2-config-label">Default lifetime</span>
        <span class="fido2-config-value ${longLifetime ? 'warn' : ''}">${defaultLife} min</span>
        ${longLifetime ? `<span class="fido2-config-hint" style="color:var(--warn)">Consider reducing — long-lived TAPs increase risk.</span>` : ''}
      </div>
      <div class="fido2-config-cell">
        <span class="fido2-config-label">Lifetime range</span>
        <span class="fido2-config-value">${minLife}–${maxLife} min</span>
      </div>
      <div class="fido2-config-cell">
        <span class="fido2-config-label">Covered users</span>
        <span class="fido2-config-value">${escapeHtml(userCoverage)}</span>
      </div>
    </div>`;

    if (!isUsableOnce) {
      h += `<div class="fido2-notice-row">
        <p class="fido2-notice">Multi-use TAPs carry higher risk — a compromised pass can be reused until it expires. For onboarding flows, set <strong>isUsableOnce = true</strong> and issue TAPs on demand. Reserve multi-use only for break-glass emergency access scenarios.</p>
        <div class="inspector-doc-links">
          ${docLink(FIDO2_DOCS.tap, 'TAP best practices')}
        </div>
      </div>`;
    }
  }

  h += `</div>`;
  return h;
}

function renderPolicies(r) {
  const policies = r.policies || [];
  const gaps     = r.policyGaps    || [];
  const summary  = r.policySummary || {};
  let h = '';

  // ── Summary strip ──────────────────────────────────────────────────────────
  const totalGaps = (summary.criticalGaps || 0) + (summary.highGaps || 0) + gaps.filter(g => g.severity === 'medium').length;
  h += `<div class="policy-summary ca-summary">
    <div class="policy-stat-item" role="button" tabindex="0" data-scroll="policies" title="View all policies">
      <span class="psi-value">${policies.length}</span>
      <span class="psi-label">Policies</span>
    </div>
    <div class="policy-stat-item ${summary.enforcing > 0 ? 'good' : ''}" role="button" tabindex="0" data-scroll="policies" title="View enforcing policies">
      <span class="psi-value">${summary.enforcing || 0}</span>
      <span class="psi-label">Enforcing passkeys</span>
    </div>
    <div class="policy-stat-item ${summary.protecting > 0 ? 'good' : ''}" role="button" tabindex="0" data-scroll="policies" title="View protecting policies">
      <span class="psi-value">${summary.protecting || 0}</span>
      <span class="psi-label">Protecting enrollment</span>
    </div>
    ${summary.blocking > 0 ? `<div class="policy-stat-item danger" role="button" tabindex="0" data-scroll="gaps" title="View blocking policy gaps">
      <span class="psi-value">${summary.blocking}</span>
      <span class="psi-label">Blocking passkeys</span>
    </div>` : ''}
    ${totalGaps > 0 ? `<div class="policy-stat-item ${summary.criticalGaps > 0 ? 'danger' : 'warn'}" role="button" tabindex="0" data-scroll="gaps" title="View detected gaps">
      <span class="psi-value">${totalGaps}</span>
      <span class="psi-label">Gaps detected</span>
    </div>` : `<div class="policy-stat-item good" role="button" tabindex="0" data-scroll="policies" title="No gaps — view policies">
      <span class="psi-value">0</span>
      <span class="psi-label">Gaps detected</span>
    </div>`}
  </div>`;

  // ── Gaps section (FIDO2 + TAP inspectors + gap analysis) ────────────────────
  h += `<div id="ca-section-gaps">`;
  h += renderFido2Inspector(r.fido2Config || null);
  h += renderTapInspector(r.tapConfig || null);
  if (gaps.length > 0) {
    const typeLabels = { missing: 'Missing Policy', config: 'Config Required', 'device-specific': 'Device-Specific', recommended: 'Recommended' };
    h += `<div class="gap-analysis">
      <div class="gap-analysis-header">
        Policy Gaps &amp; Recommendations
        <span class="gap-sub">Derived from your live tenant data</span>
      </div>
      <div class="gap-list">`;
    gaps.forEach(g => {
      const typeTag = typeLabels[g.type] || g.type;
      h += `<div class="gap-card ${escapeHtml(g.severity)}">
        <div class="gap-card-top">
          <span class="gap-sev-badge ${escapeHtml(g.severity)}">${escapeHtml(g.severity.toUpperCase())}</span>
          <span class="gap-type-tag">${escapeHtml(typeTag)}</span>
          <span class="gap-card-title">${escapeHtml(g.title)}</span>
        </div>
        <p class="gap-card-desc">${escapeHtml(g.description)}</p>
        <div class="gap-rec"><strong>Recommendation:</strong> ${escapeHtml(g.recommendation)}</div>
        <div class="gap-card-footer">
          <span class="gap-context">${escapeHtml(g.context)}</span>
          ${g.docUrl ? `<a href="${escapeHtml(g.docUrl)}" target="_blank" rel="noopener" class="gap-doc-link">Learn more →</a>` : ''}
        </div>
      </div>`;
    });
    h += `</div></div>`;
  }
  h += `</div>`;

  // ── Existing policies table ────────────────────────────────────────────────
  h += `<div id="ca-section-policies">`;
  const typeLabels = {
    'enforces-passkey':    'Enforces Passkey',
    'protects-registration': 'Protects Enrollment',
    'blocks-passkey':      'Blocks Passkey',
    'legacy-block':        'Blocks Legacy Auth',
    'risk-based':          'Risk-Based',
    'device-compliance':   'Device Compliance',
    'other':               'Other',
  };
  const stateLabels = {
    enabled: 'Enabled',
    disabled: 'Disabled',
    enabledForReportingButNotEnforced: 'Report-only',
  };

  h += `<div class="existing-policies-label">Conditional Access Policies (${policies.length})</div>`;
  h += `<div class="table-wrapper"><table>
    <thead><tr>
      <th>Policy</th><th>State</th><th>Passkey Role</th><th>Scope</th><th>Auth Strength</th><th>Action</th>
    </tr></thead><tbody>`;

  if (policies.length === 0) {
    h += `<tr><td colspan="6" style="text-align:center;color:var(--text-tertiary);padding:2rem">No CA policies found — or Policy.Read.All not consented.</td></tr>`;
  }

  policies.forEach(p => {
    const typeLabel  = typeLabels[p.type] || 'Other';
    const stateLabel = stateLabels[p.state] || p.state;
    const scope = (() => {
      const { includeUsers = [], includeGroups = [], includeRoles = [] } = p.scopeRaw || {};
      if (includeUsers.includes('All')) return 'All Users';
      const parts = [];
      if (includeRoles.length > 0)  parts.push(`${includeRoles.length} role(s)`);
      if (includeGroups.length > 0) parts.push(`${includeGroups.length} group(s)`);
      if (includeUsers.length > 0 && !includeUsers.includes('All')) parts.push(`${includeUsers.length} user(s)`);
      return parts.join(', ') || 'Unknown';
    })();

    h += `<tr>
      <td style="max-width:220px;font-weight:500">${escapeHtml(p.displayName)}</td>
      <td><span class="state-badge ${escapeHtml(p.state)}">${escapeHtml(stateLabel)}</span></td>
      <td><span class="policy-type-badge ${escapeHtml(p.type)}">${escapeHtml(typeLabel)}</span></td>
      <td style="font-size:0.8rem;color:var(--text-secondary)">${escapeHtml(scope)}</td>
      <td style="font-size:0.8rem;color:var(--text-secondary)">${escapeHtml(p.strengthName || '—')}</td>
      <td style="font-size:0.8rem;color:var(--text-secondary)">${
        p.fixGuide
          ? escapeHtml(p.fixGuide)
          : p.state === 'enabledForReportingButNotEnforced'
            ? `<span style="color:var(--warn);${p.enforcesPasskey || p.protectsRegistration ? 'font-weight:600' : ''}">Report-only — review sign-in impact in Entra ID logs before enforcing.</span> <a href="https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only" target="_blank" rel="noopener" class="inspector-doc-link">Report-only guide →</a>`
            : '<span style="color:var(--text-tertiary)">—</span>'
      }</td>
    </tr>`;
  });

  h += '</tbody></table></div>';
  h += '</div>'; // close ca-section-policies

  document.getElementById('policies-table').innerHTML = h;

  // Wire CA summary tiles → show/hide sections (no scroll)
  function showCaSection(section) {
    const gapsEl     = document.getElementById('ca-section-gaps');
    const policiesEl = document.getElementById('ca-section-policies');
    if (section === 'gaps') {
      gapsEl?.classList.remove('hidden');
      policiesEl?.classList.add('hidden');
    } else {
      gapsEl?.classList.add('hidden');
      policiesEl?.classList.remove('hidden');
    }
  }
  document.querySelectorAll('.ca-summary .policy-stat-item[data-scroll]').forEach(tile => {
    tile.addEventListener('click', () => {
      document.querySelectorAll('.ca-summary .policy-stat-item[data-scroll]').forEach(t => t.classList.remove('active'));
      tile.classList.add('active');
      showCaSection(tile.dataset.scroll);
    });
    tile.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); tile.click(); } });
  });

  const btn = document.getElementById('btn-export-policies');
  if (btn) { btn.classList.remove('hidden'); btn.onclick = exportPoliciesCsv; }
}
