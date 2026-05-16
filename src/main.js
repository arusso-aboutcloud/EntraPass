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

function renderFido2Inspector(cfg) {
  if (!cfg) {
    return `<div class="fido2-inspector fido2-disabled">
      <div class="fido2-inspector-header">
        <span class="fido2-inspector-title">FIDO2 / Passkey Method Configuration</span>
        <span class="fido2-state-chip disabled">Not configured</span>
      </div>
      <p class="fido2-notice">The FIDO2 authentication method was not found in your tenant's Authentication Methods policy. Enable it before proceeding with passkey deployment.</p>
    </div>`;
  }

  const enabled     = cfg.state === 'enabled';
  const attested    = cfg.isAttestationEnforced === true;
  const kr          = cfg.keyRestrictions || {};
  const isEnforced  = kr.isEnforced === true;
  const enforceType = (kr.enforcementType || 'allow').toLowerCase();
  const aaGuids     = (kr.aaGuids || []).map(g => g.toLowerCase());

  // Covered users label
  const targets = cfg.includeTargets || [];
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
    krLabel = enforceType === 'allow'
      ? 'Allow list (empty — all blocked)'
      : 'Block list (empty — all allowed)';
  }

  let h = `<div class="fido2-inspector ${enabled ? '' : 'fido2-disabled'}">
    <div class="fido2-inspector-header">
      <span class="fido2-inspector-title">FIDO2 / Passkey Method Configuration</span>
      <span class="fido2-state-chip ${enabled ? 'enabled' : 'disabled'}">${enabled ? 'Enabled' : 'Disabled'}</span>
    </div>
    <div class="fido2-config-row">
      <div class="fido2-config-cell">
        <span class="fido2-config-label">Attestation enforcement</span>
        <span class="fido2-config-value ${attested ? 'good' : 'warn'}">${attested ? '✓ Enforced' : '✗ Not enforced'}</span>
      </div>
      <div class="fido2-config-cell">
        <span class="fido2-config-label">Key restrictions</span>
        <span class="fido2-config-value ${isEnforced && aaGuids.length > 0 ? 'good' : ''}">${escapeHtml(krLabel)}</span>
      </div>
      <div class="fido2-config-cell">
        <span class="fido2-config-label">Covered users</span>
        <span class="fido2-config-value">${escapeHtml(userCoverage)}</span>
      </div>
    </div>`;

  if (isEnforced && aaGuids.length > 0) {
    const listLabel = enforceType === 'allow' ? 'Allowed Authenticators' : 'Blocked Authenticators';
    h += `<div class="aaguid-section">
      <div class="aaguid-section-header">
        <span class="aaguid-section-label">${listLabel} (${aaGuids.length})</span>
        <span class="aaguid-section-sub">Matched against ${Object.keys(KNOWN_AAAGUIDS).length} known device models</span>
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
        ${vendor}
        ${badge}
        <span class="aaguid-guid">${escapeHtml(guid)}</span>
      </div>`;
    });
    h += `</div></div>`;
  } else if (!isEnforced) {
    h += `<p class="fido2-notice">No AAGUID restrictions — any FIDO2-compliant device (hardware keys, platform passkeys, software authenticators) can be enrolled by users.</p>`;
  } else if (isEnforced && aaGuids.length === 0 && enforceType === 'allow') {
    h += `<p class="fido2-notice warn">Allow list is enforced but empty — no authenticator can currently be enrolled. Add at least one AAGUID to unblock registration.</p>`;
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
  h += `<div class="policy-summary">
    <div class="policy-stat-item">
      <span class="psi-value">${policies.length}</span>
      <span class="psi-label">Policies</span>
    </div>
    <div class="policy-stat-item ${summary.enforcing > 0 ? 'good' : ''}">
      <span class="psi-value">${summary.enforcing || 0}</span>
      <span class="psi-label">Enforcing passkeys</span>
    </div>
    <div class="policy-stat-item ${summary.protecting > 0 ? 'good' : ''}">
      <span class="psi-value">${summary.protecting || 0}</span>
      <span class="psi-label">Protecting enrollment</span>
    </div>
    ${summary.blocking > 0 ? `<div class="policy-stat-item danger">
      <span class="psi-value">${summary.blocking}</span>
      <span class="psi-label">Blocking passkeys</span>
    </div>` : ''}
    ${totalGaps > 0 ? `<div class="policy-stat-item ${summary.criticalGaps > 0 ? 'danger' : 'warn'}">
      <span class="psi-value">${totalGaps}</span>
      <span class="psi-label">Gaps detected</span>
    </div>` : `<div class="policy-stat-item good">
      <span class="psi-value">0</span>
      <span class="psi-label">Gaps detected</span>
    </div>`}
  </div>`;

  // ── FIDO2 method inspector ────────────────────────────────────────────────
  h += renderFido2Inspector(r.fido2Config || null);

  // ── Gap analysis ───────────────────────────────────────────────────────────
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

  // ── Existing policies table ────────────────────────────────────────────────
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
      <td style="font-size:0.8rem;color:var(--text-secondary)">${p.fixGuide ? escapeHtml(p.fixGuide) : '<span style="color:var(--text-tertiary)">—</span>'}</td>
    </tr>`;
  });

  h += '</tbody></table></div>';

  document.getElementById('policies-table').innerHTML = h;
  const btn = document.getElementById('btn-export-policies');
  if (btn) { btn.classList.remove('hidden'); btn.onclick = exportPoliciesCsv; }
}
