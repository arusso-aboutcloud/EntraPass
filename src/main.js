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

// ============================================
// Bootstrap
// ============================================
window.addEventListener('DOMContentLoaded', async () => {
  setupEventListeners();

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
}

async function sendChat() {
  const input = document.getElementById('chat-input');
  const q = input.value.trim();
  if (!q || !scanResults) return;

  const m = document.getElementById('chat-messages');
  m.innerHTML += `<div class='message user'>${escapeHtml(q)}</div>`;
  input.value = '';
  m.innerHTML += `<div class='message bot'>Thinking...</div>`;
  try {
    const a = await getAiAnswer(q, scanResults);
    m.removeChild(m.lastChild);
    m.innerHTML += `<div class='message bot'>${formatAiAnswer(a)}</div>`;
    m.scrollTop = m.scrollHeight;
  } catch (err) {
    m.removeChild(m.lastChild);
    m.innerHTML += `<div class='message bot error'>Error: ${escapeHtml(err.message)}</div>`;
  }
}

async function getAiAnswer(question, results) {
  const mode = document.getElementById('ai-mode').value;
  if (mode === 'cloudflare') {
    const r = await fetch('/ai/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question, results }),
    });
    if (!r.ok) throw new Error('AI error');
    return (await r.json()).answer;
  }
  if (mode === 'byok') {
    const ep = document.getElementById('ai-endpoint').value.trim().replace(/\/+$/, '');
    const k = document.getElementById('ai-key').value;
    const model = document.getElementById('ai-model').value;
    if (!ep || !k) throw new Error('Configure BYOK');
    const r = await fetch(ep + '/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + k,
      },
      body: JSON.stringify({
        model: model || 'gpt-4o-mini',
        messages: [
          { role: 'system', content: 'You are an Entra ID passkey expert.' },
          { role: 'user', content: `Results: ${JSON.stringify(results)} Q: ${question}` },
        ],
      }),
    });
    if (!r.ok) throw new Error('BYOK error');
    return (await r.json()).choices?.[0]?.message?.content || 'No response';
  }
  return 'AI is off.';
}

// Escapes the model output first, then applies a minimal subset of markdown
// (newlines and bold). Escaping must happen before formatting so an AI
// response cannot inject markup.
function formatAiAnswer(text) {
  return escapeHtml(text)
    .replace(/\n/g, '<br>')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
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
  renderStats(r);
  renderReadiness(r);
  renderApps(r);
  renderPolicies(r);
  renderSummary(r);
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

function renderStats(r) {
  const { total, ready, needsAttention, blocked } = r.passkeyReadiness;
  const sampled = r.meta && r.meta.usersFound > r.meta.usersAnalyzed;
  const totalLabel = sampled ? 'Users Analyzed' : 'Total Users';
  document.getElementById('stats-grid').innerHTML =
    `<div class='stat-card'>
      <div class='stat-value'>${escapeHtml(String(total))}</div>
      <div class='stat-label'>${totalLabel}</div>
    </div>
    <div class='stat-card good'>
      <div class='stat-value'>${escapeHtml(String(ready))}</div>
      <div class='stat-label'>Ready</div>
    </div>
    <div class='stat-card warn'>
      <div class='stat-value'>${escapeHtml(String(needsAttention))}</div>
      <div class='stat-label'>Needs Attention</div>
    </div>
    <div class='stat-card danger'>
      <div class='stat-value'>${escapeHtml(String(blocked))}</div>
      <div class='stat-label'>Blocked</div>
    </div>`;
}

function renderSummary(r) {
  const el = document.getElementById('summary-content');
  let html = '';

  // Narrative
  if (r.narrative) {
    html += '<div style="margin-bottom:1rem;padding:1rem;background:#f8f9fa;border-radius:8px;">';
    html += '<h3 style="margin-bottom:0.5rem;">Executive Summary</h3>';
    html += '<pre style="white-space:pre-wrap;font-family:inherit;font-size:0.95rem;line-height:1.6;margin:0;">'
      + escapeHtml(r.narrative)
      + '</pre></div>';
  }

  // Toxic combinations
  if (r.toxicCombos && r.toxicCombos.length > 0) {
    html += '<div style="margin-bottom:1rem;">';
    html += '<h3 style="color:#d13438;margin-bottom:0.5rem;">Toxic Combinations Found</h3>';
    r.toxicCombos.forEach((t) => {
      const bg = t.severity === 'critical' ? '#fff0f0' : '#fff8f0';
      const border = t.severity === 'critical' ? '#d13438' : '#ff8c00';
      html += '<div style="background:' + bg + ';border-left:4px solid ' + border + ';padding:0.75rem;margin-bottom:0.5rem;border-radius:4px;">';
      html += '<strong>' + escapeHtml(t.displayName || t.fix) + '</strong><br>';
      html += '<span style="font-size:0.9rem;">' + escapeHtml(t.description || '') + '</span>';
      if (t.fix) html += '<br><span style="font-size:0.85rem;color:#666;">Fix: ' + escapeHtml(t.fix) + '</span>';
      html += '</div>';
    });
    html += '</div>';
  }

  // Recommendations
  html += '<div class="summary-list">';
  if (!r.recommendations || !r.recommendations.length) {
    html += '<p>No issues found.</p>';
  } else {
    r.recommendations.forEach((rec) => {
      let icon;
      switch (rec.severity) {
        case 'critical': icon = '\u{1F6A8}'; break;
        case 'high': icon = '\u{1F534}'; break;
        case 'medium': icon = '\u{1F7E1}'; break;
        default: icon = '\u{1F7E2}';
      }
      html += '<div class="recommendation ' + escapeHtml(rec.severity) + '">';
      html += '<div><span class="rec-icon">' + icon + '</span></div>';
      html += '<div><strong>' + escapeHtml(rec.title || rec.text) + '</strong>';
      if (rec.text && rec.title && rec.text !== rec.title)
        html += '<br><span style="font-size:0.9rem;">' + escapeHtml(rec.text) + '</span>';
      if (rec.fix) html += '<br><span style="font-size:0.85rem;color:#0078d4;">Fix: ' + escapeHtml(rec.fix) + '</span>';
      html += '</div></div>';
    });
  }
  html += '</div>';
  el.innerHTML = html;
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
}

function renderApps(r) {
  const compatible = r.apps.filter((a) => a.passkeyCompatible).length;
  const total = r.apps.length;
  const flagged = total - compatible;

  let h = '';
  h += '<div style="margin-bottom:1rem;font-size:0.95rem;color:var(--text-secondary);">';
  h += '<span style="color:var(--good);">\u{1F7E2} ' + escapeHtml(String(compatible)) + ' compatible</span>';
  if (flagged > 0) h += ' <span style="color:var(--danger);margin-left:0.5rem;">\u{1F534} ' + escapeHtml(String(flagged)) + ' need review</span>';
  h += ' <span style="margin-left:0.5rem;">out of ' + escapeHtml(String(total)) + ' apps scanned</span>';
  h += '</div>';

  h += '<div style="overflow-x:auto;">';
  h += '<table><thead><tr><th>App</th><th>Status</th><th>Issues</th><th>Description &amp; Fix</th></tr></thead><tbody>';

  const order = { high: 0, medium: 1, low: 2, good: 3, info: 4 };
  const sorted = [...r.apps].sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));

  sorted.forEach((a) => {
    let badge, statusText;
    if (a.isSubstrate && !a.passkeyCompatible) {
      badge = '\u{1F4C4}';
      statusText = 'Info';
    } else if (a.passkeyCompatible) {
      badge = '\u{1F7E2}';
      statusText = 'OK';
    } else {
      badge = '\u{1F534}';
      statusText = 'Flagged';
    }

    const issueText = a.issues.length > 0 ? a.issues.join('; ') : 'None';
    const descBg = a.severity === 'high' ? '#fff0f0' : a.severity === 'medium' ? '#fff8f0' : '#f8f8f8';
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
  document.getElementById('apps-table').innerHTML = h;
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
}
