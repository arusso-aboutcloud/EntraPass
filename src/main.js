import { PublicClientApplication } from '@azure/msal-browser';
import { GraphAPI } from './graph.js';
import { Analyzer } from './analyzer.js';

const msalConfig = {
  auth: {
    clientId: import.meta.env.VITE_CLIENT_ID
      || '885e7b72-5a73-44d7-9b42-bdd0e33b01f6',
    authority: 'https://login.microsoftonline.com/'
      + (import.meta.env.VITE_TENANT_ID
        || '0b259eac-5a5e-4c47-bc9f-f29ed875b165'),
    redirectUri: window.location.origin,
  },
  cache: { cacheLocation: 'sessionStorage', storeAuthStateInCookie: false },
};

const loginRequest = {
  scopes: [
    'User.Read', 'User.Read.All', 'Device.Read.All',
    'Policy.Read.All', 'Application.Read.All',
    'AuditLog.Read.All', 'Organization.Read.All',
  ],
};

let msalInstance = null;
let graphApi = null;
let analyzer = null;
let scanResults = null;

window.addEventListener('DOMContentLoaded', async () => {
  msalInstance = new PublicClientApplication(msalConfig);
  await msalInstance.initialize();
  await msalInstance.handleRedirectPromise().catch(() => null);
  const accounts = msalInstance.getAllAccounts();
  if (accounts.length > 0) await initializeApp(accounts[0]);
  else showAuthScreen();
});

window.signIn = async () => {
  try { await msalInstance.loginRedirect(loginRequest); }
  catch (err) { console.error(err); alert('Sign-in failed.'); }
};

window.signOut = () => msalInstance.logoutRedirect({
  postLogoutRedirectUri: window.location.origin,
});

async function initializeApp(account) {
  msalInstance.setActiveAccount(account);
  graphApi = new GraphAPI(msalInstance, loginRequest.scopes);
  analyzer = new Analyzer();
  document.getElementById('auth-screen').classList.add('hidden');
  document.getElementById('dashboard').classList.remove('hidden');
  document.getElementById('user-info').textContent = account.username;
  try {
    const org = await graphApi.getOrganization();
    document.getElementById('tenant-name').textContent
      = org.displayName || 'Tenant';
  } catch { document.getElementById('tenant-name').textContent = 'Connected'; }
  const cached = sessionStorage.getItem('entrapass_results');
  if (cached) {
    try {
      scanResults = JSON.parse(cached);
      renderDashboard(scanResults);
    } catch (e) {}
  }
}

function showAuthScreen() {
  document.getElementById('auth-screen').classList.remove('hidden');
  document.getElementById('dashboard').classList.add('hidden');
}

window.startScan = async () => {
  const btn = document.getElementById('scan-btn');
  btn.disabled = true;
  btn.textContent = 'Scanning...';
  showLoading('Scanning...');
  try {
    const [u, d, p, a, o] = await Promise.all([
      graphApi.getUsers().catch(() => []),
      graphApi.getDevices().catch(() => []),
      graphApi.getConditionalAccessPolicies().catch(() => []),
      graphApi.getApplications().catch(() => []),
      graphApi.getOrganization().catch(() => null),
    ]);
    scanResults = analyzer.analyzeAll({
      users: u, devices: d, policies: p, apps: a, org: o,
    });
    sessionStorage.setItem('entrapass_results',
      JSON.stringify(scanResults));
    renderDashboard(scanResults);
  } catch (err) { alert('Scan failed: ' + err.message); }
  finally {
    hideLoading();
    btn.disabled = false;
    btn.textContent = 'Scan Tenant Now';
  }
};
window.switchTab = (tabName) => {
  document.querySelectorAll('.tab').forEach(
    t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(
    t => t.classList.add('hidden'));
  document.querySelector(
    `.tab[data-tab='${tabName}']`)
    .classList.add('active');
  document.getElementById(
    `tab-${tabName}`)
    .classList.remove('hidden');
};

window.toggleAiMode = () => {
  const mode = document.getElementById('ai-mode').value;
  document.getElementById('byok-config')
    .classList.toggle('hidden', mode !== 'byok');
  document.getElementById('ai-chat')
    .classList.toggle('hidden', mode === 'off');
};

window.sendChat = async () => {
  const input = document.getElementById('chat-input');
  const q = input.value.trim();
  if (!q || !scanResults) return;
  const m = document.getElementById('chat-messages');
  m.innerHTML += `<div class='message user'>${q}</div>`;
  input.value = '';
  m.innerHTML += `<div class='message bot'>Thinking...</div>`;
  try {
    const a = await getAiAnswer(q, scanResults);
    m.removeChild(m.lastChild);
    m.innerHTML += `<div class='message bot'>${formatAiAnswer(a)}</div>`;
    m.scrollTop = m.scrollHeight;
  } catch (err) {
    m.removeChild(m.lastChild);
    m.innerHTML += `<div class='message bot error'>Error: ${err.message}</div>`;
  }
};

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
    const ep = document.getElementById('ai-endpoint').value;
    const k = document.getElementById('ai-key').value;
    const m = document.getElementById('ai-model').value;
    if (!ep || !k) throw new Error('Configure BYOK');
    const r = await fetch(ep + '/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + k,
      },
      body: JSON.stringify({
        model: m || 'gpt-4o-mini',
        messages: [
          { role: 'system',
            content: 'You are an Entra ID passkey expert.' },
          { role: 'user',
            content: `Results: ${JSON.stringify(results)}`
              + `Q: ${question}` },
        ],
      }),
    });
    if (!r.ok) throw new Error('BYOK error');
    return (await r.json()).choices?.[0]?.message?.content
      || 'No response';
  }
  return 'AI is off.';
}

function formatAiAnswer(t) {
  return t.replace(/\\n/g, '<br>')
    .replace(/\\*\\*(.*?)\\*\\*/g,
      '<strong>$1</strong>');
}

function showLoading(t) {
  document.getElementById('loading-text').textContent
    = t || 'Loading...';
  document.getElementById('loading-overlay')
    .classList.remove('hidden');
}

function hideLoading() {
  document.getElementById('loading-overlay')
    .classList.add('hidden');
}

function renderDashboard(r) {
  renderStats(r);
  renderReadiness(r);
  renderApps(r);
  renderPolicies(r);
  renderSummary(r);
}

function renderStats(r) {
  const { total, ready, needsAttention, blocked }
    = r.passkeyReadiness;
  document.getElementById('stats-grid').innerHTML
    = `<div class='stat-card'>\
      <div class='stat-value'>${total}</div>\
      <div class='stat-label'>Total Users</div>\
    </div>\
    <div class='stat-card good'>\
      <div class='stat-value'>${ready}</div>\
      <div class='stat-label'>Ready</div>\
    </div>\
    <div class='stat-card warn'>\
      <div class='stat-value'>${needsAttention}</div>\
      <div class='stat-label'>Needs Attention</div>\
    </div>\
    <div class='stat-card danger'>\
      <div class='stat-value'>${blocked}</div>\
      <div class='stat-label'>Blocked</div>\
    </div>`;
}

function renderSummary(r) {
  let h = '<div class="summary-list">';
  if (!r.recommendations.length) {
    h += '<p>No issues found.</p>';
  } else {
    r.recommendations.slice(0,5).forEach(rec => {
      const ic = rec.severity === 'high'
        ? '&#128308;'
        : rec.severity === 'medium'
        ? '&#128993;'
        : '&#128994;';
      h += `<div class='recommendation ${rec.severity}'>\
        <span class='rec-icon'>${ic}</span>\
        <span class='rec-text'>${rec.text}</span>\
      </div>`;
    });
  }
  h += '</div>';
  document.getElementById('summary-content').innerHTML = h;
}

function renderReadiness(r) {
  const { users } = r.passkeyReadiness;
  let h = '<table><thead><tr>' + '<th>User</th><th>Status</th><th>Issues</th></tr></thead><tbody>';
  users.forEach(u => {
    const ic = u.status === 'ready' ? '&#128994;'
      : u.status === 'attention' ? '&#128993;' : '&#128308;';
    h += `<tr>\
      <td>${u.displayName}</td>\
      <td>${ic} ${u.status}</td>\
      <td>${u.issues.join(', ') || 'None'}</td>\
    </tr>`;
  });
  h += '</tbody></table>';
  document.getElementById('readiness-table').innerHTML = h;
}

function renderApps(r) {
  let h = '<table><thead><tr>' + '<th>App</th><th>Passkey</th><th>Issue</th></tr></thead><tbody>';
  r.apps.forEach(a => {
    const ok = a.passkeyCompatible ? '&#128994; Yes' : '&#128308; No';
    h += `<tr>\
      <td>${a.displayName}</td>\
      <td>${ok}</td>\
      <td>${a.passkeyIssue || 'None'}</td>\
    </tr>`;
  });
  h += '</tbody></table>';
  document.getElementById('apps-table').innerHTML = h;
}

function renderPolicies(r) {
  let h = '<table><thead><tr>' + '<th>Policy</th><th>Blocks Passkeys?</th><th>Action</th></tr></thead><tbody>';
  r.policies.forEach(p => {
    const blk = p.blocksPasskeyRegistration ? '&#128308; Yes' : '&#128994; No';
    h += `<tr>\
      <td>${p.displayName}</td>\
      <td>${blk}</td>\
      <td>${p.recommendation || 'None'}</td>\
    </tr>`;
  });
  h += '</tbody></table>';
  document.getElementById('policies-table').innerHTML = h;
}
