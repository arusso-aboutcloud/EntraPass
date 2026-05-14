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
  showLoading('Fetching users, devices, policies, apps, auth methods...');
  try {
    // Phase 1: Get basic data
    const [users, devices, policies, apps, org, sps, authPolicy, authMethodsConfig] = await Promise.all([
      graphApi.getUsers().catch(() => []),
      graphApi.getDevices().catch(() => []),
      graphApi.getConditionalAccessPolicies().catch(() => []),
      graphApi.getApplications().catch(() => []),
      graphApi.getOrganization().catch(() => null),
      graphApi.getServicePrincipals().catch(() => []),
      graphApi.getAuthorizationPolicy().catch(() => ({})),
      graphApi.getAuthenticationMethodsPolicy().catch(() => []),
    ]);

    showLoading('Analyzing authentication methods and device ownership...');

    // Phase 2: Get per-user rich data
    const userDetails = await Promise.all(
      users.slice(0, 50).map(async (u) => {  // Limit to 50 for performance
        const [authMethods, activity, groups] = await Promise.all([
          graphApi.getAuthenticationMethodsForUser(u.id).catch(() => []),
          graphApi.getUserSignInActivity(u.id).catch(() => ({})),
          graphApi.getUserMemberOf(u.id).catch(() => []),
        ]);
        return { ...u, authMethods, signInActivity: activity, groups };
      })
    );

    // Phase 3: Get device ownership
    const deviceDetails = await Promise.all(
      devices.slice(0, 100).map(async (d) => {
        const owners = await graphApi.getDeviceRegisteredOwners(d.id).catch(() => []);
        return { ...d, registeredOwners: owners };
      })
    );

    showLoading('Running AI-powered analysis...');

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

    sessionStorage.setItem('entrapass_results',
      JSON.stringify(scanResults));
    renderDashboard(scanResults);
  } catch (err) {
    console.error('Scan failed:', err);
    alert('Scan failed: ' + err.message);
  }
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
  const el = document.getElementById("summary-content");
  let html = "";

  // Narrative
  if (r.narrative) {
    html += "<div style=\"margin-bottom:1rem;padding:1rem;background:#f8f9fa;border-radius:8px;\">";
    html += "<h3 style=\"margin-bottom:0.5rem;\">Executive Summary</h3>";
    html += "<pre style=\"white-space:pre-wrap;font-family:inherit;font-size:0.95rem;line-height:1.6;margin:0;\">"
      + r.narrative.replace(/\\n/g, "<br>")
      + "</pre></div>";
  }

  // Toxic combos
  if (r.toxicCombos && r.toxicCombos.length > 0) {
    html += "<div style=\"margin-bottom:1rem;\">";
    html += "<h3 style=\"color:#d13438;margin-bottom:0.5rem;\">Toxic Combinations Found</h3>";
    r.toxicCombos.forEach(t => {
      const bg = t.severity === "critical" ? "#fff0f0" : "#fff8f0";
      const border = t.severity === "critical" ? "#d13438" : "#ff8c00";
      html += "<div style=\"background:" + bg + ";border-left:4px solid " + border + ";padding:0.75rem;margin-bottom:0.5rem;border-radius:4px;\">";
      html += "<strong>" + (t.displayName || t.fix) + "</strong><br>";
      html += "<span style=\"font-size:0.9rem;\">" + (t.description || "") + "</span>";
      if (t.fix) html += "<br><span style=\"font-size:0.85rem;color:#666;\">Fix: " + t.fix + "</span>";
      html += "</div>";
    });
    html += "</div>";
  }

  // Recommendations
  html += "<div class=\"summary-list\">";
  if (!r.recommendations || !r.recommendations.length) {
    html += "<p>No issues found.</p>";
  } else {
    r.recommendations.forEach(rec => {
      let icon;
      switch(rec.severity) {
        case "critical": icon = "\ud83d\udea8"; break;
        case "high": icon = "\ud83d\udd34"; break;
        case "medium": icon = "\ud83d\udfe1"; break;
        default: icon = "\ud83d\udfe2";
      }
      html += "<div class=\"recommendation " + rec.severity + "\">";
      html += "<div><span class=\"rec-icon\">" + icon + "</span></div>";
      html += "<div><strong>" + (rec.title || rec.text) + "</strong>";
      if (rec.text && rec.title && rec.text !== rec.title)
        html += "<br><span style=\"font-size:0.9rem;\">" + rec.text + "</span>";
      if (rec.fix) html += "<br><span style=\"font-size:0.85rem;color:#0078d4;\">Fix: " + rec.fix + "</span>";
      html += "</div></div>";
    });
  }
  html += "</div>";
  el.innerHTML = html;
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
  const compatible = r.apps.filter(a => a.passkeyCompatible).length;
  const total = r.apps.length;
  const flagged = total - compatible;

  let h = "";

  // Summary line
  h += "<div style=\"margin-bottom:1rem;font-size:0.95rem;color:var(--text-secondary);\">";
  h += "<span style=\"color:var(--good);\">&#128994; " + compatible + " compatible</span>";
  if (flagged > 0) h += " <span style=\"color:var(--danger);margin-left:0.5rem;\">&#128308; " + flagged + " need review</span>";
  h += " <span style=\"margin-left:0.5rem;\">out of " + total + " apps scanned</span>";
  h += "</div>";

  h += "<div style=\"overflow-x:auto;\">";
  h += "<table><thead><tr><th>App</th><th>Status</th><th>Issues</th><th>Description &amp; Fix</th></tr></thead><tbody>";

  // Sort: flagged apps first, then by severity
  const sorted = [...r.apps].sort((a, b) => {
    const order = { high: 0, medium: 1, low: 2, good: 3, info: 4 };
    return (order[a.severity] || 5) - (order[b.severity] || 5);
  });

  sorted.forEach(a => {
    let badge, statusText;
    if (a.isSubstrate && !a.passkeyCompatible) {
      badge = "&#128196;";
      statusText = "Info";
    } else if (a.passkeyCompatible) {
      badge = "&#128994;";
      statusText = "OK";
    } else {
      badge = "&#128308;";
      statusText = "Flagged";
    }

    const issueText = a.issues.length > 0 ? a.issues.join("; ") : "None";
    const descBg = a.severity === "high" ? "#fff0f0" : a.severity === "medium" ? "#fff8f0" : "#f8f8f8";
    const descBorder = a.severity === "high" ? "var(--danger)" : a.severity === "medium" ? "var(--warn)" : "var(--border)";

    h += "<tr>";
    h += "<td><strong>" + a.displayName + "</strong>" + (a.isSubstrate ? "<br><span style=\"font-size:0.75rem;color:#888;\">Microsoft-managed</span>" : "") + "</td>";
    h += "<td>" + badge + " " + statusText + "</td>";
    h += "<td>" + issueText + "</td>";
    h += "<td style=\"font-size:0.85rem;background:" + descBg + ";border-left:3px solid " + descBorder + ";padding:0.5rem 0.75rem;\">";
    h += "<p style=\"margin-bottom:0.3rem;\">" + a.description + "</p>";
    if (a.fixGuide) h += "<p style=\"margin-top:0.3rem;color:var(--primary);\"><strong>Fix:</strong> " + a.fixGuide + "</p>";
    h += "</td></tr>";
  });

  h += "</tbody></table></div>";
  document.getElementById('apps-table').innerHTML = h;
}
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

