import { PublicClientApplication } from '@azure/msal-browser';
import { GraphAPI } from './graph.js';
import { Analyzer } from './analyzer.js';

// ============================================
// MSAL Configuration (PKCE - SPA)
// ============================================
const msalConfig = {
  auth: {
    clientId: import.meta.env.VITE_CLIENT_ID || '885e7b72-5a73-44d7-9b42-bdd0e33b01f6',
    authority: 'https://login.microsoftonline.com/' + (import.meta.env.VITE_TENANT_ID || '0b259eac-5a5e-4c47-bc9f-f29ed875b165'),
    redirectUri: window.location.origin,
  },
  cache: {
    cacheLocation: 'sessionStorage',
    storeAuthStateInCookie: false,
  },
};

const loginRequest = {
  scopes: [
    'User.Read',
    'User.Read.All',
    'Device.Read.All',
    'Policy.Read.All',
    'Application.Read.All',
    'AuditLog.Read.All',
    'Organization.Read.All',
  ],
};

let msalInstance = null;
let graphApi = null;
let analyzer = null;
let scanResults = null;

// ============================================
// Initialize
// ============================================
window.addEventListener('DOMContentLoaded', async () => {
  msalInstance = new PublicClientApplication(msalConfig);
  await msalInstance.initialize();
  
  // Handle redirect promise
  const resp = await msalInstance.handleRedirectPromise().catch(() => null);
  
  const accounts = msalInstance.getAllAccounts();
  if (accounts.length > 0) {
    await initializeApp(accounts[0]);
  } else {
    showAuthScreen();
  }
});

// ============================================
// Auth Functions (PKCE)
// ============================================
window.signIn = async function() {
  try {
    await msalInstance.loginRedirect(loginRequest);
  } catch (err) {
    console.error('Sign-in failed:', err);
    alert('Sign-in failed. Please try again.');
  }
};

window.signOut = function() {
  msalInstance.logoutRedirect({
    postLogoutRedirectUri: window.location.origin,
  });
};

async function initializeApp(account) {
  msalInstance.setActiveAccount(account);
  
  graphApi = new GraphAPI(msalInstance, loginRequest.scopes);
  analyzer = new Analyzer();
  
  // Show dashboard
  document.getElementById('auth-screen').classList.add('hidden');
  document.getElementById('dashboard').classList.remove('hidden');
  
  // Set user info
  document.getElementById('user-info').textContent = account.username;
  
  // Get tenant name
  try {
    const org = await graphApi.getOrganization();
    document.getElementById('tenant-name').textContent = org.displayName || 'Unknown Tenant';
  } catch (e) {
    document.getElementById('tenant-name').textContent = 'Connected';
  }
  
  // Check if we have cached results
  const cached = sessionStorage.getItem('entrapass_results');
  if (cached) {
    try {
      scanResults = JSON.parse(cached);
      renderDashboard(scanResults);
    } catch (e) {
      // ignore
    }
  }
}

function showAuthScreen() {
  document.getElementById('auth-screen').classList.remove('hidden');
  document.getElementById('dashboard').classList.add('hidden');
}

// ============================================
// Scan Functions
// ============================================
window.startScan = async function() {
  const btn = document.getElementById('scan-btn');
  btn.disabled = true;
  btn.textContent = '? Scanning...';
  
  showLoading('Scanning users, devices, policies, and applications...');
  
  try {
    const token = await getToken();
    
    // Fetch all data in parallel
    const [users, devices, policies, apps, org] = await Promise.all([
      graphApi.getUsers().catch(e => { console.error('Users fetch failed:', e); return []; }),
      graphApi.getDevices().catch(e => { console.error('Devices fetch failed:', e); return []; }),
      graphApi.getConditionalAccessPolicies().catch(e => { console.error('Policies fetch failed:', e); return []; }),
      graphApi.getApplications().catch(e => { console.error('Apps fetch failed:', e); return []; }),
      graphApi.getOrganization().catch(e => { console.error('Org fetch failed:', e); return null; }),
    ]);
    
    // Analyze
    scanResults = analyzer.analyzeAll({ users, devices, policies, apps, org });
    
    // Cache in session storage (browser-only, no server)
    sessionStorage.setItem('entrapass_results', JSON.stringify(scanResults));
    
    renderDashboard(scanResults);
    
  } catch (err) {
    console.error('Scan failed:', err);
    alert('Scan failed: ' + err.message);
  } finally {
    hideLoading();
    btn.disabled = false;
    btn.textContent = '?? Scan Tenant Now';
  }
};

async function getToken() {
  const account = msalInstance.getActiveAccount();
  if (!account) throw new Error('No active account');
  
  const resp = await msalInstance.acquireTokenSilent({
    scopes: loginRequest.scopes,
    account,
  });
  return resp.accessToken;
}

// ============================================
// Tab Switching
// ============================================
window.switchTab = function(tabName) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.add('hidden'));
  
  document.querySelector(.tab[data-tab=""]).classList.add('active');
  document.getElementById(	ab-).classList.remove('hidden');
};

// ============================================
// AI Functions
// ============================================
window.toggleAiMode = function() {
  const mode = document.getElementById('ai-mode').value;
  document.getElementById('byok-config').classList.toggle('hidden', mode !== 'byok');
  document.getElementById('ai-chat').classList.toggle('hidden', mode === 'off');
};

window.sendChat = async function() {
  const input = document.getElementById('chat-input');
  const question = input.value.trim();
  if (!question || !scanResults) return;
  
  const messages = document.getElementById('chat-messages');
  messages.innerHTML += <div class="message user"></div>;
  input.value = '';
  
  messages.innerHTML += <div class="message bot">Thinking...</div>;
  
  try {
    const answer = await getAiAnswer(question, scanResults);
    messages.removeChild(messages.lastChild);
    messages.innerHTML += <div class="message bot"></div>;
    messages.scrollTop = messages.scrollHeight;
  } catch (err) {
    messages.removeChild(messages.lastChild);
    messages.innerHTML += <div class="message bot error">Error: </div>;
  }
};

async function getAiAnswer(question, results) {
  const mode = document.getElementById('ai-mode').value;
  
  if (mode === 'cloudflare') {
    // Call Cloudflare AI Worker
    const resp = await fetch('/ai/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question, results }),
    });
    if (!resp.ok) throw new Error('AI request failed');
    const data = await resp.json();
    return data.answer;
  } else if (mode === 'byok') {
    const endpoint = document.getElementById('ai-endpoint').value;
    const key = document.getElementById('ai-key').value;
    const model = document.getElementById('ai-model').value;
    
    if (!endpoint || !key) throw new Error('Please configure BYOK endpoint and key');
    
    const resp = await fetch(endpoint + '/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + key,
      },
      body: JSON.stringify({
        model: model || 'gpt-4o-mini',
        messages: [
          { role: 'system', content: 'You are a Microsoft Entra ID passkey migration expert. Answer concisely based on the scan results.' },
          { role: 'user', content: Scan results: \n\nQuestion:  }
        ],
      }),
    });
    if (!resp.ok) throw new Error('BYOK request failed');
    const data = await resp.json();
    return data.choices?.[0]?.message?.content || 'No response';
  }
  
  return 'AI is off. Enable AI mode above.';
}

function formatAiAnswer(text) {
  return text.replace(/\\n/g, '<br>').replace(/\\*\\*(.*?)\\*\\*/g, '<strong></strong>');
}

// ============================================
// Loading Overlay
// ============================================
function showLoading(text) {
  document.getElementById('loading-text').textContent = text || 'Loading...';
  document.getElementById('loading-overlay').classList.remove('hidden');
}

function hideLoading() {
  document.getElementById('loading-overlay').classList.add('hidden');
}

// ============================================
// Render Dashboard
// ============================================
function renderDashboard(results) {
  renderStats(results);
  renderReadiness(results);
  renderApps(results);
  renderPolicies(results);
  renderSummary(results);
}

function renderStats(results) {
  const grid = document.getElementById('stats-grid');
  const { total, ready, needsAttention, blocked } = results.passkeyReadiness;
  
  grid.innerHTML = 
    <div class="stat-card">
      <div class="stat-value"></div>
      <div class="stat-label">Total Users</div>
    </div>
    <div class="stat-card good">
      <div class="stat-value"></div>
      <div class="stat-label">Ready for Passkeys</div>
    </div>
    <div class="stat-card warn">
      <div class="stat-value"></div>
      <div class="stat-label">Needs Attention</div>
    </div>
    <div class="stat-card danger">
      <div class="stat-value"></div>
      <div class="stat-label">Blocked</div>
    </div>
  ;
}

function renderSummary(results) {
  const div = document.getElementById('summary-content');
  
  let html = '<div class="summary-list">';
  
  if (results.recommendations.length === 0) {
    html += '<p>No specific recommendations. Your tenant looks good!</p>';
  } else {
    results.recommendations.slice(0, 5).forEach(rec => {
      const icon = rec.severity === 'high' ? '??' : rec.severity === 'medium' ? '??' : '??';
      html += <div class="recommendation ">
        <span class="rec-icon"></span>
        <span class="rec-text"></span>
      </div>;
    });
  }
  
  html += '</div>';
  div.innerHTML = html;
}

function renderReadiness(results) {
  const table = document.getElementById('readiness-table');
  const { users } = results.passkeyReadiness;
  
  let html = '<table><thead><tr><th>User</th><th>Status</th><th>Issues</th></tr></thead><tbody>';
  
  users.forEach(u => {
    const icon = u.status === 'ready' ? '??' : u.status === 'attention' ? '??' : '??';
    html += <tr>
      <td></td>
      <td> </td>
      <td></td>
    </tr>;
  });
  
  html += '</tbody></table>';
  table.innerHTML = html;
}

function renderApps(results) {
  const table = document.getElementById('apps-table');
  const { apps } = results;
  
  let html = '<table><thead><tr><th>App</th><th>Passkey Compatible</th><th>Issue</th></tr></thead><tbody>';
  
  apps.forEach(a => {
    const icon = a.passkeyCompatible ? '?? Yes' : '?? No';
    html += <tr>
      <td></td>
      <td></td>
      <td></td>
    </tr>;
  });
  
  html += '</tbody></table>';
  table.innerHTML = html;
}

function renderPolicies(results) {
  const table = document.getElementById('policies-table');
  const { policies } = results;
  
  let html = '<table><thead><tr><th>Policy Name</th><th>Blocks Passkeys?</th><th>Action</th></tr></thead><tbody>';
  
  policies.forEach(p => {
    const icon = p.blocksPasskeyRegistration ? '?? Yes' : '?? No';
    html += <tr>
      <td></td>
      <td></td>
      <td></td>
    </tr>;
  });
  
  html += '</tbody></table>';
  table.innerHTML = html;
}
