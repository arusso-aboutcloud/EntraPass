/**
 * EntraPass AI Worker (Cloudflare Workers)
 *
 * Optional AI assistant for passkey migration questions. The browser SPA can
 * POST scan results here when the user opts into "Cloudflare Free AI" mode.
 *
 * Configuration (wrangler.toml [vars] or dashboard):
 *   ALLOWED_ORIGIN  - the exact origin of the EntraPass site allowed to call
 *                     this worker (e.g. "https://entrapass.pages.dev"). If
 *                     unset, requests are rejected — the worker is not a
 *                     public, unauthenticated AI relay.
 */

// Reject request bodies larger than this (scan results for a sampled tenant
// are well under 1 MB; anything larger is almost certainly abuse).
const MAX_BODY_BYTES = 512 * 1024;

function corsHeaders(env, request) {
  const allowed = (env && env.ALLOWED_ORIGIN) || '';
  const origin = request.headers.get('Origin') || '';
  const headers = {
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin',
  };
  // Only echo the origin back if it matches the configured allowlist.
  if (allowed && origin === allowed) {
    headers['Access-Control-Allow-Origin'] = allowed;
  }
  return headers;
}

function json(body, status, extraHeaders) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...(extraHeaders || {}) },
  });
}

export default {
  async fetch(request, env) {
    const cors = corsHeaders(env, request);

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: cors });
    }
    if (request.method !== 'POST') {
      return json({ error: 'Method not allowed' }, 405, cors);
    }
    // Block requests from origins that are not on the allowlist.
    if (!cors['Access-Control-Allow-Origin']) {
      return json({ error: 'Origin not allowed' }, 403, cors);
    }

    // Enforce a body size limit before reading the payload.
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

    const { question, results } = payload || {};
    if (!question || typeof question !== 'string') {
      return json({ error: 'Question is required' }, 400, cors);
    }

    // Reduce the scan results to a compact, non-identifying summary before
    // sending anything to the model.
    const summary = results ? {
      totalUsers: results.passkeyReadiness?.total || 0,
      readyUsers: results.passkeyReadiness?.ready || 0,
      blockedUsers: results.passkeyReadiness?.blocked || 0,
      attentionUsers: results.passkeyReadiness?.needsAttention || 0,
      recommendations: (results.recommendations || []).map((r) => r.title || r.text),
    } : {};

    const systemPrompt = 'You are a Microsoft Entra ID passkey migration expert. '
      + 'Answer concisely with actionable advice based on the scan data. '
      + 'Keep responses under 200 words.';
    const userPrompt = `Scan results: ${JSON.stringify(summary)}\n\nIT admin question: ${question}`;

    let answer;
    try {
      const aiResp = await env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt },
        ],
        max_tokens: 500,
      });
      answer = aiResp.response || 'I could not generate a response.';
    } catch (aiError) {
      console.error('AI error:', aiError);
      answer = generateRuleBasedResponse(question, summary);
    }

    return json({ answer }, 200, cors);
  },
};

function generateRuleBasedResponse(question, summary) {
  const q = question.toLowerCase();

  if (q.includes('ready') || q.includes('readiness')) {
    return `Based on your scan: ${summary.readyUsers} users are ready, `
      + `${summary.attentionUsers} need attention, and ${summary.blockedUsers} are blocked. `
      + 'Focus on unblocking users first by reviewing CA policies.';
  }
  if (q.includes('block') || q.includes('ca policy')) {
    return 'Check your Conditional Access policies that require "password" as a grant control. '
      + 'These block passkey-only authentication. Consider adding a separate policy for '
      + 'passkey-capable users.';
  }
  if (q.includes('recommend') || q.includes('first')) {
    if (summary.recommendations && summary.recommendations.length > 0) {
      return 'Top recommendation: ' + summary.recommendations[0];
    }
    return 'Your tenant looks good! Start a pilot with your ready users.';
  }
  if (q.includes('pilot') || q.includes('rollout')) {
    return 'Recommended phased rollout: 1) Pilot with the IT team (ready users), '
      + '2) Enable passkey registration for all, 3) Gradually require passkey for sensitive apps, '
      + '4) Monitor sign-in logs for failures.';
  }
  return 'I can help with passkey readiness, CA policy analysis, app compatibility, and '
    + 'rollout planning. Ask me specific questions about your scan results.';
}
