/**
 * EntraPass AI Worker (Cloudflare Workers)
 * Optional AI assistant for passkey migration questions
 * Users can bring their own key or use Cloudflare free tier
 */

export default {
  async fetch(request, env) {
    // Handle CORS
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
        },
      });
    }

    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405 });
    }

    try {
      const { question, results } = await request.json();

      if (!question) {
        return new Response(JSON.stringify({ error: 'Question is required' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // Prepare context from scan results
      const summary = results ? {
        totalUsers: results.passkeyReadiness?.total || 0,
        readyUsers: results.passkeyReadiness?.ready || 0,
        blockedUsers: results.passkeyReadiness?.blocked || 0,
        attentionUsers: results.passkeyReadiness?.needsAttention || 0,
        recommendations: results.recommendations || [],
      } : {};

      // Use Cloudflare AI (free tier with Llama or other model)
      const systemPrompt = 'You are a Microsoft Entra ID passkey migration expert. Answer concisely with actionable advice based on the scan data. Keep responses under 200 words.';
      const userPrompt = Scan Results: \n\nIT Admin Question: ;

      // Try Cloudflare AI first, fallback to rule-based response
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

      return new Response(JSON.stringify({ answer }), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      });

    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  },
};

function generateRuleBasedResponse(question, summary) {
  const q = question.toLowerCase();
  
  if (q.includes('ready') || q.includes('readiness')) {
    return \Based on your scan: \ users are ready, \ need attention, and \ are blocked. Focus on unblocking users first by reviewing CA policies.\;
  }
  
  if (q.includes('block') || q.includes('ca policy')) {
    return 'Check your Conditional Access policies that require "password" as a grant control. These block passkey-only authentication. Consider adding a separate policy for passkey-capable users.';
  }
  
  if (q.includes('recommend') || q.includes('first')) {
    if (summary.recommendations?.length > 0) {
      return 'Top recommendation: ' + summary.recommendations[0].text;
    }
    return 'Your tenant looks good! Start a pilot with your ready users.';
  }
  
  if (q.includes('pilot') || q.includes('rollout')) {
    return 'Recommend phased rollout: 1) Pilot with IT team (ready users), 2) Enable passkey registration for all, 3) Gradually require passkey for sensitive apps, 4) Monitor sign-in logs for failures.';
  }
  
  return 'I can help with passkey readiness, CA policy analysis, app compatibility, and rollout planning. Ask me specific questions about your scan results!';
}
