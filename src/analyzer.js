export class Analyzer {
  analyzeAll(data) {
    const passkeyReadiness = this.analyzePasskeyReadiness(data);
    const appCompatibility = this.analyzeAppCompatibility(data);
    const policyAnalysis = this.analyzePolicies(data);
    const toxicCombos = this.findToxicCombinations(passkeyReadiness, data);
    const recommendations = this.generateRecommendations(passkeyReadiness, appCompatibility, policyAnalysis, toxicCombos);
    const narrative = this.generateNarrative(passkeyReadiness, appCompatibility, policyAnalysis, toxicCombos);
    return { passkeyReadiness, apps: appCompatibility, policies: policyAnalysis, toxicCombos, recommendations, narrative, timestamp: new Date().toISOString() };
  }

  analyzePasskeyReadiness({ users, devices, policies }) {
    const result = { total: users.length, ready: 0, needsAttention: 0, blocked: 0, users: [], breakdown: { byDevice: { ready: 0, outdated: 0, none: 0 }, byPolicy: { blocked: 0, allowed: 0 } } };
    const blockingPolicies = policies.filter(p => this.policyBlocksPasskeyRegistration(p));
    users.forEach(user => {
      const issues = [];
      const d = { modernDevice: false, blockedByPolicy: false };
      const am = user.authMethods || [];
      const hasFido = am.some(m => (m.authenticationMethodType||"").toLowerCase().includes("fido") || (m.authenticationMethodType||"").toLowerCase().includes("passkey"));
      const hasMfa = am.length > 0;
      if (!hasMfa) issues.push("No MFA method registered");
      if (hasFido) issues.push("Already has passkey/FIDO2 registered");
      const userDevices = devices.filter(d2 => (d2.registeredOwners || []).some(o => o.id === user.id || o.userPrincipalName === user.userPrincipalName));
      userDevices.forEach(d2 => {
        const osName = (d2.operatingSystem || "").toLowerCase();
        const ver = parseInt(d2.operatingSystemVersion) || 0;
        if ((osName.includes("windows") && ver >= 10) || (osName.includes("ios") && ver >= 16) || (osName.includes("android") && ver >= 14) || (osName.includes("mac") && ver >= 13)) d.modernDevice = true;
      });
      if (d.modernDevice) result.breakdown.byDevice.ready++;
      else if (userDevices.length > 0) result.breakdown.byDevice.outdated++;
      else result.breakdown.byDevice.none++;
      if (!d.modernDevice && userDevices.length > 0) issues.push("Device OS outdated for passkeys");
      if (userDevices.length === 0 && !hasFido) issues.push("No compatible device registered");
      blockingPolicies.forEach(p => {
        if (p.conditions?.users?.includeUsers?.includes("All") || p.conditions?.users?.includeUsers?.includes(user.id)) {
          issues.push("Blocked by CA policy: " + p.displayName);
          d.blockedByPolicy = true;
        }
      });
      if (d.blockedByPolicy) result.breakdown.byPolicy.blocked++;
      else result.breakdown.byPolicy.allowed++;
      let status = "ready";
      if (issues.length > 0) status = d.blockedByPolicy ? "blocked" : "attention";
      result.users.push({ id: user.id, displayName: user.displayName || user.userPrincipalName, userPrincipalName: user.userPrincipalName, status, issues, deviceCount: userDevices.length, authMethodCount: am.length, groups: (user.groups || []).map(g => g.displayName), lastSignIn: user.signInActivity?.lastSuccessfulSignIn || null });
      if (status === "ready") result.ready++;
      else if (status === "attention") result.needsAttention++;
      else result.blocked++;
    });
    return result;
  }

  analyzeAppCompatibility({ apps, servicePrincipals }) {
    const all = [...(apps||[]), ...(servicePrincipals||[])];
    return all.map(app => {
      const issues = [];
      if (app.signInAudience === "AzureADMyOrg" && !app.requiredResourceAccess?.length)
        issues.push("No delegated permissions - may use legacy auth");
      if (app.passwordCredentials?.length > 0)
        issues.push("Has password credentials - not compatible with passkeys");
      if (app.keyCredentials?.length > 0)
        issues.push("Uses certificate-based auth - verify passkey support");
      return { id: app.id, displayName: app.displayName || app.appId || "Unnamed", passkeyCompatible: issues.length === 0, issues, fixGuide: issues.length > 0 ? this.getAppFixGuide(issues) : null };
    }).filter(a => a.displayName !== "Unnamed");
  }

  getAppFixGuide(issues) {
    const guides = [];
    if (issues.some(i => i.includes("password")))
      guides.push("Remove password credentials. Migrate to OAuth 2.0 OIDC with PKCE.");
    if (issues.some(i => i.includes("legacy auth")))
      guides.push("Configure delegated permissions in Azure Portal.");
    return guides.join(" ");
  }

  analyzePolicies({ policies }) {
    return (policies||[]).map(policy => {
      const blocks = this.policyBlocksPasskeyRegistration(policy);
      return { id: policy.id, displayName: policy.displayName, state: policy.state, blocksPasskeyRegistration: blocks, warning: blocks ? "This policy requires password as a grant control, which blocks passkey-only authentication." : null, fixGuide: blocks ? "Create a separate CA policy for passkey-capable users that requires FIDO2 authentication strength instead of password." : null };
    });
  }

  findToxicCombinations(passkeyReadiness, { users, policies }) {
    const combos = [];
    (users||[]).forEach(u => {
      const groups = (u.groups || []).map(g => (g.displayName||"").toLowerCase());
      const isPrivileged = groups.some(g => g.includes("admin") || g.includes("global") || g.includes("privileged") || g.includes("exchange") || g.includes("administrator"));
      if (isPrivileged) {
        const hasFido = (u.authMethods || []).some(m => (m.authenticationMethodType||"").toLowerCase().includes("fido") || (m.authenticationMethodType||"").toLowerCase().includes("passkey"));
        const hasMfa = (u.authMethods || []).length > 0;
        if (!hasFido && !hasMfa) {
          combos.push({ severity: "critical", displayName: u.displayName || u.userPrincipalName, groups: (u.groups||[]).map(g => g.displayName), description: "No MFA and NO passkey on high-privilege account", fix: "Enable MFA immediately. Register passkey/FIDO2 as primary auth method." });
        }
      }
    });
    const vulnerablePolicies = (policies||[]).filter(p => p.state !== "disabled" && p.grantControls?.builtInControls?.includes("password") && p.grantControls?.builtInControls?.includes("mfa"));
    if (vulnerablePolicies.length > 0)
      combos.push({ severity: "high", displayName: "Password fallback enabled", description: vulnerablePolicies.length + " CA policies allow password fallback with passkey.", fix: "Update to require FIDO2 authentication strength." });
    return combos;
  }

  policyBlocksPasskeyRegistration(policy) {
    if (policy.state === "disabled") return false;
    return policy.grantControls?.builtInControls?.includes("password") || false;
  }

  generateRecommendations(passkeyReadiness, appCompatibility, policyAnalysis, toxicCombos) {
    const recs = [];
    toxicCombos.filter(t => t.severity === "critical").forEach(t => recs.push({ severity: "critical", icon: "\U0001F6A8", category: "Security Risk", title: t.displayName, text: t.description, fix: t.fix }));
    policyAnalysis.filter(p => p.blocksPasskeyRegistration).forEach(p => recs.push({ severity: "high", icon: "\U0001F534", category: "Policy", title: "CA policy blocks passkeys: " + p.displayName, text: p.warning || "Blocks passkey registration", fix: p.fixGuide || "Review policy" }));
    if (passkeyReadiness.blocked > 0)
      recs.push({ severity: "high", icon: "\U0001F534", category: "Blocked", title: passkeyReadiness.blocked + " user(s) blocked", text: "Blocked by CA policies or device limitations.", fix: "Address policy and device issues." });
    if (passkeyReadiness.needsAttention > 0)
      recs.push({ severity: "medium", icon: "\U0001F7E1", category: "Attention", title: passkeyReadiness.needsAttention + " user(s) need prep", text: "Devices or MFA need updating.", fix: "Guide users to register modern devices." });
    const badApps = appCompatibility.filter(a => !a.passkeyCompatible);
    if (badApps.length > 0)
      recs.push({ severity: "medium", icon: "\U0001F7E1", category: "Apps", title: badApps.length + " app(s) not compatible", text: badApps.map(a => a.displayName).join(", "), fix: "Review app auth config." });
    if (passkeyReadiness.ready > 0)
      recs.push({ severity: "low", icon: "\U0001F7E2", category: "Ready", title: passkeyReadiness.ready + " user(s) ready!", text: "Start a pilot program.", fix: "Enable passkey for pilot group." });
    if (recs.length === 0)
      recs.push({ severity: "low", icon: "\u2705", category: "All Clear", title: "Tenant is ready!", text: "Great job!", fix: "Proceed with rollout." });
    return recs;
  }

  generateNarrative(passkeyReadiness, appCompatibility, policyAnalysis, toxicCombos) {
    const parts = [];
    parts.push("Tenant has " + passkeyReadiness.total + " users.");
    if (passkeyReadiness.ready > 0) parts.push("Ready: " + passkeyReadiness.ready + " users can use passkeys immediately.");
    if (passkeyReadiness.needsAttention > 0) parts.push("Attention: " + passkeyReadiness.needsAttention + " users need device/MFA updates.");
    if (passkeyReadiness.blocked > 0) parts.push("Blocked: " + passkeyReadiness.blocked + " users blocked by CA policies.");
    if (toxicCombos.length > 0) {
      parts.push("=== ALERTS ===");
      toxicCombos.forEach(t => parts.push(t.severity.toUpperCase() + ": " + t.description));
    }
    if (passkeyReadiness.ready > 0) {
      parts.push("=== ROLLOUT PLAN ===");
      parts.push("Phase 1: Pilot with " + passkeyReadiness.ready + " ready users");
      parts.push("Phase 2: Enable for attention users after updates");
      parts.push("Phase 3: Resolve blocking policies");
      parts.push("Phase 4: Full rollout");
    }
    return parts.join("\n");
  }
}
