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

  // A "strong" authentication method is MFA-grade. Password is intentionally
  // excluded: a registered password is not an MFA method, so counting it would
  // make "No MFA method registered" and the toxic-combination checks never fire.
  isStrongAuthMethod(method) {
    const t = (method['@odata.type'] || method.authenticationMethodType || '').toLowerCase();
    return t.includes('fido2')
      || t.includes('passkey')
      || t.includes('windowshelloforbusiness')
      || t.includes('microsoftauthenticator')
      || t.includes('softwareoath')
      || t.includes('phone')
      || t.includes('temporaryaccesspass');
  }

  isPasskeyMethod(method) {
    const t = (method['@odata.type'] || method.authenticationMethodType || '').toLowerCase();
    return t.includes('fido2') || t.includes('passkey');
  }

  analyzePasskeyReadiness({ users, devices, policies }) {
    const result = { total: users.length, ready: 0, needsAttention: 0, blocked: 0, users: [], breakdown: { byDevice: { ready: 0, outdated: 0, none: 0 }, byPolicy: { blocked: 0, allowed: 0 } } };
    const blockingPolicies = policies.filter(p => this.policyBlocksPasskeyRegistration(p));
    users.forEach(user => {
      const issues = [];
      const d = { modernDevice: false, blockedByPolicy: false };
      const am = user.authMethods || [];
      const hasFido = am.some(m => this.isPasskeyMethod(m));
      const hasMfa = am.some(m => this.isStrongAuthMethod(m));
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
      const severity = [];
      let description = "";
      if (app.signInAudience === "AzureADMyOrg" && !app.requiredResourceAccess?.length) {
        issues.push("No delegated permissions - may use legacy auth");
        severity.push("medium");
        description = "This app has no delegated permissions configured. Users signing in with a passkey may be prompted for a password instead, because the app does not request modern token flows.";
      }
      if (app.passwordCredentials?.length > 0) {
        issues.push("Has password credentials");
        severity.push("high");
        description = (description ? description + " " : "") + "Password credentials allow the app to authenticate with a client secret, which bypasses passkey altogether. Users will be prompted for credentials instead of using their passkey.";
      }
      if (app.keyCredentials?.length > 0) {
        issues.push("Uses certificate-based auth");
        severity.push("low");
        description = (description ? description + " " : "") + "Certificate-based authentication can coexist with passkeys, but verify that the app supports FIDO2 token binding.";
      }
      // Classify app source: Microsoft-managed apps arent configurable by the tenant
      const msDomains = ["microsoft.com", "microsoftonline.com", "windows.net", "sharepoint.com", "skype.com", "office.com", "live.com", "azure.com", "graph.microsoft.com"];
      // Microsoft's first-party tenant IDs (service principals carry appOwnerOrganizationId).
      const msTenantIds = ["f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"];
      const domain = (app.publisherDomain || "").toLowerCase();
      const isSubstrate = msDomains.some(d => domain.includes(d))
        || app.signInAudience === "AzureADMultipleOrgs"
        || msTenantIds.includes((app.appOwnerOrganizationId || "").toLowerCase());
      const appSeverity = isSubstrate ? 'info' : (severity.includes('high') ? 'high' : severity.includes('medium') ? 'medium' : severity.includes('low') ? 'low' : 'good');
      return {
        id: app.id,
        displayName: app.displayName || app.appId || 'Unnamed',
        passkeyCompatible: issues.length === 0,
        issues,
        severity: appSeverity,
        description: description || 'No issues detected. This app should work with passkey authentication.',
        isSubstrate,
        fixGuide: !isSubstrate && issues.length > 0 ? this.getAppFixGuide(issues) : (isSubstrate && issues.length > 0 ? 'Microsoft-managed app - not directly configurable. Monitor for updates from Microsoft.' : null)
      };
    }).filter(a => a.displayName !== 'Unnamed');
  }

  getAppFixGuide(issues) {
    const guides = [];
    if (issues.some(i => i.includes('password')))
      guides.push('Remove password credentials. Migrate to OAuth 2.0 OIDC with PKCE.');
    if (issues.some(i => i.includes('legacy auth')))
      guides.push('Configure delegated permissions in Azure Portal. The app needs to request token delegation via the requiredResourceAccess property.');
    if (issues.some(i => i.includes('certificate')))
      guides.push('Verify FIDO2 token binding support in the certificate auth configuration.');
    return guides.join(' ');
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
        const hasFido = (u.authMethods || []).some(m => this.isPasskeyMethod(m));
        const hasMfa = (u.authMethods || []).some(m => this.isStrongAuthMethod(m));
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
    toxicCombos.filter(t => t.severity === "critical").forEach(t => recs.push({ severity: "critical", icon: "\u{1F6A8}", category: "Security Risk", title: t.displayName, text: t.description, fix: t.fix }));
    policyAnalysis.filter(p => p.blocksPasskeyRegistration).forEach(p => recs.push({ severity: "high", icon: "\u{1F534}", category: "Policy", title: "CA policy blocks passkeys: " + p.displayName, text: p.warning || "Blocks passkey registration", fix: p.fixGuide || "Review policy" }));
    if (passkeyReadiness.blocked > 0)
      recs.push({ severity: "high", icon: "\u{1F534}", category: "Blocked", title: passkeyReadiness.blocked + " user(s) blocked", text: "Blocked by CA policies or device limitations.", fix: "Address policy and device issues." });
    if (passkeyReadiness.needsAttention > 0)
      recs.push({ severity: "medium", icon: "\u{1F7E1}", category: "Attention", title: passkeyReadiness.needsAttention + " user(s) need prep", text: "Devices or MFA need updating.", fix: "Guide users to register modern devices." });
    const badApps = appCompatibility.filter(a => !a.passkeyCompatible);
    if (badApps.length > 0)
      recs.push({ severity: "low", icon: "\uD83D\uDCA1", category: "Apps", title: badApps.length + " app(s) flagged - see Entra Tip tab", text: badApps.map(a => a.displayName + (a.isSubstrate ? " (Microsoft-managed)" : "")).join(", "), fix: "Review the App Compatibility tab for descriptions and fixes." });
    if (passkeyReadiness.ready > 0)
      recs.push({ severity: "low", icon: "\u{1F7E2}", category: "Ready", title: passkeyReadiness.ready + " user(s) ready!", text: "Start a pilot program.", fix: "Enable passkey for pilot group." });
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
