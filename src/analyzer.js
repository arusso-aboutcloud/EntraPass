export class Analyzer {
  analyzeAll(data) {
    const passkeyReadiness = this.analyzePasskeyReadiness(data);
    const appCompatibility = this.analyzeAppCompatibility(data);
    const policyResult    = this.analyzePolicies(data);
    const toxicCombos     = this.findToxicCombinations(passkeyReadiness, data);
    const recommendations = this.generateRecommendations(passkeyReadiness, appCompatibility, policyResult, toxicCombos);
    const narrative       = this.generateNarrative(passkeyReadiness, appCompatibility, policyResult.policies, toxicCombos);
    const readinessScore  = this.computeReadinessScore(passkeyReadiness, toxicCombos, policyResult);
    return {
      readinessScore,
      passkeyReadiness,
      apps: appCompatibility,
      policies:      policyResult.policies,
      policyGaps:    policyResult.gaps,
      policySummary: policyResult.summary,
      toxicCombos,
      recommendations,
      narrative,
      timestamp: new Date().toISOString(),
    };
  }

  computeReadinessScore(passkeyReadiness, toxicCombos, policyResult) {
    const { total, blocked, needsAttention } = passkeyReadiness;
    const policies = policyResult.policies || [];
    const gaps     = policyResult.gaps     || [];
    if (total === 0) return 50;
    let score = 100;
    score -= (blocked / total) * 45;
    score -= (needsAttention / total) * 20;
    score -= Math.min(toxicCombos.filter(t => t.severity === 'critical').length * 15, 20);
    score -= Math.min(policies.filter(p => p.blocksPasskeyRegistration).length * 5, 15);
    score -= Math.min(gaps.filter(g => g.severity === 'critical').length * 8, 20);
    score -= Math.min(gaps.filter(g => g.severity === 'high').length * 3, 8);
    return Math.max(0, Math.min(100, Math.round(score)));
  }

  isStrongAuthMethod(method) {
    const t = (method['@odata.type'] || method.authenticationMethodType || '').toLowerCase();
    return t.includes('fido2') || t.includes('passkey') || t.includes('windowshelloforbusiness')
      || t.includes('microsoftauthenticator') || t.includes('softwareoath')
      || t.includes('phone') || t.includes('temporaryaccesspass');
  }

  isPasskeyMethod(method) {
    const t = (method['@odata.type'] || method.authenticationMethodType || '').toLowerCase();
    return t.includes('fido2') || t.includes('passkey');
  }

  analyzePasskeyReadiness({ users, devices, policies }) {
    const result = {
      total: users.length, ready: 0, needsAttention: 0, blocked: 0, users: [],
      breakdown: { byDevice: { ready: 0, outdated: 0, none: 0 }, byPolicy: { blocked: 0, allowed: 0 } },
    };
    const blockingPolicies = policies.filter(p => this.policyBlocksPasskeyRegistration(p));
    users.forEach(user => {
      const issues = [];
      const d = { modernDevice: false, blockedByPolicy: false };
      const am = user.authMethods || [];
      const hasFido = am.some(m => this.isPasskeyMethod(m));
      const hasMfa  = am.some(m => this.isStrongAuthMethod(m));
      if (!hasMfa) issues.push("No MFA method registered");
      if (hasFido) issues.push("Already has passkey/FIDO2 registered");
      const userDevices = devices.filter(d2 =>
        (d2.registeredOwners || []).some(o => o.id === user.id || o.userPrincipalName === user.userPrincipalName)
      );
      userDevices.forEach(d2 => {
        const osName = (d2.operatingSystem || '').toLowerCase();
        const ver = parseInt(d2.operatingSystemVersion) || 0;
        if ((osName.includes('windows') && ver >= 10) || (osName.includes('ios') && ver >= 16)
          || (osName.includes('android') && ver >= 14) || (osName.includes('mac') && ver >= 13))
          d.modernDevice = true;
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
      result.users.push({
        id: user.id,
        displayName: user.displayName || user.userPrincipalName,
        userPrincipalName: user.userPrincipalName,
        status, issues,
        deviceCount: userDevices.length,
        authMethodCount: am.length,
        groups: (user.groups || []).map(g => g.displayName),
        lastSignIn: user.signInActivity?.lastSuccessfulSignIn || null,
      });
      if (status === "ready") result.ready++;
      else if (status === "attention") result.needsAttention++;
      else result.blocked++;
    });
    return result;
  }

  analyzeAppCompatibility({ apps, servicePrincipals }) {
    const all = [...(apps || []), ...(servicePrincipals || [])];
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
        description = (description ? description + " " : "") + "Password credentials allow the app to authenticate with a client secret, which bypasses passkey altogether.";
      }
      if (app.keyCredentials?.length > 0) {
        issues.push("Uses certificate-based auth");
        severity.push("low");
        description = (description ? description + " " : "") + "Certificate-based authentication can coexist with passkeys, but verify that the app supports FIDO2 token binding.";
      }
      const msDomains = ["microsoft.com", "microsoftonline.com", "windows.net", "sharepoint.com", "skype.com", "office.com", "live.com", "azure.com", "graph.microsoft.com"];
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
        fixGuide: !isSubstrate && issues.length > 0 ? this.getAppFixGuide(issues) : (isSubstrate && issues.length > 0 ? 'Microsoft-managed app — not directly configurable.' : null),
      };
    }).filter(a => a.displayName !== 'Unnamed');
  }

  getAppFixGuide(issues) {
    const guides = [];
    if (issues.some(i => i.includes('password')))
      guides.push('Remove password credentials. Migrate to OAuth 2.0 OIDC with PKCE.');
    if (issues.some(i => i.includes('legacy auth')))
      guides.push('Configure delegated permissions in Azure Portal.');
    if (issues.some(i => i.includes('certificate')))
      guides.push('Verify FIDO2 token binding support in the certificate auth configuration.');
    return guides.join(' ');
  }

  // ============================================================================
  // Policy Analysis — enriched per-policy + gap detection
  // ============================================================================

  analyzePolicies({ policies, users, devices, authMethodsConfig }) {
    const enriched = (policies || []).map(p => this.enrichPolicy(p));
    const gaps     = this.detectPolicyGaps(enriched, users || [], devices || [], authMethodsConfig || []);

    const enabled = enriched.filter(p => p.state === 'enabled');
    const summary = {
      total:        enriched.length,
      enforcing:    enabled.filter(p => p.enforcesPasskey).length,
      protecting:   enabled.filter(p => p.protectsRegistration).length,
      blocking:     enriched.filter(p => p.blocksPasskeyRegistration).length,
      criticalGaps: gaps.filter(g => g.severity === 'critical').length,
      highGaps:     gaps.filter(g => g.severity === 'high').length,
    };

    return { policies: enriched, gaps, summary };
  }

  enrichPolicy(policy) {
    const state      = policy.state || 'unknown';
    const grant      = policy.grantControls || {};
    const conditions = policy.conditions   || {};
    const builtIn    = grant.builtInControls || [];
    const authStr    = grant.authenticationStrength;
    const userActions = conditions.applications?.includeUserActions || [];
    const clientTypes = conditions.clientAppTypes || [];
    const includeUsers  = conditions.users?.includeUsers  || [];
    const includeRoles  = conditions.users?.includeRoles  || [];
    const includeGroups = conditions.users?.includeGroups || [];

    const isEnabled = state !== 'disabled';

    // --- What does the policy do? ---
    const blocksPasskeyRegistration = isEnabled && builtIn.includes('password');

    // Enforces passkey: grant requires an auth strength containing FIDO2 or WHfB
    const enforcesPasskey = isEnabled && !!(
      authStr?.allowedCombinations?.some(c =>
        c === 'fido2' || c === 'windowsHelloForBusiness' || c === 'deviceBasedPush'
      )
    );

    // Protects registration: targets the registerSecurityInfo user action
    const protectsRegistration = isEnabled && (
      userActions.includes('urn:user:registerSecurityInfo') ||
      userActions.includes('urn:user:registerbiometricinfo')
    );

    // Blocks legacy auth: targets legacy client types with a block action
    const blocksLegacyAuth = isEnabled && (
      (clientTypes.includes('exchangeActiveSync') || clientTypes.includes('other')) &&
      builtIn.includes('block')
    );

    // Risk-based: responds to sign-in or user risk signals
    const isRiskBased = isEnabled && (
      (conditions.signInRiskLevels || []).length > 0 ||
      (conditions.userRiskLevels   || []).length > 0
    );

    // --- Scope ---
    const allUsers = includeUsers.includes('All') || includeUsers.includes('GuestsOrExternalUsers');

    // --- Classification ---
    let type = 'other';
    if (blocksPasskeyRegistration) type = 'blocks-passkey';
    else if (enforcesPasskey)       type = 'enforces-passkey';
    else if (protectsRegistration)  type = 'protects-registration';
    else if (blocksLegacyAuth)      type = 'legacy-block';
    else if (isRiskBased)           type = 'risk-based';
    else if (builtIn.includes('compliantDevice') || builtIn.includes('domainJoinedDevice'))
      type = 'device-compliance';

    const strengthName = authStr?.displayName || null;

    // --- Fix guide ---
    let fixGuide = null;
    if (blocksPasskeyRegistration) {
      fixGuide = 'Replace the password grant control with an Authentication Strength that includes Passkey (FIDO2). Consider splitting: one policy for passkey users (FIDO2 strength), one for legacy users.';
    }

    return {
      id: policy.id,
      displayName: policy.displayName,
      state,
      type,
      blocksPasskeyRegistration,
      enforcesPasskey,
      protectsRegistration,
      blocksLegacyAuth,
      isRiskBased,
      allUsers,
      includeRoles: includeRoles.length > 0,
      includeGroups: includeGroups.length > 0,
      scopeRaw: { includeUsers, includeGroups, includeRoles },
      strengthName,
      authStrength: authStr || null,
      warning: blocksPasskeyRegistration
        ? 'This policy requires password as a grant control, blocking passkey-only authentication.'
        : null,
      fixGuide,
      recommendation: fixGuide,
      conditions: policy.conditions,
      grantControls: policy.grantControls,
    };
  }

  detectPolicyGaps(enrichedPolicies, users, devices, authMethodsConfig) {
    const gaps    = [];
    const enabled = enrichedPolicies.filter(p => p.state === 'enabled');

    // Resolve FIDO2 method config
    const fido2Config = authMethodsConfig.find(c =>
      c.id === 'Fido2' || (c['@odata.type'] || '').toLowerCase().includes('fido2')
    );
    const fido2Enabled = fido2Config?.state === 'enabled';

    // ── GAP 1: FIDO2 method not enabled ──────────────────────────────────────
    if (!fido2Config || !fido2Enabled) {
      gaps.push({
        id: 'gap-fido2-disabled',
        severity: 'critical',
        type: 'config',
        title: 'FIDO2 / Passkey authentication method is not enabled',
        description: 'The FIDO2 security key authentication method is disabled in your Authentication Methods policy. Users cannot register or use passkeys until this is turned on — all other passkey work is blocked by this single setting.',
        recommendation: 'Entra ID → Protection → Authentication methods → FIDO2 security key → Enable. Configure key restrictions and attestation based on your device fleet (see gap below if applicable).',
        docUrl: 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key',
        context: fido2Config ? 'Detected from: Authentication Methods Policy — FIDO2 state is "disabled"' : 'Detected from: No FIDO2 configuration found in Authentication Methods Policy',
      });
    }

    // ── GAP 2: No phishing-resistant MFA enforcement ──────────────────────────
    const enforcingAll  = enabled.filter(p => p.enforcesPasskey && p.allUsers);
    const enforcingAny  = enabled.filter(p => p.enforcesPasskey);
    if (enforcingAll.length === 0) {
      gaps.push({
        id: 'gap-enforce-phishing-resistant',
        severity: 'critical',
        type: 'missing',
        title: enforcingAny.length > 0
          ? 'Phishing-resistant MFA not enforced for all users — scope gap'
          : 'No policy enforces phishing-resistant MFA for any user',
        description: enforcingAny.length > 0
          ? `${enforcingAny.length} policy(ies) enforce passkey/phishing-resistant MFA but not for All Users. Users outside those scopes can sign in with password only, even after passkeys are deployed.`
          : 'No Conditional Access policy requires phishing-resistant authentication (FIDO2 or Windows Hello for Business). After passkeys are deployed, users can still sign in with just a password — making the deployment security-neutral.',
        recommendation: 'Create a CA policy: All Users → All Cloud Apps → Grant: Require Authentication Strength → Phishing-resistant MFA. Exclude break-glass accounts and the security info registration action.',
        docUrl: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-strengths',
        context: enforcingAny.length > 0
          ? `Detected from: ${enforcingAny.length} policy(ies) enforce passkey strength but no "All Users" scope found`
          : 'Detected from: 0 enabled policies use an auth strength including FIDO2 or Windows Hello for Business',
      });
    }

    // ── GAP 3: Security info registration unprotected ────────────────────────
    const hasRegistrationPolicy = enabled.some(p => p.protectsRegistration);
    if (!hasRegistrationPolicy) {
      gaps.push({
        id: 'gap-protect-registration',
        severity: 'critical',
        type: 'missing',
        title: 'Passkey self-enrollment is unprotected (no registration policy)',
        description: 'No CA policy governs the "Register security information" user action — the flow where users enroll a new passkey. An attacker who compromises a user\'s password could silently register their own passkey, gaining persistent phishing-resistant access to the account.',
        recommendation: 'Create a CA policy targeting User Action: "Register security information". Require Temporary Access Pass or an existing passkey as the grant. Exclude users who are bootstrapping their first credential (use a TAP-based onboarding flow).',
        docUrl: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-registration',
        context: 'Detected from: 0 enabled policies target the urn:user:registerSecurityInfo user action',
      });
    }

    // ── GAP 4: Privileged accounts not covered ────────────────────────────────
    const privilegedUsers = users.filter(u => {
      const groups = (u.groups || []).map(g => (g.displayName || '').toLowerCase());
      return groups.some(g => g.includes('admin') || g.includes('global') || g.includes('privileged') || g.includes('exchange administrator'));
    });
    const hasPrivilegedPolicy = enabled.some(p => p.enforcesPasskey && p.includeRoles);
    if (privilegedUsers.length > 0 && !hasPrivilegedPolicy) {
      gaps.push({
        id: 'gap-privileged-roles',
        severity: 'high',
        type: 'missing',
        title: `${privilegedUsers.length} privileged user(s) not required to use phishing-resistant MFA`,
        description: `Your tenant has ${privilegedUsers.length} user(s) in admin or privileged groups. No CA policy specifically targets directory roles with phishing-resistant authentication strength. Admin accounts are the highest-value target for phishing and credential theft.`,
        recommendation: 'Create a dedicated CA policy targeting directory roles (Global Administrator, Privileged Role Administrator, Security Administrator, etc.) requiring Phishing-resistant MFA. Make this your highest-priority policy — enable it before the org-wide rollout.',
        docUrl: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa',
        context: `Detected from: ${privilegedUsers.length} user(s) in admin-scoped groups + 0 enabled CA policies targeting directory roles with passkey strength`,
      });
    }

    // ── GAP 5: Legacy auth not blocked ────────────────────────────────────────
    const hasLegacyBlock = enabled.some(p => p.blocksLegacyAuth);
    if (!hasLegacyBlock) {
      gaps.push({
        id: 'gap-block-legacy-auth',
        severity: 'high',
        type: 'missing',
        title: 'Legacy authentication protocols not blocked',
        description: 'No CA policy blocks legacy auth (IMAP, POP3, SMTP AUTH, Exchange ActiveSync with basic auth). Legacy clients bypass all Conditional Access policies entirely — including any passkey enforcement — making your deployment security-incomplete regardless of what CA policies you create.',
        recommendation: 'Create a CA policy: All Users → All Cloud Apps → Client apps: Exchange ActiveSync + Other clients → Block. Exclude any service accounts that legitimately require legacy protocols, and validate with report-only mode first.',
        docUrl: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication',
        context: 'Detected from: 0 enabled policies with clientAppTypes = exchangeActiveSync or other AND grantControls = block',
      });
    }

    // ── GAP 6: No sign-in risk policy ────────────────────────────────────────
    const hasSignInRisk = enabled.some(p =>
      (p.conditions?.signInRiskLevels || []).length > 0
    );
    if (!hasSignInRisk) {
      gaps.push({
        id: 'gap-sign-in-risk',
        severity: 'medium',
        type: 'recommended',
        title: 'No sign-in risk policy — Identity Protection signals unused',
        description: 'No CA policy responds to Entra ID Identity Protection sign-in risk signals (impossible travel, token replay, anonymous proxy, etc.). High-risk sign-ins will not trigger additional challenges even when passkeys are deployed, leaving token-theft attacks undetected.',
        recommendation: 'Create a CA policy for high/medium sign-in risk requiring phishing-resistant MFA or blocking access. Requires Microsoft Entra ID P2 (included in E5). Start with report-only mode to calibrate before enforcing.',
        docUrl: 'https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies',
        context: 'Detected from: 0 enabled policies with signInRiskLevels configured',
      });
    }

    // ── GAP 7: Attestation not enforced (device-aware) ────────────────────────
    if (fido2Enabled && fido2Config.isAttestationEnforced !== true) {
      const managedCount = devices.filter(d => d.isManaged || d.isCompliant).length;
      if (managedCount >= 3) {
        gaps.push({
          id: 'gap-attestation',
          severity: 'medium',
          type: 'device-specific',
          title: `FIDO2 attestation not enforced — ${managedCount} managed device(s) detected`,
          description: `FIDO2 attestation verification is disabled, so any FIDO2 authenticator (including uncertified or consumer-grade devices) can be enrolled. With ${managedCount} managed/compliant devices in your tenant, you likely operate a controlled device fleet where enforcing approved authenticator models (by AAGUID) is appropriate.`,
          recommendation: 'Enable attestation enforcement in Authentication Methods → FIDO2 security key → Key restrictions. Build an Allow list from the AAGUIDs of your approved keys (YubiKey, Feitian, EZTRUST, platform authenticators). For Windows devices, Windows Hello for Business provides hardware-bound attestation via TPM automatically.',
          docUrl: 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key#fido2-security-key-optional-settings',
          context: `Detected from: FIDO2 isAttestationEnforced = false with ${managedCount} managed/compliant devices in tenant`,
        });
      }
    }

    // Sort: critical → high → medium → low
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    gaps.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
    return gaps;
  }

  findToxicCombinations(passkeyReadiness, { users, policies }) {
    const combos = [];
    (users || []).forEach(u => {
      const groups = (u.groups || []).map(g => (g.displayName || '').toLowerCase());
      const isPrivileged = groups.some(g => g.includes("admin") || g.includes("global") || g.includes("privileged") || g.includes("exchange"));
      if (isPrivileged) {
        const hasFido = (u.authMethods || []).some(m => this.isPasskeyMethod(m));
        const hasMfa  = (u.authMethods || []).some(m => this.isStrongAuthMethod(m));
        if (!hasFido && !hasMfa)
          combos.push({ severity: "critical", displayName: u.displayName || u.userPrincipalName, groups: (u.groups || []).map(g => g.displayName), description: "No MFA and no passkey on high-privilege account", fix: "Enable MFA immediately. Register passkey/FIDO2 as primary auth method." });
      }
    });
    const vulnerablePolicies = (policies || []).filter(p => p.state !== "disabled" && p.grantControls?.builtInControls?.includes("password") && p.grantControls?.builtInControls?.includes("mfa"));
    if (vulnerablePolicies.length > 0)
      combos.push({ severity: "high", displayName: "Password fallback enabled", description: vulnerablePolicies.length + " CA policies allow password fallback with passkey.", fix: "Update to require FIDO2 authentication strength." });
    return combos;
  }

  policyBlocksPasskeyRegistration(policy) {
    if (policy.state === "disabled") return false;
    return policy.grantControls?.builtInControls?.includes("password") || false;
  }

  generateRecommendations(passkeyReadiness, appCompatibility, policyResult, toxicCombos) {
    const recs       = [];
    const policies   = policyResult.policies || [];
    const gaps       = policyResult.gaps     || [];

    toxicCombos.filter(t => t.severity === "critical").forEach(t =>
      recs.push({ severity: "critical", icon: "\u{1F6A8}", category: "Security Risk", title: t.displayName, text: t.description, fix: t.fix })
    );

    policies.filter(p => p.blocksPasskeyRegistration).forEach(p =>
      recs.push({ severity: "high", icon: "\u{1F534}", category: "Policy", title: "CA policy blocks passkeys: " + p.displayName, text: p.warning || "Blocks passkey registration", fix: p.fixGuide || "Review policy" })
    );

    // Aggregate critical/high gap recommendation for overview tab
    const urgentGaps = gaps.filter(g => g.severity === 'critical' || g.severity === 'high');
    if (urgentGaps.length > 0) {
      recs.push({
        severity: urgentGaps.some(g => g.severity === 'critical') ? 'critical' : 'high',
        icon: '\u{1F510}',
        category: 'Policy Gap',
        title: `${urgentGaps.length} CA policy gap(s) — review required before rollout`,
        text: urgentGaps.map(g => g.title).join(' · '),
        fix: 'Open the CA Policies tab for tenant-specific recommendations and fix guides.',
      });
    }

    if (passkeyReadiness.blocked > 0)
      recs.push({ severity: "high", icon: "\u{1F534}", category: "Blocked", title: passkeyReadiness.blocked + " user(s) blocked", text: "Blocked by CA policies or device limitations.", fix: "Address policy and device issues." });
    if (passkeyReadiness.needsAttention > 0)
      recs.push({ severity: "medium", icon: "\u{1F7E1}", category: "Attention", title: passkeyReadiness.needsAttention + " user(s) need prep", text: "Devices or MFA need updating.", fix: "Guide users to register modern devices." });

    const badApps = appCompatibility.filter(a => !a.passkeyCompatible);
    if (badApps.length > 0)
      recs.push({ severity: "low", icon: "💡", category: "Apps", title: badApps.length + " app(s) flagged — see Entra Tip tab", text: badApps.map(a => a.displayName + (a.isSubstrate ? " (Microsoft-managed)" : "")).join(", "), fix: "Review the App Compatibility tab." });

    if (passkeyReadiness.ready > 0)
      recs.push({ severity: "low", icon: "\u{1F7E2}", category: "Ready", title: passkeyReadiness.ready + " user(s) ready!", text: "Start a pilot program.", fix: "Enable passkey for pilot group." });

    if (recs.length === 0)
      recs.push({ severity: "low", icon: "✅", category: "All Clear", title: "Tenant is ready!", text: "Great job!", fix: "Proceed with rollout." });

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
