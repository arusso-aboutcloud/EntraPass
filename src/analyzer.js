export class Analyzer {
  analyzeAll(data) {
    const policyResult     = this.analyzePolicies(data);
    const passkeyReadiness = this.analyzePasskeyReadiness(data, policyResult.policies);
    const appResult        = this.analyzeAppCompatibility(data);
    const toxicCombos      = this.findToxicCombinations(passkeyReadiness, data);
    const recommendations  = this.generateRecommendations(passkeyReadiness, appResult.apps, policyResult, toxicCombos);
    const narrative        = this.generateNarrative(passkeyReadiness, appResult.apps, policyResult.policies, toxicCombos);
    const readinessScore   = this.computeReadinessScore(passkeyReadiness, toxicCombos, policyResult);
    return {
      readinessScore,
      passkeyReadiness,
      apps:              appResult.apps,
      appsExcludedCount: appResult.excludedCount,
      policies:          policyResult.policies,
      policyGaps:        policyResult.gaps,
      policySummary:     policyResult.summary,
      fido2Config:       policyResult.fido2Config,
      tapConfig:         policyResult.tapConfig,
      toxicCombos,
      recommendations,
      narrative,
      timestamp: new Date().toISOString(),
    };
  }

  computeReadinessScore(passkeyReadiness, toxicCombos, policyResult) {
    const users = passkeyReadiness.users || [];
    const total  = users.length;
    if (total === 0) return null;

    // Derive tier counts from the actual user list — robust against stale cached summaries.
    const cnt       = s => users.filter(u => u.status === s).length;
    const exempt    = cnt('exempt');
    const unknown   = cnt('unknown');
    const blocked   = cnt('blocked');
    const needsPrep = cnt('needsPrep');
    const capable   = cnt('capable');
    // 'unknown' users (registration data unavailable) are excluded from the denominator
    // alongside 'exempt' — they cannot be scored and should not dilute the result.
    const effective = total - exempt - unknown;
    if (effective === 0) return null;

    let score = 100;

    // ── User readiness (35 pts max penalty) ──────────────────────────────────
    // Blocked = no path to passkey without admin action → heaviest signal
    // Needs prep = one gap solvable in a short admin session → moderate
    // Capable = can self-register today → very light (just needs a nudge)
    score -= (blocked   / effective) * 35;
    score -= (needsPrep / effective) * 12;
    score -= (capable   / effective) *  3;

    // ── Infrastructure readiness (28 pts max penalty) ─────────────────────────
    // FIDO2 disabled → passkeys literally cannot be registered at all (-20)
    // TAP not enabled → new hires and lost-credential recovery are blocked (-8)
    const fido2 = policyResult.fido2Config;
    const tap   = policyResult.tapConfig;
    if (!fido2 || fido2.state !== 'enabled') score -= 20;
    if (!tap   || tap.state   !== 'enabled') score -=  8;

    // ── Toxic combinations (-15 pts max) ─────────────────────────────────────
    score -= Math.min((toxicCombos || []).filter(t => t.severity === 'critical').length * 10, 15);

    // ── Policy gaps & blocking policies (-14 pts max) ─────────────────────────
    const gaps     = policyResult.gaps     || [];
    const policies = policyResult.policies || [];
    score -= Math.min(gaps.filter(g => g.severity === 'critical').length * 8, 10);
    score -= Math.min(policies.filter(p => p.blocksPasskeyRegistration).length * 4,  5);
    score -= Math.min(gaps.filter(g => g.severity === 'high').length * 2,             4);

    return Math.max(0, Math.min(100, Math.round(score)));
  }

  // Classify an account into one of four identity types before any readiness logic.
  // Break-glass and guest/MSA accounts follow completely different guidance paths.
  classifyAccountType(user, tenantDomain) {
    const upn      = (user.userPrincipalName || '').toLowerCase();
    const name     = (user.displayName       || '').toLowerCase();
    const type     = (user.userType          || 'member').toLowerCase();
    const domain   = upn.split('@')[1] || '';

    const BG_PATTERNS = ['breakglass','break-glass','emergency','emergencyaccess','bg01','bg02','bg-','bgadmin','emergency-access'];
    if (BG_PATTERNS.some(p => upn.includes(p) || name.includes(p))) return 'breakglass';

    if (type === 'guest' || upn.includes('#ext#')) return 'guest';

    const PERSONAL_DOMAINS = [
      'outlook.com','hotmail.com','live.com','msn.com',
      'gmail.com','yahoo.com',
      'icloud.com','me.com','mac.com',
      'proton.me','protonmail.com','pm.me',
      'aol.com',
      'fastmail.com','fastmail.fm',
      'tutanota.com','tutanota.de','tuta.io',
      'gmx.com','gmx.net','gmx.de',
      'zoho.com','zohomail.com',
      'yandex.com','yandex.ru',
      'mail.com',
    ];
    if (PERSONAL_DOMAINS.some(d => domain === d)) return 'personal';

    if (tenantDomain && domain && domain !== tenantDomain) return 'guest';

    return 'member';
  }

  // Accepts the `methodsRegistered` string array from
  // /reports/authenticationMethods/userRegistrationDetails.
  // Values are camelCase strings such as 'passKeyDeviceBound',
  // 'microsoftAuthenticatorPush', 'softwareOneTimePasscode', 'mobilePhone'.
  classifyAuthMethods(methodsRegistered) {
    const MAP = [
      { re: /passkey|fido2/i,                type: 'fido2',         label: 'Passkey / FIDO2' },
      { re: /microsoftauthenticator/i,       type: 'authenticator', label: 'Authenticator App' },
      { re: /windowshelloforbusiness/i,      type: 'whfb',          label: 'Windows Hello' },
      { re: /softwareonetimepasscode|oath/i, type: 'totp',          label: 'TOTP App' },
      { re: /mobilephone|sms|phone/i,        type: 'phone',         label: 'SMS / Phone' },
      { re: /temporaryaccesspass/i,          type: 'tap',           label: 'Temp Access Pass' },
      { re: /email/i,                        type: 'email',         label: 'Email OTP' },
    ];
    const seen = new Set();
    return (methodsRegistered || []).flatMap(m => {
      const hit = MAP.find(r => r.re.test(m));
      if (!hit || seen.has(hit.type)) return [];
      seen.add(hit.type);
      return [{ type: hit.type, label: hit.label }];
    });
  }

  generateRecommendedAction({ accountType, hasFido, hasMfa, hasModernDevice, blockedByPolicy, isPrivileged, userDevices, authTypes }) {
    if (accountType === 'breakglass') {
      return 'Break-glass account — do not register passkeys. Verify: excluded from all CA policies, sign-in alert is active, emergency password stored offline.';
    }
    if (accountType === 'guest') {
      return 'Guest account — passkey registration is governed by the user\'s home tenant. Verify they are in scope of your CA policies if applicable.';
    }
    if (accountType === 'personal') {
      return 'Personal account — governed by an external identity provider, not tenant policies. Remove from tenant if access is no longer needed, or re-invite with a work or school account.';
    }
    if (hasFido) {
      return 'Passkey already registered. Verify the CA policy enforcing passkey sign-in is active and covers this user.';
    }
    if (isPrivileged && !hasMfa) {
      return 'CRITICAL — Privileged account with no MFA. Issue a Temporary Access Pass immediately and require passkey registration before any further admin activity.';
    }
    if (blockedByPolicy) {
      return 'Blocked by a CA policy requiring password as a grant control. Update the policy to use Authentication Strength (FIDO2) or add a temporary exclusion for the passkey onboarding window.';
    }
    if (hasMfa === null) {
      return 'Authentication method data unavailable — re-run the scan or verify the scanning account has Reports Reader (or equivalent) role so registration data can be retrieved.';
    }
    const hasAuthenticator = authTypes.some(a => a.type === 'authenticator' || a.type === 'whfb');
    if (hasMfa && hasModernDevice) {
      return hasAuthenticator
        ? 'Ready to self-register. Share aka.ms/mysecurityinfo — user can add a passkey today without admin intervention.'
        : 'Has MFA and a compatible device. Direct user to aka.ms/mysecurityinfo to add a passkey (Authenticator app recommended first).';
    }
    if (hasMfa && !hasModernDevice) {
      return userDevices.length > 0
        ? 'MFA registered but device OS is outdated. Upgrade to Windows 10+, iOS 16+, Android 14+, or macOS 13+. Alternatively, issue a FIDO2 hardware security key.'
        : 'MFA registered but no enrolled device. Issue a FIDO2 hardware security key (YubiKey, Feitian, etc.) so the user can register without a platform authenticator.';
    }
    if (!hasMfa && hasModernDevice) {
      return 'Compatible device enrolled but no MFA registered. Issue a Temporary Access Pass, then guide the user to register at aka.ms/mysecurityinfo.';
    }
    return isPrivileged
      ? 'Privileged account with no MFA and no compatible device. Issue a TAP and a FIDO2 hardware key immediately — this is a critical security gap.'
      : 'No MFA and no compatible device. Issue a Temporary Access Pass, then guide the user to register at aka.ms/mysecurityinfo. Consider issuing a FIDO2 hardware key if the user has no compatible personal device.';
  }

  summarizeDevices(userDevices) {
    if (!userDevices.length) return null;
    const parts = userDevices.slice(0, 2).map(d => {
      const os  = d.operatingSystem || 'Unknown';
      const ver = d.operatingSystemVersion ? ' ' + String(d.operatingSystemVersion).split('.')[0] : '';
      return os + ver;
    });
    if (userDevices.length > 2) parts.push(`+${userDevices.length - 2}`);
    return parts.join(' · ');
  }

  analyzePasskeyReadiness({ users, devices, policies, org }, enrichedPolicies = []) {
    const tenantDomain = (org?.verifiedDomains || []).find(d => d.isDefault)?.name?.toLowerCase() || null;

    const result = {
      total: users.length,
      ready: 0, capable: 0, needsPrep: 0, blocked: 0, exempt: 0, unknown: 0,
      needsAttention: 0, // = capable + needsPrep — kept for backward compat with overview hero + score
      partialDataCount: 0, // users where reg or sign-in data was unavailable
      users: [],
      breakdown: { byDevice: { ready: 0, outdated: 0, none: 0 }, byPolicy: { blocked: 0, allowed: 0 } },
    };

    const blockingPolicies  = policies.filter(p => this.policyBlocksPasskeyRegistration(p));
    const enforcingPolicies = enrichedPolicies.filter(p => p.enforcesPasskey && p.state === 'enabled');

    users.forEach(user => {
      // ── Registration data (bulk report) ──────────────────────────────────────
      // Shape: { available, reason, isMfaRegistered, methodsRegistered, ... }
      const reg             = user.registrationData || { available: false, reason: 'no_record' };
      const methodsReg      = reg.available ? (reg.methodsRegistered || []) : [];

      // hasFido: passkey registered. Only trust the positive when data is available.
      const PASSKEY_METHODS = ['passKeyDeviceBound', 'fido2'];
      const hasFido = methodsReg.some(m =>
        PASSKEY_METHODS.includes(m) || m.toLowerCase().startsWith('passkey')
      );

      // hasMfa: null when registration data unavailable (drives 'unknown' tier).
      // Use isMfaRegistered (policy-agnostic) from the bulk report.
      const hasMfa = reg.available ? (reg.isMfaRegistered ?? false) : null;

      const authTypes   = this.classifyAuthMethods(methodsReg);
      const accountType = this.classifyAccountType(user, tenantDomain);

      const isPrivileged = (user.groups || []).some(g => {
        // Primary: @odata.type discriminates directoryRole objects from groups.
        // Fires even when the scanning account can't read the role's displayName.
        if ((g['@odata.type'] || '').includes('directoryRole')) return true;
        // Fallback: displayName substring match. Best-effort — known to produce false
        // positives on groups whose names contain 'admin', 'global', etc.
        const n = (g.displayName || '').toLowerCase();
        return n.includes('admin') || n.includes('global') || n.includes('privileged') || n.includes('exchange');
      });

      // ── Sign-in activity (per-user fetch) ────────────────────────────────────
      // Shape: { available, reason, lastSuccessfulSignInDateTime,
      //          lastSignInDateTime, lastNonInteractiveSignInDateTime }
      const sia = user.signInActivity || { available: false, reason: 'no_record' };

      // Effective last sign-in: take the most-recent of the three timestamp fields.
      // None of these fields are backfilled before Dec 2023, so absence != never signed in.
      const effectiveLastSignIn = sia.available ? (
        sia.lastSuccessfulSignInDateTime ||
        sia.lastSignInDateTime ||
        sia.lastNonInteractiveSignInDateTime || null
      ) : null;

      // isStale is null when data is unavailable — never assumed true.
      const isStale = sia.available
        ? (effectiveLastSignIn
            ? (Date.now() - new Date(effectiveLastSignIn).getTime()) > 90 * 86400000
            : null)
        : null;

      const userDevices = devices.filter(d =>
        (d.registeredOwners || []).some(o => o.id === user.id || o.userPrincipalName === user.userPrincipalName)
      );

      let hasModernDevice = false;
      userDevices.forEach(d => {
        const os  = (d.operatingSystem || '').toLowerCase();
        const ver = parseInt(d.operatingSystemVersion) || 0;
        if ((os.includes('windows') && ver >= 10) || (os.includes('ios') && ver >= 16)
          || (os.includes('android') && ver >= 14) || (os.includes('mac') && ver >= 13))
          hasModernDevice = true;
      });

      if (hasModernDevice) result.breakdown.byDevice.ready++;
      else if (userDevices.length > 0) result.breakdown.byDevice.outdated++;
      else result.breakdown.byDevice.none++;

      let blockedByPolicy = false;
      blockingPolicies.forEach(p => {
        if (p.conditions?.users?.includeUsers?.includes('All') || p.conditions?.users?.includeUsers?.includes(user.id)) {
          blockedByPolicy = true;
        }
      });
      if (blockedByPolicy) result.breakdown.byPolicy.blocked++;
      else result.breakdown.byPolicy.allowed++;

      // CA coverage gap
      let notCoveredByEnforcement = false;
      if (!hasFido && enforcingPolicies.length > 0) {
        const userGroupIds = (user.groups || []).map(g => g.id).filter(Boolean);
        const covered = enforcingPolicies.some(p => {
          const { includeUsers = [], includeGroups = [] } = p.scopeRaw || {};
          const { excludeUsers = [], excludeGroups = [] } = p.conditions?.users || {};
          if (excludeUsers.includes(user.id)) return false;
          if (excludeGroups.some(g => userGroupIds.includes(g))) return false;
          if (includeUsers.includes('All') || includeUsers.includes(user.id)) return true;
          if (includeGroups.some(g => userGroupIds.includes(g))) return true;
          return false;
        });
        notCoveredByEnforcement = !covered;
      }

      // ── 5-tier status ────────────────────────────────────────────────────────
      // 'unknown' = registration data unavailable; excluded from score denominator.
      let status;
      const issues = [];

      if (accountType === 'breakglass') {
        status = 'exempt';
        issues.push('Break-glass account — exempt from passkey rollout');
      } else if (accountType === 'guest' || accountType === 'personal') {
        status = 'exempt';
        issues.push(accountType === 'personal'
          ? 'Personal account — governed by external identity provider, not tenant policies'
          : 'Guest / external account — passkey governed by home tenant');
      } else if (hasFido) {
        status = 'ready';
        issues.push('Passkey / FIDO2 registered');
      } else if (blockedByPolicy) {
        status = 'blocked';
        issues.push('Blocked by a CA policy requiring password');
        if (reg.available && hasMfa === false) issues.push('No MFA registered');
      } else if (reg.available && hasMfa === false && !hasModernDevice) {
        status = 'blocked';
        issues.push('No MFA registered');
        issues.push('No compatible device registered');
      } else if (reg.available && hasMfa === false) {
        status = 'needsPrep';
        issues.push('No MFA registered — TAP needed to bootstrap');
        if (!hasModernDevice && userDevices.length > 0) issues.push('Device OS outdated');
      } else if (hasMfa === null) {
        // Registration report unavailable — cannot classify, do not penalise.
        status = 'unknown';
        issues.push('Registration data unavailable — re-run scan with Reports Reader role');
      } else if (!hasModernDevice) {
        status = 'needsPrep';
        issues.push(userDevices.length > 0 ? 'Device OS outdated for passkeys' : 'No compatible device registered');
      } else {
        status = 'capable'; // hasMfa + hasModernDevice + no blocker
      }

      if (isPrivileged  && status !== 'exempt') issues.push('Privileged account — prioritise');
      // Only emit the stale badge when sign-in data is actually available.
      if (isStale === true && status !== 'exempt') issues.push('Inactive >90 days — verify before onboarding');
      if (notCoveredByEnforcement && status !== 'exempt') issues.push('Not in scope of any passkey-enforcing CA policy');

      const recommendedAction = this.generateRecommendedAction({
        accountType, hasFido, hasMfa, hasModernDevice, blockedByPolicy,
        isPrivileged, userDevices, authTypes,
      });

      result[status]++;
      if (status === 'capable' || status === 'needsPrep') result.needsAttention++;
      if (!reg.available || !sia.available) result.partialDataCount++;

      result.users.push({
        id:                         user.id,
        displayName:                user.displayName || user.userPrincipalName,
        userPrincipalName:          user.userPrincipalName,
        accountType,
        status,
        isPrivileged,
        isStale,
        issues,
        recommendedAction,
        authMethodTypes:            authTypes,
        deviceCount:                userDevices.length,
        deviceSummary:              this.summarizeDevices(userDevices),
        authMethodCount:            methodsReg.length,
        methodsRegistered:          methodsReg,
        groups:                     (user.groups || []).map(g => g.displayName),
        lastSignIn:                 effectiveLastSignIn,
        registrationDataAvailable:  reg.available,
        signInActivityAvailable:    sia.available,
      });
    });

    return result;
  }

  analyzeAppCompatibility({ apps, servicePrincipals, org }) {
    const tenantId = (org?.id || '').toLowerCase();
    const MS_TENANT_IDS = new Set([
      'f8cdef31-a31e-4b4a-93e4-5f571e91255a',
      '72f988bf-86f1-41af-91ab-2d7cd011db47',
    ]);
    const MS_DOMAINS = [
      'microsoft.com', 'microsoftonline.com', 'windows.net', 'sharepoint.com',
      'skype.com', 'office.com', 'live.com', 'azure.com', 'graph.microsoft.com',
    ];

    const isMicrosoftOwned = (item) => {
      const orgId = (item.appOwnerOrganizationId || '').toLowerCase();
      const domain = (item.publisherDomain || item.publisherName || '').toLowerCase();
      return MS_TENANT_IDS.has(orgId) || MS_DOMAINS.some(d => domain.includes(d));
    };

    // Merge: app registrations (always tenant-owned) first, then non-Microsoft SPs.
    // Deduplication by appId ensures the same logical app doesn't appear twice.
    const seen = new Set();
    const merged = [];
    let excludedCount = 0;

    (apps || []).forEach(app => {
      if (!app.appId || seen.has(app.appId)) return;
      seen.add(app.appId);
      merged.push({ ...app, _source: 'registration' });
    });

    (servicePrincipals || []).forEach(sp => {
      if (isMicrosoftOwned(sp)) { excludedCount++; return; }
      if (!sp.appId || seen.has(sp.appId)) return;
      seen.add(sp.appId);
      merged.push({ ...sp, _source: 'servicePrincipal' });
    });

    const now = new Date();
    const analyzedApps = merged
      .map(app => this.analyzeApp(app, now, tenantId))
      .filter(a => a.displayName !== 'Unnamed');

    return { apps: analyzedApps, excludedCount };
  }

  classifyAppType(app) {
    if (app._source === 'servicePrincipal') {
      return (app.passwordCredentials || []).length > 0 || (app.keyCredentials || []).length > 0
        ? 'daemon' : 'api';
    }
    const hasSpa = (app.spa?.redirectUris || []).length > 0;
    const hasWeb = (app.web?.redirectUris || []).length > 0;
    const hasPub = (app.publicClient?.redirectUris || []).length > 0;
    const hasRes = (app.requiredResourceAccess || []).length > 0;
    if (hasSpa) return 'spa';
    if (hasWeb) return 'web';
    if (hasPub) return 'native';
    if (hasRes) return 'daemon';
    return 'api';
  }

  analyzeApp(app, now, tenantId) {
    const issues = [];
    const severities = [];
    const credentialAlerts = [];
    const descParts = [];
    const fixes = [];

    // ── Client secrets ───────────────────────────────────────────────────────
    if ((app.passwordCredentials || []).length > 0) {
      issues.push('Has client secret(s)');
      severities.push('high');
      descParts.push(
        'This app uses client secrets for authentication. ' +
        'It can obtain access tokens without user interaction, completely bypassing ' +
        'Conditional Access, MFA, and passkey enforcement — those controls only apply ' +
        'to interactive user sign-ins.'
      );
      fixes.push('Migrate to certificate credentials or managed identity. Remove all client secrets once migrated.');

      app.passwordCredentials.forEach(c => {
        const end    = c.endDateTime ? new Date(c.endDateTime) : null;
        const start  = c.startDateTime ? new Date(c.startDateTime) : null;
        const label  = c.displayName || 'Secret';
        if (end) {
          const daysLeft = Math.ceil((end - now) / 86400000);
          const ageDays  = start ? Math.ceil((now - start) / 86400000) : null;
          if (end < now) {
            credentialAlerts.push({ type: 'expired', label, daysLeft: 0, severity: 'critical', expiryDate: c.endDateTime });
            issues.push(`Secret expired — ${label}`);
            severities.push('critical');
          } else if (daysLeft <= 30) {
            credentialAlerts.push({ type: 'expiring-soon', label, daysLeft, severity: 'critical', expiryDate: c.endDateTime });
            issues.push(`Secret expires in ${daysLeft}d — ${label}`);
            severities.push('critical');
          } else if (daysLeft <= 90) {
            credentialAlerts.push({ type: 'expiring', label, daysLeft, severity: 'high', expiryDate: c.endDateTime });
            issues.push(`Secret expires in ${daysLeft}d — ${label}`);
            severities.push('high');
          } else if (ageDays && ageDays > 365) {
            credentialAlerts.push({ type: 'stale', label, ageDays, severity: 'medium', expiryDate: c.endDateTime });
            issues.push(`Secret ${Math.floor(ageDays / 365)}yr old — rotation recommended`);
            severities.push('medium');
          }
        }
      });
      if (credentialAlerts.some(c => c.type === 'expired' || c.type === 'expiring-soon')) {
        fixes.unshift('Rotate expiring/expired credentials immediately to prevent service disruption.');
      }
    }

    // ── Certificate credentials ──────────────────────────────────────────────
    if ((app.keyCredentials || []).length > 0) {
      issues.push('Uses certificate credential(s)');
      severities.push('low');
      descParts.push(
        'Certificate credentials are more secure than client secrets but still allow ' +
        'machine-to-machine authentication outside CA policy scope. Ensure the certificate ' +
        'is stored in a key vault and rotated before expiry.'
      );

      app.keyCredentials.forEach(c => {
        const end   = c.endDateTime ? new Date(c.endDateTime) : null;
        const label = c.displayName || 'Certificate';
        if (end) {
          const daysLeft = Math.ceil((end - now) / 86400000);
          if (end < now) {
            credentialAlerts.push({ type: 'expired', label, daysLeft: 0, severity: 'critical', expiryDate: c.endDateTime });
            issues.push(`Certificate expired — ${label}`);
            severities.push('critical');
          } else if (daysLeft <= 30) {
            credentialAlerts.push({ type: 'expiring-soon', label, daysLeft, severity: 'critical', expiryDate: c.endDateTime });
            issues.push(`Certificate expires in ${daysLeft}d`);
            severities.push('critical');
          } else if (daysLeft <= 90) {
            credentialAlerts.push({ type: 'expiring', label, daysLeft, severity: 'high', expiryDate: c.endDateTime });
            issues.push(`Certificate expires in ${daysLeft}d`);
            severities.push('high');
          }
        }
      });
    }

    // ── App type + delegated permissions gap ─────────────────────────────────
    const appType = this.classifyAppType(app);
    const isUserFacing = appType === 'spa' || appType === 'web' || appType === 'native';
    if (isUserFacing && !(app.requiredResourceAccess || []).length) {
      issues.push('No delegated permissions — may prompt for password');
      severities.push('medium');
      descParts.push(
        'No delegated permissions are configured. Users signing in may be prompted for a ' +
        'password rather than their passkey, because the app does not request modern ' +
        'token flows (OAuth 2.0 / OIDC).'
      );
      fixes.push('Configure delegated permissions in Azure portal → App registrations → API permissions.');
    }

    // ── Multi-tenant sign-in audience ────────────────────────────────────────
    const multiTenant = app.signInAudience === 'AzureADMultipleOrgs'
      || app.signInAudience === 'AzureADandPersonalMicrosoftAccount';
    if (multiTenant) {
      issues.push('Multi-tenant: any Azure AD org can sign in');
      severities.push('medium');
      descParts.push(
        'This app accepts sign-ins from users in any Azure AD organisation. ' +
        'Your tenant\'s Conditional Access policies may not apply to external users ' +
        'authenticating through this app, leaving them outside your passkey enforcement scope.'
      );
      fixes.push('If multi-tenant access is unintentional, set Sign-in audience to "This organisation only" in App registrations → Authentication.');
    }

    // ── No owners (orphaned) ─────────────────────────────────────────────────
    const ownerCount = (app.owners || []).length;
    const isOrphaned = ownerCount === 0 && app._source === 'registration';
    if (isOrphaned) {
      issues.push('No owner — orphaned app');
      severities.push('medium');
      descParts.push(
        'No owner is assigned to this app registration. Orphaned apps have no accountable ' +
        'admin to rotate credentials, review permissions, or decommission the app when it\'s no longer needed.'
      );
      fixes.push('Assign at least one owner: App registrations → select app → Owners → Add.');
    }

    const severity = severities.includes('critical') ? 'critical'
      : severities.includes('high')   ? 'high'
      : severities.includes('medium') ? 'medium'
      : severities.includes('low')    ? 'low'
      : 'good';

    return {
      id:              app.id,
      appId:           app.appId,
      displayName:     app.displayName || app.appId || 'Unnamed',
      source:          app._source,
      appType,
      signInAudience:  app.signInAudience || 'AzureADMyOrg',
      passkeyCompatible: issues.length === 0,
      issues,
      severity,
      credentialAlerts,
      ownerCount,
      isOrphaned,
      multiTenant,
      description: descParts.join(' ') || 'No credential or configuration issues detected. This app follows modern authentication patterns compatible with passkey deployment.',
      fixGuide: fixes.length > 0 ? fixes.join(' ') : null,
      createdDateTime: app.createdDateTime || null,
      secretCount:     (app.passwordCredentials || []).length,
      certCount:       (app.keyCredentials || []).length,
    };
  }

  // ============================================================================
  // Policy Analysis — enriched per-policy + gap detection
  // ============================================================================

  analyzePolicies({ policies, users, devices, authMethodsConfig }) {
    const enriched = (policies || []).map(p => this.enrichPolicy(p));
    const gaps     = this.detectPolicyGaps(enriched, users || [], devices || [], authMethodsConfig || []);

    const enabled = enriched.filter(p => p.state === 'enabled');
    const fido2Config = authMethodsConfig.find(c =>
      c.id === 'Fido2' || (c['@odata.type'] || '').toLowerCase().includes('fido2')
    ) || null;

    const tapConfig = authMethodsConfig.find(c =>
      c.id === 'TemporaryAccessPass' || (c['@odata.type'] || '').toLowerCase().includes('temporaryaccesspass')
    ) || null;

    const summary = {
      total:        enriched.length,
      enforcing:    enabled.filter(p => p.enforcesPasskey).length,
      protecting:   enabled.filter(p => p.protectsRegistration).length,
      blocking:     enriched.filter(p => p.blocksPasskeyRegistration).length,
      criticalGaps: gaps.filter(g => g.severity === 'critical').length,
      highGaps:     gaps.filter(g => g.severity === 'high').length,
    };

    return { policies: enriched, gaps, summary, fido2Config, tapConfig };
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
    const blocksPasskeyRegistration = this.policyBlocksPasskeyRegistration(policy);

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
      fixGuide = 'Review this policy. If it blocks the security-info registration user action, ensure passkey-capable users are excluded from its scope. If it requires an authentication strength, ensure the strength includes at least one phishing-resistant combination (FIDO2, Windows Hello for Business, or device-bound push). Consider splitting into separate policies for passkey users and legacy users.';
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
        ? 'This policy prevents passkey-only users from completing the flow it governs (sign-in or security-info registration).'
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

    // ── GAP 2: Temporary Access Pass not enabled ──────────────────────────────
    const tapConfig = authMethodsConfig.find(c =>
      c.id === 'TemporaryAccessPass' || (c['@odata.type'] || '').toLowerCase().includes('temporaryaccesspass')
    );
    if (!tapConfig || tapConfig.state !== 'enabled') {
      gaps.push({
        id: 'gap-tap-disabled',
        severity: 'high',
        type: 'config',
        title: 'Temporary Access Pass (TAP) is not enabled',
        description: 'TAP is a time-limited passcode that lets admins bootstrap passkey enrollment for users who have no other MFA method — new hires, lost credential scenarios, and the initial passkey registration flow all depend on it. Without TAP, users caught by a registration CA policy (requiring proof of identity to enroll a new key) have no way to satisfy that policy on day one.',
        recommendation: 'Entra ID → Protection → Authentication methods → Temporary Access Pass → Enable. Configure isUsableOnce = true with a short lifetime (1–8 hours) for onboarding. Scope to all users or an onboarding group. Issue TAPs on demand via the Entra portal or Graph API.',
        docUrl: 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass',
        context: tapConfig
          ? 'Detected from: Authentication Methods Policy — Temporary Access Pass state is "disabled"'
          : 'Detected from: No Temporary Access Pass configuration found in Authentication Methods Policy',
      });
    }

    // ── GAP 3: No phishing-resistant MFA enforcement ──────────────────────────
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
        docUrl: 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths',
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
    const PASSKEY_METHODS = ['passKeyDeviceBound', 'fido2'];
    (users || []).forEach(u => {
      const isPrivileged = (u.groups || []).some(g => {
        if ((g['@odata.type'] || '').includes('directoryRole')) return true;
        const n = (g.displayName || '').toLowerCase();
        return n.includes('admin') || n.includes('global') || n.includes('privileged') || n.includes('exchange');
      });
      if (isPrivileged) {
        const reg        = u.registrationData || { available: false };
        const methodsReg = reg.available ? (reg.methodsRegistered || []) : [];
        const hasFido    = methodsReg.some(m => PASSKEY_METHODS.includes(m) || m.toLowerCase().startsWith('passkey'));
        const hasMfa     = reg.available ? (reg.isMfaRegistered ?? false) : null;
        // Only fire when data is available — unknown data must not produce a false critical alert.
        if (!hasFido && hasMfa === false)
          combos.push({ severity: "critical", displayName: u.displayName || u.userPrincipalName, groups: (u.groups || []).map(g => g.displayName), description: "No MFA and no passkey on high-privilege account", fix: "Enable MFA immediately. Register passkey/FIDO2 as primary auth method." });
      }
    });
    const PR = ['fido2', 'windowsHelloForBusiness', 'deviceBasedPush'];
    const vulnerablePolicies = (policies || []).filter(p => {
      if (p.state === 'disabled') return false;
      const combos = p.grantControls?.authenticationStrength?.allowedCombinations || [];
      return combos.some(c => PR.includes(c)) &&
             combos.some(c => c === 'password' || c.startsWith('password,'));
    });
    if (vulnerablePolicies.length > 0)
      combos.push({ severity: "high", displayName: "Password fallback enabled", description: vulnerablePolicies.length + " CA policies allow password fallback with passkey.", fix: "Update to require FIDO2 authentication strength." });
    return combos;
  }

  policyBlocksPasskeyRegistration(policy) {
    if (policy.state === 'disabled') return false;
    const grant      = policy.grantControls || {};
    const userActions = policy.conditions?.applications?.includeUserActions || [];
    const combos     = grant.authenticationStrength?.allowedCombinations   || [];
    const PR         = ['fido2', 'windowsHelloForBusiness', 'deviceBasedPush'];

    // (a) explicit block on the passkey registration user action
    if (grant.builtInControls?.includes('block') &&
        (userActions.includes('urn:user:registerSecurityInfo') ||
         userActions.includes('urn:user:registerbiometricinfo'))) {
      return true;
    }

    // (b) auth strength exists but offers no phishing-resistant path
    if (combos.length > 0 && !combos.some(c => PR.includes(c))) {
      return true;
    }

    return false;
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
      recs.push({ severity: "low", icon: "💡", category: "Apps", title: badApps.length + " app(s) flagged — see App Identities tab", text: badApps.map(a => a.displayName).join(", "), fix: "Review the App Identities tab for credential risk and fix guidance." });

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
