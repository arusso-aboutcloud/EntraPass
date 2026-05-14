export class Analyzer {
  analyzeAll(data) {
    const passkeyReadiness = this.analyzePasskeyReadiness(data);
    const appCompatibility = this.analyzeAppCompatibility(data);
    const policyAnalysis = this.analyzePolicies(data);
    const recommendations = this.generateRecommendations(passkeyReadiness, appCompatibility, policyAnalysis);
    
    return {
      passkeyReadiness,
      apps: appCompatibility,
      policies: policyAnalysis,
      recommendations,
      timestamp: new Date().toISOString(),
    };
  }

  analyzePasskeyReadiness({ users = [], devices = [], policies = [] }) {
    const result = {
      total: users.length,
      ready: 0,
      needsAttention: 0,
      blocked: 0,
      users: [],
    };

    // Identify policies that block passkey registration
    const blockingPolicies = policies.filter(p => this.policyBlocksPasskeyRegistration(p));

    users.forEach(user => {
      const issues = [];
      
      // Check device readiness
      const userDevices = devices.filter(d => 
        d.deviceId && user.userPrincipalName && 
        // Simplistic check - in real impl we'd check device registration owner
        true
      );
      
      const hasModernDevice = userDevices.some(d => 
        d.operatingSystem === 'Windows' && 
        parseInt(d.operatingSystemVersion) >= 10
      ) || userDevices.some(d => 
        d.operatingSystem === 'iOS' && parseInt(d.operatingSystemVersion) >= 16
      ) || userDevices.some(d => 
        d.operatingSystem === 'Android' && parseInt(d.operatingSystemVersion) >= 14
      ) || userDevices.some(d => 
        d.operatingSystem === 'macOS' && parseInt(d.operatingSystemVersion) >= 13
      );

      if (!hasModernDevice && userDevices.length > 0) {
        issues.push('Device OS too old for passkeys');
      }
      
      if (userDevices.length === 0) {
        issues.push('No registered devices found');
      }

      // Check if any policy blocks this user
      const userBlockingPolicies = blockingPolicies.filter(p => {
        if (p.conditions?.users?.includeUsers?.includes('All')) return true;
        if (p.conditions?.users?.includeUsers?.includes(user.id)) return true;
        return false;
      });

      userBlockingPolicies.forEach(p => {
        issues.push('Blocked by CA policy: ' + p.displayName);
      });

      // Determine status
      let status = 'ready';
      if (issues.length > 0) {
        const hasBlockers = issues.some(i => i.startsWith('Blocked by'));
        status = hasBlockers ? 'blocked' : 'attention';
      }

      if (status === 'ready') result.ready++;
      else if (status === 'attention') result.needsAttention++;
      else result.blocked++;

      result.users.push({
        id: user.id,
        displayName: user.displayName || user.userPrincipalName,
        userPrincipalName: user.userPrincipalName,
        status,
        issues,
      });
    });

    return result;
  }

  analyzeAppCompatibility({ apps = [] }) {
    return apps.map(app => {
      let passkeyCompatible = true;
      let passkeyIssue = null;

      // Check if app uses legacy auth protocols
      const hasLegacyAuth = app.requiredResourceAccess?.some(access => {
        return access.resourceAccess?.some(ra => {
          // OAuth legacy scopes that indicate older auth patterns
          return ra.type === 'Scope' && (
            ra.id?.includes('openid') ||
            ra.id?.includes('offline_access')
          );
        });
      });

      // Apps with signInAudience restricted to older tenants
      if (app.signInAudience === 'AzureADMyOrg' && !app.requiredResourceAccess?.length) {
        passkeyCompatible = false;
        passkeyIssue = 'No delegated permissions configured - may use legacy auth';
      }

      // Check if app uses password-based auth (ROPC)
      if (app.passwordCredentials?.length > 0) {
        passkeyCompatible = false;
        passkeyIssue = 'Uses password credentials (ROPC flow not compatible with passkeys)';
      }

      return {
        id: app.id,
        displayName: app.displayName,
        signInAudience: app.signInAudience,
        passkeyCompatible,
        passkeyIssue,
      };
    });
  }

  analyzePolicies({ policies = [] }) {
    return policies.map(policy => {
      const blocksPasskeyRegistration = this.policyBlocksPasskeyRegistration(policy);
      let recommendation = null;

      if (blocksPasskeyRegistration) {
        recommendation = 'Consider adding passkey authentication strength or removing grant control that blocks passkeys';
      }

      return {
        id: policy.id,
        displayName: policy.displayName,
        blocksPasskeyRegistration,
        recommendation,
        details: {
          grantControls: policy.grantControls,
          conditions: policy.conditions,
          state: policy.state,
        },
      };
    });
  }

  policyBlocksPasskeyRegistration(policy) {
    if (policy.state === 'disabled') return false;

    const grantControls = policy.grantControls;
    if (!grantControls) return false;

    // Check if policy explicitly blocks modern auth
    const authenticationStrength = grantControls.authenticationStrength;
    if (authenticationStrength) {
      // Some authentication strengths may not include passkey (FIDO2)
      // This is a simplified check
      return false; // Would need detailed auth strength analysis
    }

    // Check for built-in controls that block passkeys
    if (grantControls.builtInControls) {
      // If it requires "password" as a control, it blocks passkey-only auth
      if (grantControls.builtInControls.includes('password')) {
        return true;
      }
    }

    return false;
  }

  generateRecommendations(passkeyReadiness, appCompatibility, policyAnalysis) {
    const recommendations = [];

    // High severity
    const blockedCount = passkeyReadiness.blocked;
    if (blockedCount > 0) {
      recommendations.push({
        severity: 'high',
        text: ${blockedCount} user(s) are blocked from using passkeys. Review CA policies blocking FIDO2/Passkey authentication.,
      });
    }

    const blockingPolicies = policyAnalysis.filter(p => p.blocksPasskeyRegistration);
    blockingPolicies.forEach(p => {
      recommendations.push({
        severity: 'high',
        text: CA policy "" blocks passkey registration. ,
      });
    });

    // Medium severity
    const attentionCount = passkeyReadiness.needsAttention;
    if (attentionCount > 0) {
      recommendations.push({
        severity: 'medium',
        text: ${attentionCount} user(s) need attention. Most common issue: devices not registered or outdated. Guide users through device registration.,
      });
    }

    const incompatibleApps = appCompatibility.filter(a => !a.passkeyCompatible);
    if (incompatibleApps.length > 0) {
      recommendations.push({
        severity: 'medium',
        text: ${incompatibleApps.length} app(s) may not support passkey authentication. Review apps: ,
      });
    }

    // Good news
    if (passkeyReadiness.ready > 0) {
      recommendations.push({
        severity: 'low',
        text: ${passkeyReadiness.ready} user(s) are ready for passkeys now. Start a pilot group!,
      });
    }

    if (recommendations.length === 0) {
      recommendations.push({
        severity: 'low',
        text: 'Your tenant looks ready for passkey migration. Great job!',
      });
    }

    return recommendations;
  }
}
