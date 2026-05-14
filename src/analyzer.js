export class Analyzer {
  analyzeAll(data) {
    const passkeyReadiness = this.analyzePasskeyReadiness(data);
    const appCompatibility = this.analyzeAppCompatibility(data);
    const policyAnalysis = this.analyzePolicies(data);
    const recommendations = this.generateRecommendations(passkeyReadiness, appCompatibility, policyAnalysis);
    return { passkeyReadiness, apps: appCompatibility, policies: policyAnalysis, recommendations, timestamp: new Date().toISOString() };
  }

  analyzePasskeyReadiness({ users = [], devices = [], policies = [] }) {
    const result = { total: users.length, ready: 0, needsAttention: 0, blocked: 0, users: [] };
    const blockingPolicies = policies.filter(p => this.policyBlocksPasskeyRegistration(p));
    users.forEach(user => {
      const issues = [];
      const hasModernDevice = devices.some(d =>
        (d.operatingSystem === 'Windows'
         && parseInt(d.operatingSystemVersion) >= 10)
        || (d.operatingSystem === 'iOS'
         && parseInt(d.operatingSystemVersion) >= 16)
        || (d.operatingSystem === 'Android'
         && parseInt(d.operatingSystemVersion) >= 14)
        || (d.operatingSystem === 'macOS'
         && parseInt(d.operatingSystemVersion) >= 13));
      if (devices.length === 0) issues.push('No registered devices');
      if (!hasModernDevice
         && devices.length > 0)
        issues.push('Device OS too old for passkeys');
      blockingPolicies
        .filter(p =>
          p.conditions?.users?.includeUsers?.includes('All')
          || p.conditions?.users?.includeUsers?.includes(user.id))
        .forEach(p =>
          issues.push('Blocked by CA policy: '
            + p.displayName));
      let status = 'ready';
      if (issues.length > 0)
        status = issues.some(i => i.startsWith('Blocked by'))
          ? 'blocked' : 'attention';
      if (status === 'ready') result.ready++;
      else if (status === 'attention') result.needsAttention++;
      else result.blocked++;
      result.users.push({
        id: user.id,
        displayName: user.displayName || user.userPrincipalName,
        userPrincipalName: user.userPrincipalName,
        status, issues,
      });
    });
    return result;
  }
  analyzeAppCompatibility({ apps = [] }) {
    return apps.map(app => {
      let passkeyCompatible = true, passkeyIssue = null;
      if (app.signInAudience === 'AzureADMyOrg'
          && !app.requiredResourceAccess?.length) {
        passkeyCompatible = false;
        passkeyIssue = 'No delegated permissions';
      }
      if (app.passwordCredentials?.length > 0) {
        passkeyCompatible = false;
        passkeyIssue = 'Uses ROPC - not compatible';
      }
      return { id: app.id, displayName: app.displayName,
        passkeyCompatible, passkeyIssue };
    });
  }

  analyzePolicies({ policies = [] }) {
    return policies.map(policy => {
      const blocks = this.policyBlocksPasskeyRegistration(policy);
      return {
        id: policy.id,
        displayName: policy.displayName,
        blocksPasskeyRegistration: blocks,
        recommendation: blocks
          ? 'Consider removing grant control that blocks passkeys'
          : null,
      };
    });
  }

  policyBlocksPasskeyRegistration(policy) {
    if (policy.state === 'disabled') return false;
    return policy.grantControls?.builtInControls
      ?.includes('password') || false;
  }

  generateRecommendations(passkeyReadiness, appCompatibility, policyAnalysis) {
    const recs = [];
    if (passkeyReadiness.blocked > 0) {
      recs.push({
        severity: 'high',
        text: `'${passkeyReadiness.blocked}'` + ' user(s) blocked. Review CA policies.',
      });
    }
    policyAnalysis.filter(p => p.blocksPasskeyRegistration)
      .forEach(p => {
        recs.push({
          severity: 'high',
          text: 'CA policy "' + p.displayName + '" blocks passkeys.',
        });
      });
    if (passkeyReadiness.needsAttention > 0) {
      recs.push({
        severity: 'medium',
        text: `'${passkeyReadiness.needsAttention}'` + ' user(s) need attention. Guide device registration.',
      });
    }
    const badApps = appCompatibility.filter(a => !a.passkeyCompatible);
    if (badApps.length > 0) {
      recs.push({
        severity: 'medium',
        text: `'${badApps.length}'` + ' app(s) not compatible: '
          + badApps.map(a => a.displayName).join(', '),
      });
    }
    if (passkeyReadiness.ready > 0) {
      recs.push({
        severity: 'low',
        text: `'${passkeyReadiness.ready}'` + ' user(s) ready. Start pilot!',
      });
    }
    if (recs.length === 0) {
      recs.push({ severity: 'low', text: 'Tenant looks ready!' });
    }
    return recs;
  }
}
