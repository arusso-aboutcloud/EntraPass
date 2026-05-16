export class GraphAPI {
  constructor(msalInstance, scopes) {
    this.msalInstance = msalInstance;
    this.scopes = scopes;
    this.baseUrl = 'https://graph.microsoft.com/v1.0';
  }

  async getToken() {
    const account = this.msalInstance.getActiveAccount()
      || this.msalInstance.getAllAccounts()[0];
    if (!account) throw new Error('No active account. Please sign in again.');

    try {
      const resp = await this.msalInstance.acquireTokenSilent({ scopes: this.scopes, account });
      return resp.accessToken;
    } catch (err) {
      // Silent acquisition can fail when the session/refresh token has expired
      // or additional consent is required. Fall back to an interactive redirect.
      console.warn('Silent token acquisition failed, redirecting for interaction:', err);
      await this.msalInstance.acquireTokenRedirect({ scopes: this.scopes, account });
      throw new Error('Re-authentication required.');
    }
  }

  // Fetches a single Graph resource. `path` is relative to baseUrl.
  async fetch(path) {
    const token = await this.getToken();
    const resp = await fetch(this.baseUrl + path, {
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json',
      },
    });

    if (!resp.ok) {
      // Log the raw body for debugging, but do not surface it to the UI.
      const body = await resp.text().catch(() => '');
      console.error(`Graph API ${resp.status} for ${path}:`, body);
      throw new Error(`Graph API error (${resp.status}) for ${path}`);
    }

    return resp.json();
  }

  // Fetches a collection, following @odata.nextLink so results are not
  // silently truncated at Graph's default page size.
  async fetchAll(path) {
    const results = [];
    let next = this.baseUrl + path;
    let guard = 0;
    while (next && guard < 100) {
      guard++;
      const token = await this.getToken();
      const resp = await fetch(next, {
        headers: {
          'Authorization': 'Bearer ' + token,
          'Content-Type': 'application/json',
        },
      });
      if (!resp.ok) {
        const body = await resp.text().catch(() => '');
        console.error(`Graph API ${resp.status} for ${next}:`, body);
        throw new Error(`Graph API error (${resp.status})`);
      }
      const data = await resp.json();
      if (Array.isArray(data.value)) results.push(...data.value);
      next = data['@odata.nextLink'] || null;
    }
    return results;
  }

  async getOrganization() {
    const data = await this.fetch('/organization?$select=id,displayName,verifiedDomains');
    return data.value?.[0] || null;
  }

  async getUsers() {
    return this.fetchAll(
      '/users?$select=id,displayName,userPrincipalName,userType,createdDateTime&$top=999'
    );
  }

  async getDevices() {
    return this.fetchAll(
      '/devices?$select=id,displayName,deviceId,operatingSystem,operatingSystemVersion,isCompliant,isManaged,trustType&$top=999'
    );
  }

  async getConditionalAccessPolicies() {
    return this.fetchAll('/identity/conditionalAccess/policies');
  }

  async getApplications() {
    return this.fetchAll(
      '/applications?$select=id,appId,displayName,signInAudience,publisherDomain,requiredResourceAccess,passwordCredentials,keyCredentials,publicClient,web,spa,createdDateTime&$top=999'
    );
  }

  async getApplicationOwners(appObjectId) {
    try {
      const data = await this.fetch(
        '/applications/' + encodeURIComponent(appObjectId) + '/owners?$select=id,displayName'
      );
      return data.value || [];
    } catch {
      return [];
    }
  }

  async getAuthenticationMethodsForUser(userId) {
    try {
      const data = await this.fetch('/users/' + encodeURIComponent(userId) + '/authenticationMethods');
      return data.value || [];
    } catch {
      return [];
    }
  }

  // signInActivity is a property of the user resource, not a navigation
  // endpoint, so it must be retrieved via $select on the user object.
  async getUserSignInActivity(userId) {
    try {
      const data = await this.fetch(
        '/users/' + encodeURIComponent(userId) + '?$select=signInActivity'
      );
      return data.signInActivity || {};
    } catch {
      return {};
    }
  }

  async getUserMemberOf(userId) {
    try {
      const data = await this.fetch(
        '/users/' + encodeURIComponent(userId) + '/memberOf?$select=id,displayName'
      );
      return data.value || [];
    } catch {
      return [];
    }
  }

  async getDeviceRegisteredOwners(deviceId) {
    try {
      const data = await this.fetch(
        '/devices/' + encodeURIComponent(deviceId) + '/registeredOwners?$select=id,displayName,userPrincipalName'
      );
      return data.value || [];
    } catch {
      return [];
    }
  }

  async getServicePrincipals() {
    try {
      return await this.fetchAll(
        '/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,passwordCredentials,keyCredentials,servicePrincipalType,publisherName,signInAudience,createdDateTime&$top=999'
      );
    } catch {
      return [];
    }
  }

  async getAuthorizationPolicy() {
    try {
      return await this.fetch('/policies/authorizationPolicy');
    } catch {
      return {};
    }
  }

  async getAuthenticationMethodsPolicy() {
    try {
      return await this.fetchAll(
        '/policies/authenticationMethodsPolicy/authenticationMethodConfigurations'
      );
    } catch {
      return [];
    }
  }

  async getSignInLogs(filter) {
    const query = filter ? '?$filter=' + encodeURIComponent(filter) + '&$top=999' : '?$top=999';
    return this.fetchAll('/auditLogs/signIns' + query);
  }
}
