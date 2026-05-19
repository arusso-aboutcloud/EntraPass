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
  // Errors carry `.httpStatus` so callers can distinguish 403/429/5xx.
  async fetch(path) {
    const token = await this.getToken();
    const resp = await fetch(this.baseUrl + path, {
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json',
      },
    });

    if (!resp.ok) {
      const body = await resp.text().catch(() => '');
      console.error(`Graph API ${resp.status} for ${path}:`, body);
      const err = new Error(`Graph API error (${resp.status}) for ${path}`);
      err.httpStatus = resp.status;
      throw err;
    }

    return resp.json();
  }

  // Fetches a collection, following @odata.nextLink so results are not
  // silently truncated at Graph's default page size.
  // Errors carry `.httpStatus` so callers can distinguish 403/429/5xx.
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
        const err = new Error(`Graph API error (${resp.status})`);
        err.httpStatus = resp.status;
        throw err;
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

  // Bulk fetch of authentication registration state for all enabled users.
  // Uses /reports/authenticationMethods/userRegistrationDetails (requires
  // AuditLog.Read.All + Reports Reader or equivalent — see
  // https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails).
  // Note: disabled users are not returned by this endpoint.
  // Returns a tri-state object so callers can distinguish real data from
  // a permission or availability failure.
  async getUserRegistrationDetails() {
    try {
      const records = await this.fetchAll(
        '/reports/authenticationMethods/userRegistrationDetails'
      );
      return { available: true, reason: 'ok', records };
    } catch (err) {
      const s = err.httpStatus;
      const reason = s === 403 ? 'permission_denied'
                   : s === 429 ? 'http_429'
                   : s >= 500  ? 'http_5xx'
                   : 'network_error';
      console.error('getUserRegistrationDetails failed:', reason, err.message);
      return { available: false, reason, records: [] };
    }
  }

  // signInActivity is a user-resource property, not a navigation endpoint,
  // so it must be retrieved via $select on the user object.
  // Returns a tri-state object: { available, reason,
  //   lastSuccessfulSignInDateTime, lastSignInDateTime,
  //   lastNonInteractiveSignInDateTime }
  // Available only for tenants with Azure AD P1/P2 licences; requires
  // AuditLog.Read.All. See
  // https://learn.microsoft.com/en-us/graph/api/resources/signinactivity
  async getUserSignInActivity(userId) {
    try {
      const data = await this.fetch(
        '/users/' + encodeURIComponent(userId) + '?$select=signInActivity'
      );
      const sia = data.signInActivity;
      if (!sia) return { available: false, reason: 'no_record' };
      return {
        available: true,
        reason: 'ok',
        lastSuccessfulSignInDateTime: sia.lastSuccessfulSignInDateTime || null,
        lastSignInDateTime: sia.lastSignInDateTime || null,
        lastNonInteractiveSignInDateTime: sia.lastNonInteractiveSignInDateTime || null,
      };
    } catch (err) {
      const s = err.httpStatus;
      const reason = s === 403 ? 'permission_denied'
                   : s === 429 ? 'http_429'
                   : s >= 500  ? 'http_5xx'
                   : 'network_error';
      return { available: false, reason };
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
        '/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,verifiedPublisher,passwordCredentials,keyCredentials,servicePrincipalType,signInAudience,createdDateTime&$top=999'
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
