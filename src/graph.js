export class GraphAPI {
  constructor(msalInstance, scopes) {
    this.msalInstance = msalInstance;
    this.scopes = scopes;
    this.baseUrl = 'https://graph.microsoft.com/v1.0';
  }

  async getToken() {
    const account = this.msalInstance.getActiveAccount();
    if (!account) throw new Error('No active account');
    
    const resp = await this.msalInstance.acquireTokenSilent({
      scopes: this.scopes,
      account,
    });
    return resp.accessToken;
  }

  async fetch(path) {
    const token = await this.getToken();
    const resp = await fetch(this.baseUrl + path, {
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json',
      },
    });
    
    if (!resp.ok) {
      const err = await resp.text();
      throw new Error('Graph API error: ' + err);
    }
    
    return resp.json();
  }

  async getOrganization() {
    const data = await this.fetch('/organization');
    return data.value?.[0] || null;
  }

  async getUsers() {
    const data = await this.fetch('/users?=id,displayName,userPrincipalName,userType,createdDateTime&=999');
    return data.value || [];
  }

  async getDevices() {
    const data = await this.fetch('/devices?=id,displayName,deviceId,operatingSystem,operatingSystemVersion,isCompliant,isManaged,trustType&=999');
    return data.value || [];
  }

  async getConditionalAccessPolicies() {
    const data = await this.fetch('/identity/conditionalAccess/policies');
    return data.value || [];
  }

  async getApplications() {
    const data = await this.fetch('/applications?=id,displayName,signInAudience,requiredResourceAccess&=999');
    return data.value || [];
  }

  async getAuthenticationMethods() {
    const data = await this.fetch('/users?=id,displayName,userPrincipalName&=authenticationMethods&=999');
    return data.value || [];
  }

  async getSignInLogs(filter) {
    const url = '/auditLogs/signIns' + (filter ? '?=' + encodeURIComponent(filter) : '') + '&=999';
    const data = await this.fetch(url);
    return data.value || [];
  }
}
