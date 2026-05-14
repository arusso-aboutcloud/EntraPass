// EntraPass Scanner - App Registration with PKCE
// Deploy this to your Entra ID tenant to create the required app registration
// for passkey readiness scanning.
//
// Usage:
//   az deployment group create --resource-group <rg> --template-file app-registration.bicep
//   OR click the "Deploy to Azure" button in the portal

@description('The base name for the app registration (will be prefixed)')
param appName string = 'entrapass-scanner'

@description('The redirect URI for the SPA (your EntraPass portal URL)')
param redirectUri string = 'http://localhost:5173'

@description('Your tenant ID (directory ID)')
param tenantId string = ''

var uniqueSuffix = uniqueString(resourceGroup().id, tenantId)
var displayName = '${appName}-${uniqueSuffix}'

// The Graph API resource App ID (Microsoft Graph)
var microsoftGraphAppId = '00000003-0000-0000-c000-000000000000'

// ============================================
// App Registration (Microsoft Graph)
// ============================================
resource appReg 'Microsoft.Graph/applications@1.0' = {
  displayName: displayName
  signInAudience: 'AzureADMyOrg'
  spa: {
    redirectUris: [
      redirectUri
      // For local development
      'http://localhost:5173'
    ]
  }
  // Required delegated permissions for Microsoft Graph
  requiredResourceAccess: [
    {
      resourceAppId: microsoftGraphAppId
      resourceAccess: [
        // User.Read - Sign in and read user profile
        {
          id: 'e1fe6dd8-ba31-4d61-89e7-88639da4923c'
          type: 'Scope'
        }
        // User.Read.All - Read all users' full profiles
        {
          id: 'df021288-bdef-4463-88db-98f22de89214'
          type: 'Scope'
        }
        // Device.Read.All - Read all devices
        {
          id: '951183d1-1a61-466f-a6d1-1f55c005e95d'
          type: 'Scope'
        }
        // Policy.Read.All - Read all conditional access policies
        {
          id: '246dd0d5-5bd0-4def-940b-0421030a5b7b'
          type: 'Scope'
        }
        // Application.Read.All - Read all applications
        {
          id: '9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30'
          type: 'Scope'
        }
        // AuditLog.Read.All - Read audit logs
        {
          id: '26456419-2c0a-41c4-9ff7-4b10e1e682df'
          type: 'Scope'
        }
        // Organization.Read.All - Read organization information
        {
          id: '130f2d35-2658-4bcb-a614-ee92b9697645'
          type: 'Scope'
        }
      ]
    }
  ]
  // No password credentials (PKCE only)
  passwordCredentials: []
  // No certificate credentials
  keyCredentials: []
}

// ============================================
// Outputs
// ============================================
output clientId string = appReg.appId
output appName string = displayName
output tenantId string = tenantId

// Instructions for the user
output instructions string = 'Deployment complete!\n\n' +
  '1. Copy your Client ID: ${appReg.appId}\n' +
  '2. Go to the EntraPass portal and enter:\n' +
  '   - Client ID: ${appReg.appId}\n' +
  '   - Tenant ID: ${tenantId}\n' +
  '3. Click "Save Configuration" and start scanning.\n\n' +
  'Note: Admin consent may be required for some permissions.\n' +
  'Go to Azure Portal > App Registrations > ${displayName} > API Permissions > Grant admin consent.'
