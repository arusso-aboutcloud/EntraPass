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
          id: 'e1fe6dd8-ba31-4d61-89e7-88639da4683d'
          type: 'Scope'
        }
        // User.Read.All - Read all users' full profiles
        {
          id: 'a154be20-db9c-4678-8ab7-66f6cc099a59'
          type: 'Scope'
        }
        // Device.Read.All - Read all devices
        {
          id: '951183d1-1a61-466f-a6d1-1fde911bfd95'
          type: 'Scope'
        }
        // Policy.Read.All - Read all conditional access policies
        {
          id: '572fea84-0151-49b2-9301-11cb16974376'
          type: 'Scope'
        }
        // Application.Read.All - Read all applications
        {
          id: 'c79f8feb-a9db-4090-85f9-90d820caa0eb'
          type: 'Scope'
        }
        // AuditLog.Read.All - Read audit logs
        {
          id: 'e4c9e354-4dc5-45b8-9e7c-e1393b0b1a20'
          type: 'Scope'
        }
        // Organization.Read.All - Read organization information
        {
          id: '4908d5b9-3fb2-4b1e-9336-1888b7937185'
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
