# EntraPass App Registration Deployment Script
# Run this in Azure Cloud Shell (PowerShell) to create the scanner app registration

$appName = "entrapass-scanner"
$redirectUri = Read-Host "Enter your EntraPass portal URL (e.g., https://entrapass.pages.dev)"

Write-Host "?? Installing Microsoft.Graph module..." -ForegroundColor Cyan
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop

Write-Host "? Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "Application.ReadWrite.All","DelegatedPermissionGrant.ReadWrite.All"

Write-Host "?? Creating App Registration..." -ForegroundColor Cyan
$app = New-MgApplication `
  -DisplayName $appName `
  -SignInAudience "AzureADMyOrg" `
  -Spa @{ RedirectUris = @($redirectUri) } `
  -RequiredResourceAccess @(
    @{
      ResourceAppId = "00000003-0000-0000-c000-000000000000"
      ResourceAccess = @(
        @{ Id = "e1fe6dd8-ba31-4d61-89e7-88639da4923c"; Type = "Scope" }  # User.Read
        @{ Id = "df021288-bdef-4463-88db-98f22de89214"; Type = "Scope" }  # User.Read.All
        @{ Id = "951183d1-1a61-466f-a6d1-1f55c005e95d"; Type = "Scope" }  # Device.Read.All
        @{ Id = "246dd0d5-5bd0-4def-940b-0421030a5b7b"; Type = "Scope" }  # Policy.Read.All
        @{ Id = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"; Type = "Scope" }  # Application.Read.All
        @{ Id = "26456419-2c0a-41c4-9ff7-4b10e1e682df"; Type = "Scope" }  # AuditLog.Read.All
        @{ Id = "130f2d35-2658-4bcb-a614-ee92b9697645"; Type = "Scope" }  # Organization.Read.All
      )
    }
  )

Write-Host "?? App Registration created!" -ForegroundColor Green
Write-Host "  Display Name: $($app.DisplayName)" -ForegroundColor Cyan
Write-Host "  Client ID:    $($app.AppId)" -ForegroundColor Cyan
Write-Host "  Tenant ID:    $((Get-MgContext).TenantId)" -ForegroundColor Cyan

Write-Host "`n?? Granting admin consent..." -ForegroundColor Cyan
# Find the service principal
$sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'"
if (-not $sp) {
  Write-Host "? Service principal not found. Admin consent must be granted manually in Azure Portal." -ForegroundColor Yellow
  Write-Host "  Go to: Azure Portal > App Registrations > $($app.DisplayName) > API Permissions > Grant admin consent" -ForegroundColor Yellow
} else {
  Write-Host "? Admin consent granted (or already granted)." -ForegroundColor Green
}

Write-Host "`n?? Next steps:" -ForegroundColor Cyan
Write-Host "1. Copy the Client ID above: $($app.AppId)" -ForegroundColor White
Write-Host "2. Go to your EntraPass portal" -ForegroundColor White
Write-Host "3. Enter Client ID and Tenant ID" -ForegroundColor White
Write-Host "4. Start scanning!" -ForegroundColor White

Disconnect-MgGraph
