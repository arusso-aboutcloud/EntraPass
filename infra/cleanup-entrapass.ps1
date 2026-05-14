<#
.SYNOPSIS
    Cleanup EntraPass scanner app registration from your tenant.
.DESCRIPTION
    Removes the EntraPass scanner app registration and optionally revokes admin consent.
    Run this after you're done scanning to clean up.
.PARAMETER ClientId
    The Client ID of the EntraPass scanner app to remove.
.PARAMETER RevokeConsent
    Also revoke all delegated permissions admin consent.
.EXAMPLE
    .\cleanup-entrapass.ps1 -ClientId "11111111-2222-3333-4444-555555555555"
.EXAMPLE
    .\cleanup-entrapass.ps1 -ClientId "11111111-2222-3333-4444-555555555555" -RevokeConsent
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [switch]$RevokeConsent
)

$ErrorActionPreference = "Stop"

Write-Host "?? EntraPass Cleanup" -ForegroundColor Cyan
Write-Host "===================" -ForegroundColor Cyan

# Check if Microsoft Graph PowerShell module is installed
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Applications)) {
    Write-Host "? Installing Microsoft.Graph.Applications module..." -ForegroundColor Yellow
    Install-Module Microsoft.Graph.Applications -Scope CurrentUser -Force -AllowClobber
}

# Connect to Microsoft Graph
Write-Host "? Connecting to Microsoft Graph (requires Application.ReadWrite.All permission)..." -ForegroundColor Yellow
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Find the app
Write-Host "? Looking up app registration with Client ID: $ClientId..." -ForegroundColor Yellow
$app = Get-MgApplication -Filter "appId eq '$ClientId'" -ErrorAction SilentlyContinue

if (-not $app) {
    Write-Host "? No app registration found with Client ID: $ClientId. Nothing to clean up." -ForegroundColor Green
    Disconnect-MgGraph
    exit 0
}

Write-Host "? Found: $($app.DisplayName) ($($app.Id))" -ForegroundColor Yellow

# Remove the app
Write-Host "? Removing app registration..." -ForegroundColor Yellow
Remove-MgApplication -ApplicationId $app.Id -Confirm:$false
Write-Host "? App registration removed successfully." -ForegroundColor Green

# Optionally revoke admin consent
if ($RevokeConsent) {
    Write-Host "? Revoking admin consent for delegated permissions..." -ForegroundColor Yellow
    try {
        $sp = Get-MgServicePrincipal -Filter "appId eq '$ClientId'" -ErrorAction SilentlyContinue
        if ($sp) {
            Remove-MgServicePrincipal -ServicePrincipalId $sp.Id -Confirm:$false
            Write-Host "? Service principal and consent removed." -ForegroundColor Green
        }
    } catch {
        Write-Host "? No service principal found to revoke. Already clean." -ForegroundColor Green
    }
}

Write-Host "`n?? Cleanup complete!" -ForegroundColor Cyan
Write-Host "?? All EntraPass scanner artifacts removed from your tenant." -ForegroundColor Cyan

Disconnect-MgGraph
