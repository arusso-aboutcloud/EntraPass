<#
.SYNOPSIS
    Cleanup the EntraPass scanner app registration from your tenant.
.DESCRIPTION
    Removes the EntraPass scanner app registration and optionally revokes admin
    consent (by deleting the service principal). Run this after you are done
    scanning to clean up.
.PARAMETER ClientId
    The Client ID (Application ID) of the EntraPass scanner app to remove.
.PARAMETER RevokeConsent
    Also delete the service principal, which removes admin consent.
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

Write-Host "EntraPass Cleanup" -ForegroundColor Cyan
Write-Host "=================" -ForegroundColor Cyan

# Microsoft.Graph.Applications pulls in a version-matched
# Microsoft.Graph.Authentication; import it before connecting.
if (-not (Get-Module -ListAvailable Microsoft.Graph.Applications)) {
    Write-Host "Installing Microsoft.Graph.Applications module (one-time)..." -ForegroundColor Yellow
    Install-Module Microsoft.Graph.Applications -Scope CurrentUser -Force -AllowClobber
}
try {
    Import-Module Microsoft.Graph.Applications -ErrorAction Stop
} catch {
    Write-Host "ERROR: A conflicting Microsoft.Graph.Authentication assembly is already loaded." -ForegroundColor Red
    Write-Host "Close this window, open a NEW PowerShell session, and run this script again." -ForegroundColor Red
    return
}

Write-Host "Connecting to Microsoft Graph (requires Application.ReadWrite.All)..." -ForegroundColor Yellow
Connect-MgGraph -Scopes "Application.ReadWrite.All" -NoWelcome

Write-Host "Looking up app registration with Client ID: $ClientId..." -ForegroundColor Yellow
$app = Get-MgApplication -Filter "appId eq '$ClientId'" -ErrorAction SilentlyContinue

if (-not $app) {
    Write-Host "No app registration found with Client ID: $ClientId. Nothing to clean up." -ForegroundColor Green
    Disconnect-MgGraph | Out-Null
    return
}

Write-Host "Found: $($app.DisplayName) ($($app.Id))" -ForegroundColor Yellow

# Optionally delete the service principal (revokes admin consent).
if ($RevokeConsent) {
    Write-Host "Revoking admin consent (deleting the service principal)..." -ForegroundColor Yellow
    $sp = Get-MgServicePrincipal -Filter "appId eq '$ClientId'" -ErrorAction SilentlyContinue
    if ($sp) {
        Remove-MgServicePrincipal -ServicePrincipalId $sp.Id -Confirm:$false
        Write-Host "Service principal and consent removed." -ForegroundColor Green
    } else {
        Write-Host "No service principal found. Already clean." -ForegroundColor Green
    }
}

Write-Host "Removing app registration..." -ForegroundColor Yellow
Remove-MgApplication -ApplicationId $app.Id -Confirm:$false
Write-Host "App registration removed successfully." -ForegroundColor Green

Write-Host ""
Write-Host "Cleanup complete. All EntraPass scanner artifacts removed from your tenant." -ForegroundColor Cyan

Disconnect-MgGraph | Out-Null
