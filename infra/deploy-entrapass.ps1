# EntraPass App Registration Deployment Script
#
# Creates the "entrapass-scanner" app registration (PKCE-only SPA, no secret)
# with the 7 read-only Microsoft Graph delegated permissions EntraPass needs,
# creates its service principal, and grants admin consent.
#
# Run it in Azure Cloud Shell (https://shell.azure.com, PowerShell) where the
# Microsoft.Graph modules are preinstalled and version-matched:
#
#   irm https://raw.githubusercontent.com/arusso-aboutcloud/EntraPass/main/infra/deploy-entrapass.ps1 | iex
#
# It is idempotent: re-running it finds the existing app instead of duplicating it.

function Invoke-EntraPassDeploy {
    $ErrorActionPreference = "Stop"
    $appName = "entrapass-scanner"

    # --- Portal URL (where EntraPass is hosted) -----------------------------
    # The hosted build lives at entrapass.aboutcloud.io, so that is the default.
    # Press Enter to accept it; only type something if you self-host.
    $defaultUri = "https://entrapass.aboutcloud.io"
    $redirectUri = Read-Host "EntraPass portal URL [press Enter for $defaultUri]"
    if ([string]::IsNullOrWhiteSpace($redirectUri)) { $redirectUri = $defaultUri }
    $redirectUri = $redirectUri.TrimEnd("/")
    # Auto-add https:// if the user omitted the scheme (Graph rejects bare hostnames).
    if ($redirectUri -notmatch '^https?://') { $redirectUri = 'https://' + $redirectUri }

    # --- Microsoft Graph modules -------------------------------------------
    # Microsoft.Graph.Applications pulls in a version-matched
    # Microsoft.Graph.Authentication. Import it BEFORE anything else loads a
    # mismatched Authentication assembly (a bare Connect-MgGraph would).
    Write-Host "Checking Microsoft Graph PowerShell modules..." -ForegroundColor Cyan
    if (-not (Get-Module -ListAvailable Microsoft.Graph.Applications)) {
        Write-Host "Installing Microsoft.Graph.Applications (one-time)..." -ForegroundColor Cyan
        Install-Module Microsoft.Graph.Applications -Scope CurrentUser -Force -AllowClobber
    }
    try {
        Import-Module Microsoft.Graph.Applications -ErrorAction Stop
    } catch {
        Write-Host ""
        Write-Host "ERROR: A conflicting Microsoft.Graph.Authentication assembly is already" -ForegroundColor Red
        Write-Host "loaded in this PowerShell session, so the Applications module cannot load." -ForegroundColor Red
        Write-Host "Close this window, open a NEW PowerShell session, and run this script again" -ForegroundColor Red
        Write-Host "before running any other Microsoft.Graph commands." -ForegroundColor Red
        Write-Host ""
        Write-Host "Tip: Azure Cloud Shell (https://shell.azure.com) has matched modules ready." -ForegroundColor Yellow
        return
    }

    # --- Connect ------------------------------------------------------------
    Write-Host "Connecting to Microsoft Graph (a sign-in prompt will appear)..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes "Application.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All" -NoWelcome

    $graphAppId = "00000003-0000-0000-c000-000000000000"

    # --- Find existing or create new app registration ----------------------
    $app = Get-MgApplication -Filter "displayName eq '$appName'" -All -ErrorAction Stop | Select-Object -First 1
    if ($app) {
        Write-Host "Found existing app registration '$appName'." -ForegroundColor Yellow
        $uris = @($app.Spa.RedirectUris)
        if ($uris -notcontains $redirectUri) {
            Update-MgApplication -ApplicationId $app.Id `
                -Spa @{ RedirectUris = @($uris + $redirectUri | Where-Object { $_ } | Select-Object -Unique) } `
                -ErrorAction Stop
            Write-Host "Added redirect URI: $redirectUri" -ForegroundColor Green
        }
    } else {
        Write-Host "Creating app registration '$appName'..." -ForegroundColor Cyan
        try {
            $app = New-MgApplication `
                -DisplayName $appName `
                -SignInAudience "AzureADMyOrg" `
                -Spa @{ RedirectUris = @($redirectUri) } `
                -ErrorAction Stop
        } catch {
            Write-Host ""
            Write-Host "ERROR: Failed to create app registration." -ForegroundColor Red
            Write-Host "  Redirect URI used: $redirectUri" -ForegroundColor Red
            Write-Host "  Graph error: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "  Ensure the redirect URI starts with https:// and your account has" -ForegroundColor Red
            Write-Host "  the Application Developer role (or higher) in this tenant." -ForegroundColor Red
            return
        }
        if (-not $app -or -not $app.AppId) {
            Write-Host "ERROR: New-MgApplication returned no object. Aborting." -ForegroundColor Red
            return
        }
        Write-Host "App registration created: $($app.AppId)" -ForegroundColor Green
    }

    # --- Service principal (needed before consent can be granted) ----------
    $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $sp) {
        try {
            $sp = New-MgServicePrincipal -AppId $app.AppId -ErrorAction Stop
        } catch {
            Write-Host "ERROR: Failed to create service principal: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
        if (-not $sp -or -not $sp.Id) {
            Write-Host "ERROR: New-MgServicePrincipal returned no object. Aborting." -ForegroundColor Red
            return
        }
        Write-Host "Service principal created." -ForegroundColor Green
    }

    # --- Set app registration logo ------------------------------------------
    try {
        $logoUrl = "https://raw.githubusercontent.com/arusso-aboutcloud/EntraPass/main/infra/entrapass_appreg_logo.png"
        $logoBytes = (Invoke-WebRequest -Uri $logoUrl -UseBasicParsing).Content
        Invoke-MgGraphRequest -Method PUT `
            -Uri "https://graph.microsoft.com/v1.0/applications/$($app.Id)/logo" `
            -Body $logoBytes -ContentType "image/png" | Out-Null
        Write-Host "App registration logo set." -ForegroundColor Green
    } catch {
        Write-Host "Logo upload skipped (non-critical): $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # --- Grant admin consent for all 7 delegated scopes --------------------
    $consentGranted = $false
    try {
        $graphSp = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'"
        $scopeString = "User.Read User.Read.All Device.Read.All Policy.Read.All Application.Read.All AuditLog.Read.All Organization.Read.All"
        $existingGrant = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($sp.Id)' and resourceId eq '$($graphSp.Id)'" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($existingGrant) {
            Update-MgOauth2PermissionGrant -OAuth2PermissionGrantId $existingGrant.Id -Scope $scopeString
        } else {
            New-MgOauth2PermissionGrant -ClientId $sp.Id -ConsentType "AllPrincipals" -ResourceId $graphSp.Id -Scope $scopeString | Out-Null
        }
        $consentGranted = $true
        Write-Host "Admin consent granted for all 7 delegated permissions." -ForegroundColor Green
    } catch {
        Write-Host "Could not grant admin consent automatically: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # --- Summary ------------------------------------------------------------
    $tenantId = (Get-MgContext).TenantId
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "  EntraPass scanner app registration is ready" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host ("  Client ID : {0}" -f $app.AppId)
    Write-Host ("  Tenant ID : {0}" -f $tenantId)
    Write-Host ("  Portal    : {0}" -f $redirectUri)
    Write-Host "============================================================" -ForegroundColor Green
    if (-not $consentGranted) {
        Write-Host ""
        Write-Host "  ACTION NEEDED: grant admin consent in the Azure Portal:" -ForegroundColor Yellow
        Write-Host "  App registrations > $appName > API permissions > Grant admin consent" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "  Next: open $redirectUri, click 'Reset app' if needed, then enter the" -ForegroundColor Cyan
    Write-Host "  Client ID and Tenant ID above and sign in." -ForegroundColor Cyan
    Write-Host ""

    Disconnect-MgGraph | Out-Null
}

Invoke-EntraPassDeploy
