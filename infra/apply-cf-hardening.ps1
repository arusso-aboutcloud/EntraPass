<#
.SYNOPSIS
  Applies Cloudflare security hardening rules to the configured zone.

.DESCRIPTION
  Reads operator configuration from infra/cf-apply-config.local.json (gitignored)
  or equivalent CF_* environment variables. See infra/cf-apply-config.example.json
  for the expected schema.

  The admin IP is discovered automatically from the existing WAF bypass rule.

  WAF Custom Rules (5/5):
    1. Admin Bypass                         [KEEP + rename]
    2. Global: Block Scanners + Admin Paths [KEEP + rename]
    3. EntraApps: Block API Abuse           [EXPAND + rename]
    4. Umami: Protect Analytics Dashboard   [KEEP + rename]
    5. EntraApps: Static SPA Enforcement    [EXPAND + rename]

  Response Header Transform:
    1. Blog: Security Headers               [KEEP + rename]
    2. EntraPass: Security Headers          [KEEP + rename]

  Required env vars:
    CF_API_TOKEN  -- Cloudflare API token (Zone WAF + Transform Edit permissions)
    (All other operator values come from the config file or CF_* env vars — see above)

.EXAMPLE
  $env:CF_API_TOKEN = "your-token-here"
  .\infra\apply-cf-hardening.ps1
#>

param([string]$Zone = "")

$ErrorActionPreference = 'Stop'

# -- Load operator config -------------------------------------------------------
# Source: infra/cf-apply-config.local.json (gitignored, preferred) or CF_* env vars.
# Config values are never echoed to stdout.
# See infra/cf-apply-config.example.json for the expected schema.
$_cfgFile = Join-Path $PSScriptRoot 'cf-apply-config.local.json'
if (Test-Path $_cfgFile) {
    $config = Get-Content $_cfgFile -Raw | ConvertFrom-Json
} else {
    $config = [PSCustomObject]@{
        zone                    = $env:CF_ZONE
        protectedHosts          = if ($env:CF_PROTECTED_HOSTS)           { $env:CF_PROTECTED_HOSTS           | ConvertFrom-Json } else { $null }
        workerSubdomains        = if ($env:CF_WORKER_SUBDOMAINS)         { $env:CF_WORKER_SUBDOMAINS         | ConvertFrom-Json } else { $null }
        analyticsHost           = $env:CF_ANALYTICS_HOST
        aiAskExceptionHost      = $env:CF_AI_ASK_EXCEPTION_HOST
        aiAskExceptionPath      = $env:CF_AI_ASK_EXCEPTION_PATH
        ruleDescriptionPatterns = if ($env:CF_RULE_DESCRIPTION_PATTERNS) { $env:CF_RULE_DESCRIPTION_PATTERNS | ConvertFrom-Json } else { $null }
    }
}

foreach ($_f in @('protectedHosts','workerSubdomains','analyticsHost',
                  'aiAskExceptionHost','aiAskExceptionPath','ruleDescriptionPatterns')) {
    if (-not $config.$_f) {
        throw ("Required config field '$_f' is missing. " +
               "Set it in infra/cf-apply-config.local.json or the corresponding CF_* env var. " +
               "See infra/cf-apply-config.example.json for the full schema.")
    }
}
if (-not $Zone) {
    if (-not $config.zone) {
        throw ("Zone not specified. Pass -Zone 'example.com' or set 'zone' " +
               "in infra/cf-apply-config.local.json.")
    }
    $Zone = $config.zone
}
# -------------------------------------------------------------------------------

$Token = $env:CF_API_TOKEN
if (-not $Token) { throw "CF_API_TOKEN env var not set." }

$H    = @{ Authorization = "Bearer $Token"; "Content-Type" = "application/json" }
$Base = "https://api.cloudflare.com/client/v4"

function Invoke-CfGet([string]$url) {
    $r = Invoke-RestMethod $url -Headers $H -ErrorAction Stop
    if (-not $r.success) { throw "CF API error at $url : $($r.errors | ConvertTo-Json -Compress)" }
    return $r.result
}

function Invoke-CfPut([string]$url, $body) {
    $json = $body | ConvertTo-Json -Depth 20 -Compress
    $r    = Invoke-RestMethod $url -Method Put -Headers $H -Body $json -ErrorAction Stop
    if (-not $r.success) { throw "CF API error (PUT $url): $($r.errors | ConvertTo-Json -Compress)" }
    return $r.result
}

# -- Resolve zone -------------------------------------------------------------
Write-Host "Zone: $Zone" -ForegroundColor Cyan
$ZoneId = ((Invoke-RestMethod "$Base/zones?name=$Zone" -Headers $H).result[0]).id
if (-not $ZoneId) { throw "Zone '$Zone' not found or token lacks Zone read access." }
Write-Host "  ID: $ZoneId" -ForegroundColor DarkGray

# =============================================================================
# 1.  WAF Custom Rules
# =============================================================================
Write-Host "`n[WAF] Fetching current ruleset..." -ForegroundColor Cyan

$waf   = Invoke-CfGet "$Base/zones/$ZoneId/rulesets/phases/http_request_firewall_custom/entrypoint"
$wafId = $waf.id
$rules = $waf.rules

Write-Host ("  Found {0} rules:" -f $rules.Count)
$rules | ForEach-Object { Write-Host ("    [{0}] {1}" -f $_.action, $_.description) -ForegroundColor DarkGray }

# Identify rules by description (patterns handle both old and new names for idempotency)
$bypass = $rules | Where-Object { $_.description -match $config.ruleDescriptionPatterns.bypass   } | Select-Object -First 1
$global = $rules | Where-Object { $_.description -match $config.ruleDescriptionPatterns.scanner  } | Select-Object -First 1
$rlens  = $rules | Where-Object { $_.description -match $config.ruleDescriptionPatterns.apiAbuse } | Select-Object -First 1
$umami  = $rules | Where-Object { $_.description -match $config.ruleDescriptionPatterns.umami    } | Select-Object -First 1
$spas   = $rules | Where-Object { $_.description -match $config.ruleDescriptionPatterns.spa      } | Select-Object -First 1

foreach ($pair in @(
    @('bypass',  $bypass),
    @('global',  $global),
    @('rlens',   $rlens),
    @('umami',   $umami),
    @('spas',    $spas)
)) {
    if (-not $pair[1]) { throw "ABORT -- rule not found: '$($pair[0])'. Check descriptions." }
}

# Auto-detect admin IP from bypass rule expression: (ip.src in {x.x.x.x})
if ($bypass.expression -notmatch '\{(\d+\.\d+\.\d+\.\d+)\}') {
    throw "Cannot extract admin IP from bypass expression: $($bypass.expression)"
}
$AdminIp = $Matches[1]
Write-Host "  Admin IP: detected from bypass rule." -ForegroundColor DarkGray

# -- Rule 1: Admin Bypass (rename only, keep expression + action_parameters) --
$bypass.description = 'Admin Bypass'

# -- Rule 2: Global: Block Scanners + Admin Paths (rename only) ---------------
$global.description = 'Global: Block Scanners + Admin Paths'

# -- Rule 3: EntraApps: Block API Abuse (rename + expand hosts) ---------------
$_apiHosts = (@($config.protectedHosts) + @($config.workerSubdomains) |
    ForEach-Object { '"' + $_ + '"' }) -join ' '
$apiAbuseExpr = @'
((http.host in {__API_HOSTS__} or http.host wildcard "*.pages.dev") and http.request.uri.path contains "/api/" and ((lower(http.user_agent) contains "sqlmap") or (lower(http.user_agent) contains "nikto") or (lower(http.user_agent) contains "nuclei") or (lower(http.user_agent) contains "dirbuster") or (lower(http.user_agent) contains "gobuster") or (lower(http.user_agent) contains "wfuzz") or (http.request.method eq "DELETE") or (http.request.method eq "PUT") or (http.request.method eq "PATCH") or (http.request.uri.path contains "/.env") or (http.request.uri.path contains "/.git") or (http.request.uri.path contains "/wp-") or (http.request.uri.path contains "/phpinfo")) and not (ip.src eq __ADMIN_IP__))
'@
$apiAbuseExpr = $apiAbuseExpr.Trim() `
    -replace '__API_HOSTS__', $_apiHosts `
    -replace '__ADMIN_IP__',  $AdminIp

$ruleApiAbuse = @{
    action      = 'block'
    description = 'EntraApps: Block API Abuse'
    enabled     = $true
    expression  = $apiAbuseExpr
}

# -- Rule 4: Umami: Protect Analytics Dashboard (rename only) -----------------
$umami.description = 'Umami: Protect Analytics Dashboard'

# -- Rule 5: EntraApps: Static SPA Enforcement (rename + expand hosts) --------
# /ai/ask is a Pages Function that handles its own CORS + auth; POST must be
# allowed from non-admin IPs so the AI chat works for real users.
$_spaHosts = ($config.protectedHosts | ForEach-Object { '"' + $_ + '"' }) -join ' '
$spaExpr = @'
http.host in {__SPA_HOSTS__} and not http.request.method in {"GET" "HEAD"} and not ip.src eq __ADMIN_IP__ and not (http.host eq "__AI_ASK_HOST__" and http.request.uri.path eq "__AI_ASK_PATH__")
'@
$spaExpr = $spaExpr.Trim() `
    -replace '__SPA_HOSTS__',   $_spaHosts `
    -replace '__ADMIN_IP__',    $AdminIp `
    -replace '__AI_ASK_HOST__', $config.aiAskExceptionHost `
    -replace '__AI_ASK_PATH__', $config.aiAskExceptionPath

$ruleSpa = @{
    action      = 'block'
    description = 'EntraApps: Static SPA Enforcement'
    enabled     = $true
    expression  = $spaExpr
}

# -- Apply WAF ----------------------------------------------------------------
$newWafRules = @($bypass, $global, $ruleApiAbuse, $umami, $ruleSpa)

Write-Host "`n  Applying 5 rules:"
Write-Host "    1 [RENAME] $($bypass.description)"      -ForegroundColor Green
Write-Host "    2 [RENAME] $($global.description)"      -ForegroundColor Green
Write-Host "    3 [EXPAND] $($ruleApiAbuse.description) -- adds entrapass/entratracker/entraerrors" -ForegroundColor Yellow
Write-Host "    4 [RENAME] $($umami.description)"       -ForegroundColor Green
Write-Host "    5 [EXPAND] $($ruleSpa.description) -- adds entrarolelens/entratracker/entraerrors" -ForegroundColor Yellow

$r1 = Invoke-CfPut "$Base/zones/$ZoneId/rulesets/$wafId" @{ rules = $newWafRules }
Write-Host ("  OK -- {0} rules active." -f $r1.rules.Count) -ForegroundColor Green

# =============================================================================
# 2.  Response Header Transform
# =============================================================================
Write-Host "`n[Headers] Fetching current ruleset..." -ForegroundColor Cyan

$rht      = Invoke-CfGet "$Base/zones/$ZoneId/rulesets/phases/http_response_headers_transform/entrypoint"
$rhtId    = $rht.id
$rhtRules = if ($rht.rules) { $rht.rules } else { @() }

# Blog rule: rename only, preserve expression + action_parameters
$blogRule = $rhtRules | Where-Object { $_.description -match 'Blog' } | Select-Object -First 1
if (-not $blogRule) { throw "ABORT -- blog header rule not found." }
$blogRule.description = 'Blog: Security Headers'

# EntraPass headers rule: rebuild with new name (idempotent remove + re-add)
$csp = ("default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://$($config.analyticsHost); " +
        "connect-src 'self' https://login.microsoftonline.com https://graph.microsoft.com https://$($config.analyticsHost); " +
        "img-src 'self' data:; " +
        "style-src 'self' 'unsafe-inline'; " +
        "frame-ancestors 'none'")

$epHeadersRule = @{
    action      = 'rewrite'
    description = 'EntraPass: Security Headers'
    enabled     = $true
    expression  = 'http.host eq "' + $config.aiAskExceptionHost + '"'
    action_parameters = @{
        headers = @{
            'X-Frame-Options'           = @{ operation='set'; value='DENY' }
            'X-Content-Type-Options'    = @{ operation='set'; value='nosniff' }
            'Referrer-Policy'           = @{ operation='set'; value='strict-origin-when-cross-origin' }
            'Permissions-Policy'        = @{ operation='set'; value='geolocation=(), camera=(), microphone=(), payment=()' }
            'Strict-Transport-Security' = @{ operation='set'; value='max-age=31536000; includeSubDomains; preload' }
            'Content-Security-Policy'   = @{ operation='set'; value=$csp }
        }
    }
}

# Build final list: blog (renamed) + all non-EntraPass rules + new EntraPass rule
$otherRules  = @($rhtRules | Where-Object { $_.description -notmatch 'Blog|EntraPass' })
$newRhtRules = @($blogRule) + $otherRules + @($epHeadersRule)

Write-Host "    [RENAME] $($blogRule.description)"      -ForegroundColor Green
Write-Host "    [RENAME] $($epHeadersRule.description)" -ForegroundColor Green

$r2 = Invoke-CfPut "$Base/zones/$ZoneId/rulesets/$rhtId" @{ rules = $newRhtRules }
Write-Host ("  OK -- {0} rules active." -f $r2.rules.Count) -ForegroundColor Green

# =============================================================================
# 3.  Rate Limiting Rules  (Advanced Rate Limiting — Pro plan or higher)
# =============================================================================
# Adds a 30 req/min per-IP rate limit on the EntraPass AI endpoint.
# The Pages Function has in-memory rate limiting too; this is the CF edge layer.
# If this section fails the rest of the script is unaffected.
# =============================================================================
Write-Host "`n[Rate Limit] Fetching ruleset..." -ForegroundColor Cyan
try {
    $rl      = Invoke-CfGet "$Base/zones/$ZoneId/rulesets/phases/http_ratelimit/entrypoint"
    $rlId    = $rl.id
    $rlRules = if ($rl.rules) { @($rl.rules) } else { @() }

    # Preserve all existing rules except any prior AI endpoint rule
    $otherRl = @($rlRules | Where-Object { $_.description -notmatch 'EntraPass.*AI|AI.*endpoint|/ai/ask' })

    $aiRlRule = @{
        action      = 'block'
        description = 'EntraPass: AI endpoint — 30 req/min per IP'
        enabled     = $true
        expression  = 'http.host eq "' + $config.aiAskExceptionHost + '" and http.request.uri.path eq "' + $config.aiAskExceptionPath + '"'
        ratelimit   = @{
            characteristics     = @('ip.src')
            period              = 60
            requests_per_period = 30
            mitigation_timeout  = 60
        }
    }

    # Preserve rule ID if we are updating an existing rule
    $existingAiRl = $rlRules | Where-Object { $_.description -match 'EntraPass.*AI|AI.*endpoint|/ai/ask' } | Select-Object -First 1
    if ($existingAiRl) { $aiRlRule.id = $existingAiRl.id }

    $newRlRules = $otherRl + @($aiRlRule)
    Write-Host "    [UPSERT] EntraPass: AI endpoint — 30 req/min per IP" -ForegroundColor Yellow
    $r3 = Invoke-CfPut "$Base/zones/$ZoneId/rulesets/$rlId" @{ rules = $newRlRules }
    Write-Host ("  OK -- {0} rate limit rules active." -f $r3.rules.Count) -ForegroundColor Green
} catch {
    Write-Host ("  SKIP -- Rate limit phase inaccessible ({0})." -f $_.Exception.Message) -ForegroundColor DarkYellow
    Write-Host "  To add manually: Security -> Rate Limiting -> 30 req/60s on /ai/ask" -ForegroundColor DarkYellow
}

# =============================================================================
# 4.  Cache Rules
# =============================================================================
# - Hashed Vite assets (/assets/*): 1-year immutable cache
# - index.html (/):                 bypass cache so deploys are instant
# =============================================================================
Write-Host "`n[Cache] Fetching ruleset..." -ForegroundColor Cyan
try {
    $cr      = Invoke-CfGet "$Base/zones/$ZoneId/rulesets/phases/http_cache_settings/entrypoint"
    $crId    = $cr.id
    $crRules = if ($cr.rules) { @($cr.rules) } else { @() }

    # Preserve non-EntraPass cache rules
    $otherCr = @($crRules | Where-Object { $_.description -notmatch 'EntraPass.*Cache|EntraPass.*Asset|EntraPass.*index' })

    $crAssets = @{
        action      = 'set_cache_settings'
        description = 'EntraPass: Cache hashed assets (1 year)'
        enabled     = $true
        expression  = 'http.host eq "' + $config.aiAskExceptionHost + '" and http.request.uri.path contains "/assets/"'
        action_parameters = @{
            cache       = $true
            edge_ttl    = @{ mode = 'override'; default = 31536000 }
            browser_ttl = @{ mode = 'override'; default = 31536000 }
        }
    }
    $crIndex = @{
        action      = 'set_cache_settings'
        description = 'EntraPass: No-cache index.html'
        enabled     = $true
        expression  = 'http.host eq "' + $config.aiAskExceptionHost + '" and http.request.uri.path eq "/"'
        action_parameters = @{
            cache       = $false
            browser_ttl = @{ mode = 'bypass_by_default' }
        }
    }

    # Preserve IDs if updating existing rules
    $existingAssets = $crRules | Where-Object { $_.description -match 'EntraPass.*Cache|EntraPass.*Asset' } | Select-Object -First 1
    $existingIndex  = $crRules | Where-Object { $_.description -match 'EntraPass.*index'                   } | Select-Object -First 1
    if ($existingAssets) { $crAssets.id = $existingAssets.id }
    if ($existingIndex)  { $crIndex.id  = $existingIndex.id  }

    $newCrRules = $otherCr + @($crAssets, $crIndex)
    Write-Host "    [UPSERT] EntraPass: Cache hashed assets (1 year)" -ForegroundColor Yellow
    Write-Host "    [UPSERT] EntraPass: No-cache index.html"          -ForegroundColor Yellow
    $r4 = Invoke-CfPut "$Base/zones/$ZoneId/rulesets/$crId" @{ rules = $newCrRules }
    Write-Host ("  OK -- {0} cache rules active." -f $r4.rules.Count) -ForegroundColor Green
} catch {
    Write-Host ("  SKIP -- Cache ruleset inaccessible ({0})." -f $_.Exception.Message) -ForegroundColor DarkYellow
    Write-Host "  To add manually: Caching -> Cache Rules in the Cloudflare dashboard" -ForegroundColor DarkYellow
}

Write-Host "`nHardening complete." -ForegroundColor Green
