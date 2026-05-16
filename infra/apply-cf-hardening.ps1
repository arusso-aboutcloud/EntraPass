<#
.SYNOPSIS
  Applies Cloudflare security hardening for aboutcloud.io / entrapass.aboutcloud.io.

.DESCRIPTION
  WAF Custom Rules (5/5 → 5/5, restructured):
    1. [KEEP] Allow My IP (Bypass)
    2. [NEW]  WAF: Block Scanners and Admin Paths    ← merges old rules 2 + 3
    3. [KEEP] Entra RoleLens — Block API abuse and path probing
    4. [KEEP] Umami — Block dashboard, allow trackers
    5. [NEW]  EntraPass — Block non-GET methods

  Response Header Transform:
    1. [KEEP] Blog security headers
    2. [NEW]  EntraPass — Security Headers

  Required env vars:
    CF_API_TOKEN  — Cloudflare API token (Zone WAF + Transform Edit)
    CF_ADMIN_IP   — Admin home IP (used in WAF bypass and path-block expressions)

.EXAMPLE
  $env:CF_API_TOKEN = "..."
  $env:CF_ADMIN_IP  = "1.2.3.4"
  .\infra\apply-cf-hardening.ps1
#>

param([string]$Zone = "aboutcloud.io")

$ErrorActionPreference = 'Stop'

$Token   = $env:CF_API_TOKEN
$AdminIp = $env:CF_ADMIN_IP
if (-not $Token)   { throw "CF_API_TOKEN env var not set." }
if (-not $AdminIp) { throw "CF_ADMIN_IP env var not set." }

$H    = @{ Authorization = "Bearer $Token"; "Content-Type" = "application/json" }
$Base = "https://api.cloudflare.com/client/v4"

function cf-get([string]$url) {
    $r = Invoke-RestMethod $url -Headers $H -ErrorAction Stop
    if (-not $r.success) { throw "CF API error at $url : $($r.errors | ConvertTo-Json -Compress)" }
    return $r.result
}

function cf-put([string]$url, $body) {
    $json = $body | ConvertTo-Json -Depth 20 -Compress
    $r    = Invoke-RestMethod $url -Method Put -Headers $H -Body $json -ErrorAction Stop
    if (-not $r.success) { throw "CF API error (PUT $url): $($r.errors | ConvertTo-Json -Compress)" }
    return $r.result
}

# ── Resolve zone ──────────────────────────────────────────────────────────────
Write-Host "Zone: $Zone" -ForegroundColor Cyan
$ZoneId = ((Invoke-RestMethod "$Base/zones?name=$Zone" -Headers $H).result[0]).id
if (-not $ZoneId) { throw "Zone '$Zone' not found or token lacks Zone read access." }
Write-Host "  ID: $ZoneId" -ForegroundColor DarkGray

# ══════════════════════════════════════════════════════════════════════════════
# 1.  WAF Custom Rules
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "`n[WAF] Fetching current ruleset..." -ForegroundColor Cyan

$waf   = cf-get "$Base/zones/$ZoneId/rulesets/phases/http_request_firewall_custom/entrypoint"
$wafId = $waf.id
$rules = $waf.rules

Write-Host "  Current rules: $($rules.Count)"
$rules | ForEach-Object { Write-Host ("    [{0}] {1}" -f $_.action, $_.description) -ForegroundColor DarkGray }

# Identify rules to keep unchanged (matched by description keyword)
$bypass   = $rules | Where-Object { $_.description -match 'Allow My IP|Bypass' }  | Select-Object -First 1
$roleLens = $rules | Where-Object { $_.description -match 'RoleLens|Entra Role' } | Select-Object -First 1
$umami    = $rules | Where-Object { $_.description -match 'Umami' }               | Select-Object -First 1

if (-not $bypass)   { throw "ABORT — 'Allow My IP' rule not found. Check rule descriptions." }
if (-not $roleLens) { throw "ABORT — 'EntraRoleLens' rule not found. Check rule descriptions." }
if (-not $umami)    { throw "ABORT — 'Umami' rule not found. Check rule descriptions." }

# ── Consolidated expression (old Rules 2 + 3 merged into one) ─────────────────
# Single-quoted here-string preserves all embedded double-quotes literally.
# __ADMIN_IP__ is substituted after.
$consolidatedExpr = @'
((http.user_agent eq "" or lower(http.user_agent) contains "scrapy" or lower(http.user_agent) contains "nikto" or lower(http.user_agent) contains "sqlmap" or lower(http.user_agent) contains "masscan" or lower(http.user_agent) contains "zgrab" or lower(http.user_agent) contains "zap" or lower(http.user_agent) contains "nuclei" or lower(http.user_agent) contains "dirbuster" or lower(http.user_agent) contains "gobuster" or lower(http.user_agent) contains "wfuzz" or lower(http.user_agent) contains "nmap" or lower(http.user_agent) contains "semrush" or lower(http.user_agent) contains "ahrefsbot" or lower(http.user_agent) contains "dotbot" or lower(http.user_agent) contains "mj12bot" or lower(http.user_agent) contains "blexbot" or lower(http.user_agent) contains "petalbot") or (http.host eq "images.aboutcloud.io" and http.request.method ne "GET") or (ip.src ne __ADMIN_IP__ and (http.request.uri.path contains "/ghost" or http.request.uri.path contains "/admin" or http.request.uri.path contains "/domainadmin" or http.request.uri.path contains "/rspamd" or http.request.uri.path contains "/wp-admin" or http.request.uri.path contains "/wp-login" or http.request.uri.path contains "/.env" or http.request.uri.path contains "/phpinfo" or http.request.uri.path contains "/.git"))) and not (http.host eq "nextcloud.aboutcloud.io") and not (http.host eq "entrarolelens.aboutcloud.io") and not (lower(http.user_agent) contains "nextcloud")
'@
$consolidatedExpr = $consolidatedExpr.Trim() -replace '__ADMIN_IP__', $AdminIp

# ── EntraPass: static SPA — only GET/HEAD are legitimate ─────────────────────
$entrapassExpr = @'
http.host eq "entrapass.aboutcloud.io" and not http.request.method in {"GET" "HEAD"} and not ip.src eq __ADMIN_IP__
'@
$entrapassExpr = $entrapassExpr.Trim() -replace '__ADMIN_IP__', $AdminIp

$newWafRules = @(
    $bypass,
    @{ action='block'; description='WAF: Block Scanners and Admin Paths'; enabled=$true; expression=$consolidatedExpr },
    $roleLens,
    $umami,
    @{ action='block'; description='EntraPass — Block non-GET methods';   enabled=$true; expression=$entrapassExpr  }
)

Write-Host "`n  Applying 5 rules:"
Write-Host "    1 [KEEP] $($bypass.description)"   -ForegroundColor Green
Write-Host "    2 [NEW]  WAF: Block Scanners and Admin Paths  (consolidated old 2+3)" -ForegroundColor Yellow
Write-Host "    3 [KEEP] $($roleLens.description)" -ForegroundColor Green
Write-Host "    4 [KEEP] $($umami.description)"    -ForegroundColor Green
Write-Host "    5 [NEW]  EntraPass — Block non-GET methods"  -ForegroundColor Yellow

$r1 = cf-put "$Base/zones/$ZoneId/rulesets/$wafId" @{ rules = $newWafRules }
Write-Host ("  OK — {0} rules active." -f $r1.rules.Count) -ForegroundColor Green

# ══════════════════════════════════════════════════════════════════════════════
# 2.  Response Header Transform — add EntraPass security headers
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "`n[Headers] Fetching current ruleset..." -ForegroundColor Cyan

$rht   = cf-get "$Base/zones/$ZoneId/rulesets/phases/http_response_headers_transform/entrypoint"
$rhtId = $rht.id

# Keep all existing rules except any stale EntraPass header rule (idempotent re-run)
$keepRules = if ($rht.rules) {
    @($rht.rules | Where-Object { $_.description -notmatch 'EntraPass.*[Hh]eader|EntraPass.*Security' })
} else { @() }

foreach ($r in $keepRules) {
    Write-Host "    [KEEP] $($r.description)" -ForegroundColor Green
}
Write-Host "    [NEW]  EntraPass — Security Headers" -ForegroundColor Yellow

$csp = ("default-src 'self'; " +
        "script-src 'self' 'unsafe-inline'; " +
        "connect-src 'self' https://login.microsoftonline.com https://graph.microsoft.com; " +
        "img-src 'self' data:; " +
        "style-src 'self' 'unsafe-inline'; " +
        "frame-ancestors 'none'")

$epHeadersRule = @{
    action      = 'rewrite'
    description = 'EntraPass — Security Headers'
    enabled     = $true
    expression  = 'http.host eq "entrapass.aboutcloud.io"'
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

$newRhtRules = @($keepRules) + @($epHeadersRule)
$r2 = cf-put "$Base/zones/$ZoneId/rulesets/$rhtId" @{ rules = $newRhtRules }
Write-Host ("  OK — {0} rules active." -f $r2.rules.Count) -ForegroundColor Green

Write-Host "`nHardening complete." -ForegroundColor Green
