<#
.SYNOPSIS
  Exports all Cloudflare security rules for the configured zone to JSON + Markdown.

.DESCRIPTION
  Reads operator configuration from infra/cf-apply-config.local.json (gitignored)
  or equivalent CF_* environment variables. See infra/cf-apply-config.example.json
  for the expected schema.

  Queries the Cloudflare Ruleset API for every rule phase (WAF, Rate Limiting,
  Transform, Redirect, Configuration, Origin, Cache, Header rules) and writes:
    - docs/security/cf-rules-dump.json   -- raw API output (gitignored)
    - docs/security/cloudflare-rules.md  -- human-readable summary (gitignored)

  The admin IP is auto-detected from the WAF bypass rule and always redacted
  as [ADMIN-IP] in both output files. No additional secrets or parameters needed.

  Required env var:
    CF_API_TOKEN  -- Cloudflare API token (Zone WAF + Transform Read permissions)

.EXAMPLE
  $env:CF_API_TOKEN = "your-token-here"
  .\infra\export-cf-rules.ps1
#>

param(
    [string]$Zone   = "",
    [string]$OutDir = "docs\security"
)

# -- Load operator config (zone + bypass pattern) -------------------------------
$_cfgFile = Join-Path $PSScriptRoot 'cf-apply-config.local.json'
if (Test-Path $_cfgFile) {
    $config = Get-Content $_cfgFile -Raw | ConvertFrom-Json
} else {
    $config = [PSCustomObject]@{
        zone                    = $env:CF_ZONE
        ruleDescriptionPatterns = if ($env:CF_RULE_DESCRIPTION_PATTERNS) { $env:CF_RULE_DESCRIPTION_PATTERNS | ConvertFrom-Json } else { $null }
    }
}

if (-not $config.ruleDescriptionPatterns -or -not $config.ruleDescriptionPatterns.bypass) {
    throw ("Required config field 'ruleDescriptionPatterns.bypass' is missing. " +
           "Set it in infra/cf-apply-config.local.json or set CF_RULE_DESCRIPTION_PATTERNS env var. " +
           "See infra/cf-apply-config.example.json for the full schema.")
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
if (-not $Token) {
    throw "Set the CF_API_TOKEN environment variable before running this script."
}

$H    = @{ Authorization = "Bearer $Token"; "Content-Type" = "application/json" }
$Base = "https://api.cloudflare.com/client/v4"

# -- Resolve Zone -------------------------------------------------------------
Write-Host "Resolving zone: $Zone ..." -ForegroundColor Cyan
$ZoneObj = (Invoke-RestMethod "$Base/zones?name=$Zone" -Headers $H).result[0]
if (-not $ZoneObj) { throw "Zone '$Zone' not found or token lacks Zone read access." }
$ZoneId = $ZoneObj.id
Write-Host "  Zone ID: $ZoneId" -ForegroundColor DarkGray

# -- Phases to Fetch ----------------------------------------------------------
$Phases = [ordered]@{
    "Custom WAF Rules"          = "http_request_firewall_custom"
    "Rate Limiting"             = "http_ratelimit"
    "URL Rewrite Rules"         = "http_request_transform"
    "Redirect Rules"            = "http_request_redirect"
    "Configuration Rules"       = "http_config_settings"
    "Origin Rules"              = "http_request_origin"
    "Cache Rules"               = "http_request_cache_settings"
    "Response Header Transform" = "http_response_headers_transform"
    "Request Header Transform"  = "http_request_late_transform"
}

$Export = [ordered]@{
    zone     = $Zone
    zoneId   = $ZoneId
    exported = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    rulesets = [ordered]@{}
}

foreach ($Label in $Phases.Keys) {
    $Phase = $Phases[$Label]
    try {
        $R = Invoke-RestMethod "$Base/zones/$ZoneId/rulesets/phases/$Phase/entrypoint" -Headers $H -ErrorAction Stop
        $Count = if ($R.result.rules) { $R.result.rules.Count } else { 0 }
        $Export.rulesets[$Label] = $R.result
        Write-Host ("  [OK] {0,-30} {1} rule(s)" -f $Label, $Count) -ForegroundColor Green
    } catch {
        $Export.rulesets[$Label] = $null
        Write-Host ("  [--] {0,-30} empty / not enabled" -f $Label) -ForegroundColor DarkGray
    }
}

# -- Auto-detect admin IP for redaction ---------------------------------------
$AdminIp = ""
$WafRuleset = $Export.rulesets["Custom WAF Rules"]
if ($WafRuleset -and $WafRuleset.rules) {
    $BypassRule = $WafRuleset.rules | Where-Object { $_.description -match $config.ruleDescriptionPatterns.bypass } | Select-Object -First 1
    if ($BypassRule -and $BypassRule.expression -match '\{(\d+\.\d+\.\d+\.\d+)\}') {
        $AdminIp = $Matches[1]
        Write-Host "  Admin IP detected and will be redacted as [ADMIN-IP]." -ForegroundColor DarkGray
    }
}

# -- Ensure Output Dir --------------------------------------------------------
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

# -- Write JSON ---------------------------------------------------------------
$Json = $Export | ConvertTo-Json -Depth 20
if ($AdminIp) { $Json = $Json -replace [regex]::Escape($AdminIp), "[ADMIN-IP]" }

$JsonPath = Join-Path $OutDir "cf-rules-dump.json"
$Json | Out-File $JsonPath -Encoding utf8
Write-Host "`nSaved JSON : $JsonPath" -ForegroundColor Cyan

# -- Write Markdown Summary ---------------------------------------------------
$Md = [System.Text.StringBuilder]::new()
$null = $Md.AppendLine("# Cloudflare Security Rules -- $Zone")
$null = $Md.AppendLine("")
$null = $Md.AppendLine("> Auto-generated by ``infra/export-cf-rules.ps1`` on $(Get-Date -Format 'yyyy-MM-dd').")
$null = $Md.AppendLine("> Source of truth: Cloudflare dashboard -> Security / Rules.")
$null = $Md.AppendLine("> Sensitive values (IPs, etc.) are redacted as [ADMIN-IP].")
$null = $Md.AppendLine("")

foreach ($Label in $Export.rulesets.Keys) {
    $Ruleset = $Export.rulesets[$Label]
    $Rules   = if ($Ruleset -and $Ruleset.rules) { $Ruleset.rules } else { @() }

    $null = $Md.AppendLine("## $Label")
    $null = $Md.AppendLine("")

    if ($Rules.Count -eq 0) {
        $null = $Md.AppendLine("_No rules configured._")
        $null = $Md.AppendLine("")
        continue
    }

    $null = $Md.AppendLine("| # | Name | Action | Enabled |")
    $null = $Md.AppendLine("|---|------|--------|---------|")

    $i = 1
    foreach ($Rule in $Rules) {
        $Name    = if ($Rule.description) { $Rule.description } else { $Rule.ref }
        $Action  = if ($Rule.action) { $Rule.action } else { "--" }
        $Enabled = if ($Rule.enabled -eq $false) { "No" } else { "Yes" }
        $null = $Md.AppendLine("| $i | $Name | $Action | $Enabled |")
        $i++
    }

    $null = $Md.AppendLine("")

    $i = 1
    foreach ($Rule in $Rules) {
        $Name = if ($Rule.description) { $Rule.description } else { "Rule $i" }
        $Expr = if ($Rule.expression) { $Rule.expression } else { "_(legacy / no expression)_" }
        if ($AdminIp) { $Expr = $Expr -replace [regex]::Escape($AdminIp), "[ADMIN-IP]" }
        $null = $Md.AppendLine("### $i. $Name")
        $null = $Md.AppendLine("")
        $null = $Md.AppendLine("``````")
        $null = $Md.AppendLine($Expr)
        $null = $Md.AppendLine("``````")
        $null = $Md.AppendLine("")
        $i++
    }
}

$MdContent = $Md.ToString()
if ($AdminIp) { $MdContent = $MdContent -replace [regex]::Escape($AdminIp), "[ADMIN-IP]" }

$MdPath = Join-Path $OutDir "cloudflare-rules.md"
$MdContent | Out-File $MdPath -Encoding utf8
Write-Host "Saved MD   : $MdPath" -ForegroundColor Cyan
Write-Host "All sensitive values redacted as [ADMIN-IP]." -ForegroundColor Green
