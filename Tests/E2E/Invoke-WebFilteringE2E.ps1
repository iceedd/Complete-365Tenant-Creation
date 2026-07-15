#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs Security/Web-Filtering.ps1 unattended against the
    dedicated M365 test tenant and confirms it correctly reports the known,
    permanent Web Content Filtering Graph API limitation.
.DESCRIPTION
    Confirmed live (this test's earlier runs) and via Microsoft Learn
    documentation: Defender for Endpoint's "Web content filtering" feature
    has no Microsoft Graph API at all — every Microsoft doc for this feature
    says to use the Defender portal wizard exclusively. The tenant's Settings
    Catalog has no device_vendor_msft_defender_configuration_webcontentfiltering_*
    setting IDs; only unrelated Microsoft Edge browser policy settings share
    a similar name. See CLAUDE.md → "Web Content Filtering (Manual Setup
    Required)".

    Connects to Microsoft Graph with certificate-based app-only auth, then:
      1. Runs Security/Web-Filtering.ps1 non-interactively — the real
         script, same file the menu calls
      2. Verifies the script correctly detects this as a known limitation
         (Success=$false, KnownLimitation=$true) rather than crashing or
         reporting a misleading success
      3. Verifies no policy was created in the tenant (since none can be)
      4. Re-runs the script to confirm this is reported consistently, not
         just on a first attempt
      5. Cleans up any policy in a finally block regardless (defensive —
         only relevant if Microsoft ever exposes a working API and the
         create call starts succeeding)
.EXAMPLE
    ./Invoke-WebFilteringE2E.ps1 -TenantId $env:M365_TENANT_ID -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $TenantId,
    [Parameter(Mandatory)] [string] $AppId,
    [Parameter(Mandatory)] [string] $CertificateThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot   = $PSScriptRoot | Split-Path | Split-Path
$E2EPrefix  = "E2E-"
$PolicyName = "${E2EPrefix}Default Web Filter"

$WFConfigPath = Join-Path ([IO.Path]::GetTempPath()) "webfilter-e2e-config-$([guid]::NewGuid().ToString('n')).json"
$ResultPath   = Join-Path ([IO.Path]::GetTempPath()) "webfilter-e2e-result-$([guid]::NewGuid().ToString('n')).json"

@{ NamePrefix = $E2EPrefix } | ConvertTo-Json -Depth 5 | Set-Content -Path $WFConfigPath -Encoding UTF8

$failures = 0

function Write-Result {
    param([bool]$Pass, [string]$Message)
    if ($Pass) { Write-Host "  PASS  $Message" -ForegroundColor Green }
    else       { Write-Host "  FAIL  $Message" -ForegroundColor Red; $script:failures++ }
}

function Get-WebFilterPolicyByName {
    param([string]$Name)
    $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$filter=name eq '$Name'"
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue
    if ($response.value -and @($response.value).Count -gt 0) { return $response.value[0] }
    return $null
}

# ============================================================================
# Connect
# ============================================================================
Write-Host "`n== Connecting to test tenant (app-only) ==" -ForegroundColor Cyan
Connect-MgGraph -ClientId $AppId -TenantId $TenantId `
    -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
$ctx = Get-MgContext
if (!$ctx) { throw "Failed to establish Graph context" }
Write-Host "  Connected to tenant $($ctx.TenantId)" -ForegroundColor Green

try {
    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running Web-Filtering.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Security/Web-Filtering.ps1') `
        -NonInteractive -ConfigFile $WFConfigPath -ResultPath $ResultPath

    # ========================================================================
    # Assert on the script's own reported results
    # ========================================================================
    Write-Host "`n== Verifying script results ==" -ForegroundColor Cyan
    if (!(Test-Path $ResultPath)) {
        Write-Result $false "Script produced no results file — it likely aborted early"
    }
    else {
        $result = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
        Write-Result ((-not [bool]$result.Success) -and [bool]$result.KnownLimitation) `
            "Script correctly reported the known Web Content Filtering API limitation (not a crash or false success)"
    }

    # ========================================================================
    # Independently verify no policy was created (since none can be)
    # ========================================================================
    Write-Host "`n== Verifying no policy was created in tenant ==" -ForegroundColor Cyan
    $policy = Get-WebFilterPolicyByName -Name $PolicyName
    Write-Result (!$policy) "$PolicyName correctly does not exist (API cannot create it)"

    # ========================================================================
    # Re-run: the known limitation must be reported consistently
    # ========================================================================
    Write-Host "`n== Verifying the limitation is reported consistently on re-run ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Security/Web-Filtering.ps1') `
        -NonInteractive -ConfigFile $WFConfigPath -ResultPath $ResultPath

    $second = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
    Write-Result ((-not [bool]$second.Success) -and [bool]$second.KnownLimitation) `
        "Second run also correctly reported the known limitation"
}
finally {
    # ========================================================================
    # Defensive cleanup — only relevant if a policy somehow got created
    # (e.g. Microsoft starts exposing a working API for this feature)
    # ========================================================================
    Write-Host "`n== Cleaning up any E2E web filter policy ==" -ForegroundColor Cyan
    try {
        $existing = Get-WebFilterPolicyByName -Name $PolicyName
        if ($existing) {
            Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($existing.id)" -ErrorAction Stop
            Write-Host "  Deleted policy $PolicyName" -ForegroundColor Gray
        }
        else {
            Write-Host "  No policy to delete (expected)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  WARNING: could not delete policy $($PolicyName): $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Remove-Item $WFConfigPath, $ResultPath -ErrorAction SilentlyContinue
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
}

# ============================================================================
# Summary
# ============================================================================
Write-Host ""
Write-Host ("=" * 60)
Write-Host "E2E test summary: $failures failure(s)"
Write-Host ("=" * 60)

if ($failures -gt 0) { exit 1 }
exit 0
