#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs Security/Web-Filtering.ps1 unattended against the
    dedicated M365 test tenant and verifies the Settings Catalog policy it
    creates.
.DESCRIPTION
    Connects to Microsoft Graph with certificate-based app-only auth, then:
      1. Writes a throwaway config file with NamePrefix = "E2E-", so the real
         script creates/verifies/deletes a throwaway prefixed policy instead
         of the tenant's real default policy
      2. Runs Security/Web-Filtering.ps1 non-interactively — the real
         script, same file the menu calls
      3. Verifies the policy exists via the same
         beta/deviceManagement/configurationPolicies endpoint the script
         itself uses
      4. Re-runs the script to prove idempotency (second run must report
         Skipped, not create a duplicate policy)
      5. Deletes the policy in a finally block that always runs, so cleanup
         happens even on failure
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

# Pre-clean any stray leftover from a previous run's incomplete cleanup.
Write-Host "`n== Pre-cleaning any stray E2E policy ==" -ForegroundColor Cyan
try {
    $stray = Get-WebFilterPolicyByName -Name $PolicyName
    if ($stray) {
        Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($stray.id)" -ErrorAction Stop
        Write-Host "  Removed stray policy $PolicyName" -ForegroundColor Gray
    }
}
catch { Write-Host "  (no stray policy to remove, or removal failed: $($_.Exception.Message))" -ForegroundColor Gray }

# TEMP DIAGNOSTIC — remove once the setting-ID bug is understood
Write-Host "`n== DEBUG: searching configurationSettings for webcontentfiltering ==" -ForegroundColor Magenta
try {
    $diagUri = "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?`$filter=contains(id,'webcontentfiltering')&`$select=id&`$top=50"
    $diagResponse = Invoke-MgGraphRequest -Method GET -Uri $diagUri -ErrorAction Stop
    Write-Host "  Found $(@($diagResponse.value).Count) matching setting IDs:" -ForegroundColor Magenta
    foreach ($item in @($diagResponse.value)) { Write-Host "    $($item.id)" -ForegroundColor Magenta }
}
catch { Write-Host "  DEBUG query failed: $($_.Exception.Message)" -ForegroundColor Magenta }

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
        Write-Result ([bool]$result.Success -and -not [bool]$result.Skipped) "Script reported success and created a new policy"
    }

    # ========================================================================
    # Independently verify tenant state
    # ========================================================================
    Write-Host "`n== Verifying policy in tenant ==" -ForegroundColor Cyan
    $policy = Get-WebFilterPolicyByName -Name $PolicyName
    Write-Result ([bool]$policy) "$PolicyName exists"
    if ($policy) {
        Write-Result ($policy.name -eq $PolicyName) "$PolicyName has the expected name"
        Write-Result ($policy.technologies -match 'microsoftSense') "$PolicyName targets Defender for Endpoint (microsoftSense)"
    }

    # ========================================================================
    # Idempotency: a second run must report Skipped, not create a duplicate
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run skips) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Security/Web-Filtering.ps1') `
        -NonInteractive -ConfigFile $WFConfigPath -ResultPath $ResultPath

    $second = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
    Write-Result ([bool]$second.Success -and [bool]$second.Skipped) "Second run reported success and skipped (policy already exists)"
}
finally {
    # ========================================================================
    # Cleanup — always runs
    # ========================================================================
    Write-Host "`n== Cleaning up E2E web filter policy ==" -ForegroundColor Cyan
    try {
        $existing = Get-WebFilterPolicyByName -Name $PolicyName
        if ($existing) {
            Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($existing.id)" -ErrorAction Stop
            Write-Host "  Deleted policy $PolicyName" -ForegroundColor Gray
        }
        else {
            Write-Host "  No policy to delete" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  WARNING: could not delete policy $($PolicyName): $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Manually delete the '$PolicyName' Settings Catalog policy in the test tenant" -ForegroundColor Yellow
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
