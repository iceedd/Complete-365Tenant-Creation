#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs Intune/Device-Groups.ps1 unattended against the
    dedicated M365 test tenant and verifies the dynamic device groups it
    creates.
.DESCRIPTION
    Connects to Microsoft Graph with certificate-based app-only auth, then:
      1. Runs Intune/Device-Groups.ps1 non-interactively (E2E- prefix) — the
         real script, same file the menu calls
      2. Verifies each of the 8 expected groups exists, is a dynamic security
         group with the correct membership rule
      3. Re-runs the script to prove idempotency (second run must skip all 8)
      4. Deletes every E2E- prefixed group in a finally block that always
         runs, so cleanup happens even on failure

    Unlike Security-Groups.ps1, this script has no prerequisites of its own
    (it doesn't depend on any other script's output), so there's no setup
    step here.
.EXAMPLE
    ./Invoke-DeviceGroupsE2E.ps1 -TenantId $env:M365_TENANT_ID -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $TenantId,
    [Parameter(Mandatory)] [string] $AppId,
    [Parameter(Mandatory)] [string] $CertificateThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot     = $PSScriptRoot | Split-Path | Split-Path
$ConfigPath   = Join-Path $PSScriptRoot 'device-groups.e2e.json'
$ResultPath   = Join-Path ([IO.Path]::GetTempPath()) "dg-e2e-result-$([guid]::NewGuid().ToString('n')).json"

$config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$E2EPrefix = $config.NamePrefix
if (!$E2EPrefix) { throw "E2E config must set a NamePrefix — refusing to run without test isolation" }

# The 8 groups Device-Groups.ps1 creates, with their expected membership rule
$ExpectedGroups = [ordered]@{
    'Windows Devices (Autopilot)' = '(device.devicePhysicalIds -any _ -eq "[OrderID]:WIN-AP-Corp")'
    'macOS Devices'                = '(device.deviceOSType -eq "macOS")'
    'iOS Devices'                  = '(device.deviceOSType -eq "iOS")'
    'Android Devices'              = '(device.deviceOSType -eq "Android")'
    'Corporate Owned Devices'      = '(device.deviceOwnership -eq "Company")'
    'Personal Devices'             = '(device.deviceOwnership -eq "Personal")'
    'Pilot Device Group'           = '(device.displayName -startsWith "PILOT-")'
    'UAT Device Group'             = '(device.displayName -startsWith "UAT-")'
}

$failures = 0

function Write-Result {
    param([bool]$Pass, [string]$Message)
    if ($Pass) { Write-Host "  PASS  $Message" -ForegroundColor Green }
    else       { Write-Host "  FAIL  $Message" -ForegroundColor Red; $script:failures++ }
}

# ============================================================================
# Connect
# ============================================================================
Write-Host "`n== Connecting to test tenant (app-only) ==" -ForegroundColor Cyan
Connect-MgGraph -ClientId $AppId -TenantId $TenantId `
    -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
$ctx = Get-MgContext
if ($ctx.AuthType -ne 'AppOnly') { throw "Expected AppOnly auth, got $($ctx.AuthType)" }
Write-Host "  Connected to tenant $($ctx.TenantId)" -ForegroundColor Green

try {
    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running Device-Groups.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Intune/Device-Groups.ps1') `
        -NonInteractive -ConfigFile $ConfigPath -ResultPath $ResultPath

    Write-Host "`n== Waiting 30s for directory replication ==" -ForegroundColor Cyan
    Start-Sleep -Seconds 30

    # ========================================================================
    # Assert on the script's own reported results
    # ========================================================================
    Write-Host "`n== Verifying script results ==" -ForegroundColor Cyan
    if (!(Test-Path $ResultPath)) {
        Write-Result $false "Script produced no results file — it likely aborted early"
    }
    else {
        $result = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
        Write-Result ([bool]$result.Success) "Script reported success (created: $(@($result.Created).Count), skipped: $(@($result.Skipped).Count), failed: $(@($result.Failed).Count))"
        foreach ($fail in @($result.Failed)) {
            Write-Host "        failed group: $($fail.Name) — $($fail.Error)" -ForegroundColor Red
        }
    }

    # ========================================================================
    # Independently verify tenant state via Graph
    # ========================================================================
    Write-Host "`n== Verifying created groups in tenant ==" -ForegroundColor Cyan
    foreach ($name in $ExpectedGroups.Keys) {
        $fullName = "$E2EPrefix$name"
        $group = Get-MgGroup -Filter "displayName eq '$fullName'" -ErrorAction SilentlyContinue

        if (!$group) {
            Write-Result $false "$fullName exists"
            continue
        }
        Write-Result $true "$fullName exists"
        Write-Result ($group.GroupTypes -contains 'DynamicMembership') "$fullName is a dynamic group"
        Write-Result ($group.MembershipRule -eq $ExpectedGroups[$name]) "$fullName has the correct membership rule"
    }

    # ========================================================================
    # Idempotency: a second run must skip everything and create nothing
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run skips all) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Intune/Device-Groups.ps1') `
        -NonInteractive -ConfigFile $ConfigPath -ResultPath $ResultPath

    $second = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
    Write-Result ([bool]$second.Success -and @($second.Created).Count -eq 0 -and @($second.Skipped).Count -eq $ExpectedGroups.Count) `
        "Second run created nothing and skipped all $($ExpectedGroups.Count) groups"
}
finally {
    # ========================================================================
    # Cleanup — always runs; deletes ONLY prefix-matched groups
    # ========================================================================
    Write-Host "`n== Cleaning up E2E groups ==" -ForegroundColor Cyan
    try {
        $e2eGroups = @(Get-MgGroup -Filter "startsWith(displayName, '$E2EPrefix')" -All -ErrorAction Stop)
        foreach ($group in $e2eGroups) {
            try {
                Remove-MgGroup -GroupId $group.Id -Confirm:$false -ErrorAction Stop
                Write-Host "  Deleted group $($group.DisplayName)" -ForegroundColor Gray
            }
            catch {
                Write-Host "  WARNING: could not delete group $($group.DisplayName): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        Write-Host "  Removed $($e2eGroups.Count) group(s)" -ForegroundColor Green
    }
    catch {
        Write-Host "  WARNING: group cleanup query failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Manually delete groups prefixed '$E2EPrefix' in the test tenant" -ForegroundColor Yellow
    }

    Remove-Item $ResultPath -ErrorAction SilentlyContinue
    $null = Disconnect-MgGraph -ErrorAction SilentlyContinue
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
