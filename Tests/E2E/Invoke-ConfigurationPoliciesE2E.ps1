#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs Intune/Configuration-Policies.ps1 unattended against
    the dedicated M365 test tenant and verifies the configuration policies it
    creates.
.DESCRIPTION
    Connects to Microsoft Graph with certificate-based app-only auth, then:
      1. Runs Intune/Device-Groups.ps1 non-interactively (E2E- prefix) to
         create the two prerequisite dynamic device groups these policies
         are assigned to
      2. Runs Intune/Configuration-Policies.ps1 non-interactively (NamePrefix
         and GroupNamePrefix E2E-) — the real script, same file the menu
         calls
      3. Verifies all 18 expected configuration policies exist (via the same
         beta/deviceManagement/configurationPolicies endpoint the script
         itself uses) and that each has assignments to its target groups
      4. Re-runs the script to prove idempotency
      5. Deletes every E2E- prefixed configuration policy and device group in
         a finally block that always runs, so cleanup happens even on
         failure
.EXAMPLE
    ./Invoke-ConfigurationPoliciesE2E.ps1 -TenantId $env:M365_TENANT_ID -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $TenantId,
    [Parameter(Mandatory)] [string] $AppId,
    [Parameter(Mandatory)] [string] $CertificateThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot         = $PSScriptRoot | Split-Path | Split-Path
$GroupConfigPath  = Join-Path $PSScriptRoot 'device-groups.e2e.json'
$PolicyConfigPath = Join-Path $PSScriptRoot 'configuration-policies.e2e.json'
$GroupResultPath  = Join-Path ([IO.Path]::GetTempPath()) "dg-e2e-result-$([guid]::NewGuid().ToString('n')).json"
$PolicyResultPath = Join-Path ([IO.Path]::GetTempPath()) "cfp-e2e-result-$([guid]::NewGuid().ToString('n')).json"

$policyConfig = Get-Content $PolicyConfigPath -Raw | ConvertFrom-Json
$E2EPrefix = $policyConfig.NamePrefix
if (!$E2EPrefix) { throw "E2E config must set a NamePrefix — refusing to run without test isolation" }

# The 18 policies Configuration-Policies.ps1 creates, and the (already-prefixed)
# device groups each should be assigned to
$ExpectedPolicyAssignments = [ordered]@{
    "${E2EPrefix}Default Web Pages"                          = @("${E2EPrefix}Windows Devices (Autopilot)")
    "${E2EPrefix}Defender Configuration"                     = @("${E2EPrefix}Windows Devices (Autopilot)")
    "${E2EPrefix}Disable UAC for Quickassist"                = @("${E2EPrefix}Windows Devices (Autopilot)")
    "${E2EPrefix}Edge Update Policy"                         = @("${E2EPrefix}Windows Devices (Autopilot)")
    "${E2EPrefix}EDR Policy"                                 = @("${E2EPrefix}Windows Devices (Autopilot)")
    "${E2EPrefix}Enable Bitlocker"                            = @("${E2EPrefix}Windows Devices (Autopilot)")
    "${E2EPrefix}Enable Built-in Administrator Account"      = @("${E2EPrefix}Windows Devices (Autopilot)")
    "${E2EPrefix}LAPS"                                       = @("${E2EPrefix}Windows Devices (Autopilot)")
    "${E2EPrefix}Office Updates Configuration"                = @("${E2EPrefix}Windows Devices (Autopilot)")
    "${E2EPrefix}OneDrive Configuration"                      = @("${E2EPrefix}Windows Devices (Autopilot)")
    "${E2EPrefix}Outlook Configuration"                       = @("${E2EPrefix}Windows Devices (Autopilot)")
    "${E2EPrefix}Power Options"                               = @("${E2EPrefix}Windows Devices (Autopilot)")
    "${E2EPrefix}Prevent Users From Unenrolling Devices"      = @("${E2EPrefix}Windows Devices (Autopilot)", "${E2EPrefix}Corporate Owned Devices")
    "${E2EPrefix}Sharepoint File Sync"                        = @("${E2EPrefix}Windows Devices (Autopilot)")
    "${E2EPrefix}System Services"                             = @("${E2EPrefix}Windows Devices (Autopilot)")
    "${E2EPrefix}Tamper Protection"                           = @("${E2EPrefix}Windows Devices (Autopilot)")
    "${E2EPrefix}Web Sign-in Policy"                          = @("${E2EPrefix}Windows Devices (Autopilot)")
    "${E2EPrefix}NGP Windows Default Policy"                  = @("${E2EPrefix}Windows Devices (Autopilot)", "${E2EPrefix}Corporate Owned Devices")
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
    # Prerequisite: create the device groups Configuration-Policies depends on
    # ========================================================================
    Write-Host "`n== Creating prerequisite device groups (Device-Groups.ps1) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Intune/Device-Groups.ps1') `
        -NonInteractive -ConfigFile $GroupConfigPath -ResultPath $GroupResultPath

    Write-Host "`n== Waiting 30s for directory replication ==" -ForegroundColor Cyan
    Start-Sleep -Seconds 30

    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running Configuration-Policies.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Intune/Configuration-Policies.ps1') `
        -NonInteractive -ConfigFile $PolicyConfigPath -ResultPath $PolicyResultPath

    # ========================================================================
    # Assert on the script's own reported results
    # ========================================================================
    Write-Host "`n== Verifying script results ==" -ForegroundColor Cyan
    if (!(Test-Path $PolicyResultPath)) {
        Write-Result $false "Script produced no results file — it likely aborted early"
    }
    else {
        $result = Get-Content $PolicyResultPath -Raw | ConvertFrom-Json -AsHashtable
        Write-Result ([bool]$result.Success) "Script reported success (created: $(@($result.Created).Count), skipped: $(@($result.Skipped).Count), failed: $(@($result.Failed).Count))"
        foreach ($fail in @($result.Failed)) {
            Write-Host "        failed policy: $($fail.Name) — $($fail.Error)" -ForegroundColor Red
        }
    }

    # ========================================================================
    # Independently verify tenant state via Graph
    # ========================================================================
    Write-Host "`n== Verifying created policies in tenant ==" -ForegroundColor Cyan
    $allPolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -Method GET -ErrorAction Stop

    foreach ($policyName in $ExpectedPolicyAssignments.Keys) {
        $policy = $allPolicies.value | Where-Object { $_.name -eq $policyName }

        if (!$policy) {
            Write-Result $false "$policyName exists"
            continue
        }
        Write-Result $true "$policyName exists"

        $assignments = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($policy.id)')/assignments" -Method GET -ErrorAction Stop
        $assignedGroupIds = @($assignments.value | ForEach-Object { $_.target.groupId })

        foreach ($groupName in $ExpectedPolicyAssignments[$policyName]) {
            $group = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue
            Write-Result ($group -and ($assignedGroupIds -contains $group.Id)) "$policyName is assigned to $groupName"
        }
    }

    # ========================================================================
    # Idempotency: a second run must skip everything and create nothing
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run skips all) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Intune/Configuration-Policies.ps1') `
        -NonInteractive -ConfigFile $PolicyConfigPath -ResultPath $PolicyResultPath

    $second = Get-Content $PolicyResultPath -Raw | ConvertFrom-Json -AsHashtable
    Write-Result ([bool]$second.Success -and @($second.Created).Count -eq 0 -and @($second.Skipped).Count -eq $ExpectedPolicyAssignments.Count) `
        "Second run created nothing and skipped all $($ExpectedPolicyAssignments.Count) policies"
}
finally {
    # ========================================================================
    # Cleanup — always runs; deletes ONLY prefix-matched objects
    # ========================================================================
    Write-Host "`n== Cleaning up E2E configuration policies ==" -ForegroundColor Cyan
    try {
        $allPolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -Method GET -ErrorAction Stop
        $e2ePolicies = @($allPolicies.value | Where-Object { $_.name -like "$E2EPrefix*" })
        foreach ($policy in $e2ePolicies) {
            try {
                $null = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($policy.id)')" -Method DELETE -ErrorAction Stop
                Write-Host "  Deleted policy $($policy.name)" -ForegroundColor Gray
            }
            catch {
                Write-Host "  WARNING: could not delete policy $($policy.name): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        Write-Host "  Removed $($e2ePolicies.Count) polic(y/ies)" -ForegroundColor Green
    }
    catch {
        Write-Host "  WARNING: policy cleanup query failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Manually delete configuration policies prefixed '$E2EPrefix' in the test tenant" -ForegroundColor Yellow
    }

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

    Remove-Item $GroupResultPath, $PolicyResultPath -ErrorAction SilentlyContinue
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
