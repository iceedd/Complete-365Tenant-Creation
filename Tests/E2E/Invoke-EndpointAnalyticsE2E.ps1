#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs Intune/Endpoint-Analytics.ps1 unattended against the
    dedicated M365 test tenant and verifies the policy it creates.
.DESCRIPTION
    Connects to Microsoft Graph with certificate-based app-only auth, then:
      1. Runs Intune/Device-Groups.ps1 non-interactively (E2E- prefix) to
         create the prerequisite device group the policy is assigned to
      2. Runs Intune/Endpoint-Analytics.ps1 non-interactively (NamePrefix and
         GroupNamePrefix E2E-) — the real script, same file the menu calls
      3. Verifies the policy exists, is assigned to the E2E device group, and
         independently reads back its actual applied setting VALUES (not just
         that a policy object with this name exists) — this is what proves
         the two settingDefinitionId strings are real and accepted by this
         tenant's Settings Catalog, rather than just trusting the script's own
         success report
      4. Re-runs the script to prove idempotency
      5. Deletes the E2E- prefixed policy and device group in a finally block
         that always runs, so cleanup happens even on failure
.EXAMPLE
    ./Invoke-EndpointAnalyticsE2E.ps1 -TenantId $env:M365_TENANT_ID -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $TenantId,
    [Parameter(Mandatory)] [string] $AppId,
    [Parameter(Mandatory)] [string] $CertificateThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot        = $PSScriptRoot | Split-Path | Split-Path
$GroupConfigPath = Join-Path $PSScriptRoot 'device-groups.e2e.json'
$PolicyConfigPath = Join-Path $PSScriptRoot 'endpoint-analytics.e2e.json'
$GroupResultPath  = Join-Path ([IO.Path]::GetTempPath()) "dg-e2e-result-$([guid]::NewGuid().ToString('n')).json"
$PolicyResultPath = Join-Path ([IO.Path]::GetTempPath()) "ea-e2e-result-$([guid]::NewGuid().ToString('n')).json"

$policyConfig = Get-Content $PolicyConfigPath -Raw | ConvertFrom-Json
$E2EPrefix = $policyConfig.NamePrefix
if (!$E2EPrefix) { throw "E2E config must set a NamePrefix — refusing to run without test isolation" }

$PolicyName = "${E2EPrefix}Endpoint Analytics - Diagnostic Data"
$GroupName  = "${E2EPrefix}Windows Devices (Autopilot)"

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
    # Prerequisite: create the device group Endpoint-Analytics depends on
    # ========================================================================
    Write-Host "`n== Creating prerequisite device group (Device-Groups.ps1) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Intune/Device-Groups.ps1') `
        -NonInteractive -ConfigFile $GroupConfigPath -ResultPath $GroupResultPath

    Write-Host "`n== Waiting 30s for directory replication ==" -ForegroundColor Cyan
    Start-Sleep -Seconds 30

    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running Endpoint-Analytics.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Intune/Endpoint-Analytics.ps1') `
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
        Write-Result ([bool]$result.Success) "Script reported success (skipped: $($result.Skipped))"
    }

    # ========================================================================
    # Independently verify tenant state via Graph
    # ========================================================================
    Write-Host "`n== Verifying created policy in tenant ==" -ForegroundColor Cyan
    $allPolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -Method GET -ErrorAction Stop
    $policy = $allPolicies.value | Where-Object { $_.name -eq $PolicyName }

    Write-Result ([bool]$policy) "$PolicyName exists"

    if ($policy) {
        $assignments = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($policy.id)')/assignments" -Method GET -ErrorAction Stop
        $assignedGroupIds = @($assignments.value | ForEach-Object { $_.target.groupId })
        $group = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue
        Write-Result ($group -and ($assignedGroupIds -contains $group.Id)) "$PolicyName is assigned to $GroupName"

        # Independently confirm the actual applied setting VALUES, not just that
        # a policy object with this name exists — this is what proves the two
        # settingDefinitionId strings are real and correctly accepted by this
        # tenant's Settings Catalog.
        $settings = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($policy.id)')/settings" -Method GET -ErrorAction Stop
        $telemetry = $settings.value | Where-Object { $_.settingInstance.settingDefinitionId -eq 'device_vendor_msft_policy_config_system_allowtelemetry' } | Select-Object -First 1
        $deviceName = $settings.value | Where-Object { $_.settingInstance.settingDefinitionId -eq 'device_vendor_msft_policy_config_system_allowdevicenameindiagnosticdata' } | Select-Object -First 1

        Write-Result ([bool]$telemetry -and $telemetry.settingInstance.choiceSettingValue.value -eq 'device_vendor_msft_policy_config_system_allowtelemetry_1') "Diagnostic data is set to Required (1)"
        Write-Result ([bool]$deviceName -and $deviceName.settingInstance.choiceSettingValue.value -eq 'device_vendor_msft_policy_config_system_allowdevicenameindiagnosticdata_1') "Allow device name in diagnostic data is Enabled"
    }

    # ========================================================================
    # Idempotency: a second run must skip and create nothing
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run skips) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Intune/Endpoint-Analytics.ps1') `
        -NonInteractive -ConfigFile $PolicyConfigPath -ResultPath $PolicyResultPath

    $second = Get-Content $PolicyResultPath -Raw | ConvertFrom-Json -AsHashtable
    Write-Result ([bool]$second.Success -and [bool]$second.Skipped) "Second run skipped the existing policy and created nothing"
}
finally {
    # ========================================================================
    # Cleanup — always runs; deletes ONLY prefix-matched objects
    # ========================================================================
    Write-Host "`n== Cleaning up E2E policy ==" -ForegroundColor Cyan
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
