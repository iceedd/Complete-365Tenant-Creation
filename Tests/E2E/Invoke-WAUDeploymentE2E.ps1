#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs Intune/WAU-Deployment.ps1 unattended against the
    dedicated M365 test tenant and verifies the ADMX import, Store app, and
    configuration policy it creates.
.DESCRIPTION
    Connects to Microsoft Graph with certificate-based app-only auth, then:
      1. Runs Intune/Device-Groups.ps1 non-interactively (E2E- prefix) to
         create the prerequisite "Windows Devices (Autopilot)" group this
         script assigns the app and config policy to
      2. Runs Intune/WAU-Deployment.ps1 non-interactively (NamePrefix and
         GroupNamePrefix E2E-) — the real script, same file the menu calls
      3. Verifies via Graph: the WAU ADMX was imported and processed
         (available), the winGetApp Store app exists and is assigned to the
         target group, and the Administrative Templates config policy
         exists and is assigned to the target group
      4. Re-runs the script to prove idempotency (ADMX/App/Config all
         reported as already-existing, no errors)
      5. Deletes the config policy, the app, the imported ADMX definition
         file, and the E2E- prefixed device groups in a finally block that
         always runs, so cleanup happens even on failure

    Note: the ADMX file itself is NOT prefixed (it's a single shared
    tenant-wide resource, same as real usage), so cleanup always removes it
    — this test tenant is dedicated to E2E testing only.
.EXAMPLE
    ./Invoke-WAUDeploymentE2E.ps1 -TenantId $env:M365_TENANT_ID -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
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
$WAUConfigPath   = Join-Path $PSScriptRoot 'wau-deployment.e2e.json'
$GroupResultPath = Join-Path ([IO.Path]::GetTempPath()) "dg-e2e-result-$([guid]::NewGuid().ToString('n')).json"
$WAUResultPath   = Join-Path ([IO.Path]::GetTempPath()) "wau-e2e-result-$([guid]::NewGuid().ToString('n')).json"

$wauConfig = Get-Content $WAUConfigPath -Raw | ConvertFrom-Json
$E2EPrefix = $wauConfig.NamePrefix
if (!$E2EPrefix) { throw "E2E config must set a NamePrefix — refusing to run without test isolation" }

$ExpectedAppName    = "${E2EPrefix}WinGet-AutoUpdate-Configurator"
$ExpectedPolicyName = "${E2EPrefix}WAU - MSP Configuration"
$ExpectedGroupName  = "${E2EPrefix}Windows Devices (Autopilot)"
$AdmxFileName       = "WinGet-AutoUpdate-Configurator.admx"

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
    # Prerequisite: create the device group WAU-Deployment assigns to
    # ========================================================================
    Write-Host "`n== Creating prerequisite device groups (Device-Groups.ps1) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Intune/Device-Groups.ps1') `
        -NonInteractive -ConfigFile $GroupConfigPath -ResultPath $GroupResultPath

    Write-Host "`n== Waiting 30s for directory replication ==" -ForegroundColor Cyan
    Start-Sleep -Seconds 30

    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running WAU-Deployment.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Intune/WAU-Deployment.ps1') `
        -NonInteractive -ConfigFile $WAUConfigPath -ResultPath $WAUResultPath

    # ========================================================================
    # Assert on the script's own reported results
    # ========================================================================
    Write-Host "`n== Verifying script results ==" -ForegroundColor Cyan
    if (!(Test-Path $WAUResultPath)) {
        Write-Result $false "Script produced no results file — it likely aborted early"
    }
    else {
        $result = Get-Content $WAUResultPath -Raw | ConvertFrom-Json -AsHashtable
        Write-Result ([bool]$result.Success) "Script reported success (ADMX: $($result.AdmxImported), App: $($result.AppDeployed), Config: $($result.ConfigDeployed))"
        foreach ($err in @($result.Errors)) {
            Write-Host "        error: $err" -ForegroundColor Red
        }
    }

    # ========================================================================
    # Independently verify tenant state via Graph
    # ========================================================================
    Write-Host "`n== Verifying ADMX import in tenant ==" -ForegroundColor Cyan
    $admxFiles = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles" -Method GET -ErrorAction Stop
    $admx = $admxFiles.value | Where-Object { $_.fileName -eq $AdmxFileName } | Select-Object -First 1
    Write-Result ([bool]$admx) "$AdmxFileName was imported"
    if ($admx) {
        Write-Result ($admx.status -eq 'available') "ADMX processing completed (status: $($admx.status))"
    }

    Write-Host "`n== Verifying Store app in tenant ==" -ForegroundColor Cyan
    $apps = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=displayName eq '$ExpectedAppName'" -Method GET -ErrorAction Stop
    $app = $apps.value | Select-Object -First 1
    Write-Result ([bool]$app) "$ExpectedAppName exists"

    $group = Get-MgGroup -Filter "displayName eq '$ExpectedGroupName'" -ErrorAction SilentlyContinue
    if ($app -and $group) {
        $appAssignments = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$($app.id)')/assignments" -Method GET -ErrorAction Stop
        $assignedAppGroupIds = @($appAssignments.value | ForEach-Object { $_.target.groupId })
        Write-Result ($assignedAppGroupIds -contains $group.Id) "$ExpectedAppName is assigned to $ExpectedGroupName"
    }

    Write-Host "`n== Verifying configuration policy in tenant ==" -ForegroundColor Cyan
    $configs = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations?`$filter=displayName eq '$ExpectedPolicyName'" -Method GET -ErrorAction Stop
    $config = $configs.value | Select-Object -First 1
    Write-Result ([bool]$config) "$ExpectedPolicyName exists"

    if ($config -and $group) {
        $configAssignments = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($config.id)/assignments" -Method GET -ErrorAction Stop
        $assignedConfigGroupIds = @($configAssignments.value | ForEach-Object { $_.target.groupId })
        Write-Result ($assignedConfigGroupIds -contains $group.Id) "$ExpectedPolicyName is assigned to $ExpectedGroupName"

        $defValues = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($config.id)/definitionValues" -Method GET -ErrorAction Stop
        Write-Result (@($defValues.value).Count -gt 0) "$ExpectedPolicyName has configured setting definition values (found $(@($defValues.value).Count))"
    }

    # ========================================================================
    # Idempotency: a second run must report everything as already existing
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run skips all) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Intune/WAU-Deployment.ps1') `
        -NonInteractive -ConfigFile $WAUConfigPath -ResultPath $WAUResultPath

    $second = Get-Content $WAUResultPath -Raw | ConvertFrom-Json -AsHashtable
    Write-Result ([bool]$second.Success -and [bool]$second.AdmxImported -and [bool]$second.AppDeployed -and [bool]$second.ConfigDeployed -and @($second.Errors).Count -eq 0) `
        "Second run reported ADMX/App/Config all already-existing with no errors"
}
finally {
    # ========================================================================
    # Cleanup — always runs
    # ========================================================================
    Write-Host "`n== Cleaning up E2E configuration policy ==" -ForegroundColor Cyan
    try {
        $configs = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations?`$filter=displayName eq '$ExpectedPolicyName'" -Method GET -ErrorAction Stop
        foreach ($config in @($configs.value)) {
            try {
                $null = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($config.id)" -Method DELETE -ErrorAction Stop
                Write-Host "  Deleted config policy $($config.displayName)" -ForegroundColor Gray
            }
            catch {
                Write-Host "  WARNING: could not delete config policy $($config.displayName): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Host "  WARNING: config policy cleanup query failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Manually delete the '$ExpectedPolicyName' configuration policy in the test tenant" -ForegroundColor Yellow
    }

    Write-Host "`n== Cleaning up E2E Store app ==" -ForegroundColor Cyan
    try {
        $apps = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=displayName eq '$ExpectedAppName'" -Method GET -ErrorAction Stop
        foreach ($app in @($apps.value)) {
            try {
                $null = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($app.id)" -Method DELETE -ErrorAction Stop
                Write-Host "  Deleted app $($app.displayName)" -ForegroundColor Gray
            }
            catch {
                Write-Host "  WARNING: could not delete app $($app.displayName): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Host "  WARNING: app cleanup query failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Manually delete the '$ExpectedAppName' app in the test tenant" -ForegroundColor Yellow
    }

    Write-Host "`n== Cleaning up imported WAU ADMX ==" -ForegroundColor Cyan
    try {
        $admxFiles = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles" -Method GET -ErrorAction Stop
        foreach ($admx in @($admxFiles.value | Where-Object { $_.fileName -eq $AdmxFileName })) {
            try {
                $null = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles/$($admx.id)" -Method DELETE -ErrorAction Stop
                Write-Host "  Deleted ADMX $($admx.fileName)" -ForegroundColor Gray
            }
            catch {
                Write-Host "  WARNING: could not delete ADMX $($admx.fileName): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Host "  WARNING: ADMX cleanup query failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Manually delete the '$AdmxFileName' ADMX file in the test tenant" -ForegroundColor Yellow
    }

    Write-Host "`n== Cleaning up E2E groups ==" -ForegroundColor Cyan
    try {
        $e2eGroups = @(Get-MgGroup -Filter "startsWith(displayName, '$E2EPrefix')" -All -ErrorAction Stop)
        foreach ($grp in $e2eGroups) {
            try {
                Remove-MgGroup -GroupId $grp.Id -Confirm:$false -ErrorAction Stop
                Write-Host "  Deleted group $($grp.DisplayName)" -ForegroundColor Gray
            }
            catch {
                Write-Host "  WARNING: could not delete group $($grp.DisplayName): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        Write-Host "  Removed $($e2eGroups.Count) group(s)" -ForegroundColor Green
    }
    catch {
        Write-Host "  WARNING: group cleanup query failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Manually delete groups prefixed '$E2EPrefix' in the test tenant" -ForegroundColor Yellow
    }

    Remove-Item $GroupResultPath, $WAUResultPath -ErrorAction SilentlyContinue
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
