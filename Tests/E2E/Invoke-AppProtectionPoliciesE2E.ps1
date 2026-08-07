#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs Intune/App-Protection-Policies.ps1 unattended against
    the dedicated M365 test tenant and verifies the app protection policies it
    creates.
.DESCRIPTION
    Connects to Microsoft Graph with certificate-based app-only auth, then:
      1. Runs entra/Security-Groups.ps1 non-interactively (E2E- prefix) to
         create the NoMFA Exclusion Group this script uses as an assignment
         exclusion
      2. Runs Intune/App-Protection-Policies.ps1 non-interactively (E2E-
         prefix) — the real script, same file the menu calls. It auto-creates
         its own CA-BYOD-Mobile group (the required assignment target - Intune
         app protection policies reject "All Licensed Users", confirmed live)
      3. Verifies the 2 expected policies (Android + iOS) exist via the beta
         deviceAppManagement endpoints, are targeted at the core M365 apps,
         and are assigned to the E2E CA-BYOD-Mobile group with the E2E NoMFA
         group excluded
      4. Re-runs the script to prove idempotency (settings/apps reconciled,
         no duplicate policies, assignment left untouched)
      5. Deletes every E2E- prefixed app protection policy and group in a
         finally block that always runs, so cleanup happens even on failure
.EXAMPLE
    ./Invoke-AppProtectionPoliciesE2E.ps1 -TenantId $env:M365_TENANT_ID -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
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
$GroupConfigPath = Join-Path $PSScriptRoot 'security-groups.e2e.json'
$AppConfigPath   = Join-Path $PSScriptRoot 'app-protection-policies.e2e.json'
$GroupResultPath = Join-Path ([IO.Path]::GetTempPath()) "sg-e2e-result-$([guid]::NewGuid().ToString('n')).json"
$AppResultPath   = Join-Path ([IO.Path]::GetTempPath()) "ap-e2e-result-$([guid]::NewGuid().ToString('n')).json"

$appConfig = Get-Content $AppConfigPath -Raw | ConvertFrom-Json
$E2EPrefix = $appConfig.NamePrefix
if (!$E2EPrefix) { throw "E2E config must set a NamePrefix — refusing to run without test isolation" }

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
    # Prerequisite: create the NoMFA Exclusion Group this script uses
    # ========================================================================
    Write-Host "`n== Creating prerequisite groups (Security-Groups.ps1) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'entra/Security-Groups.ps1') `
        -NonInteractive -ConfigFile $GroupConfigPath -ResultPath $GroupResultPath

    Write-Host "`n== Waiting 30s for directory replication ==" -ForegroundColor Cyan
    Start-Sleep -Seconds 30

    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running App-Protection-Policies.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Intune/App-Protection-Policies.ps1') `
        -NonInteractive -ConfigFile $AppConfigPath -ResultPath $AppResultPath

    # ========================================================================
    # Assert on the script's own reported results
    # ========================================================================
    Write-Host "`n== Verifying script results ==" -ForegroundColor Cyan
    if (!(Test-Path $AppResultPath)) {
        Write-Result $false "Script produced no results file — it likely aborted early"
    }
    else {
        $result = Get-Content $AppResultPath -Raw | ConvertFrom-Json -AsHashtable
        Write-Result ([bool]$result.Success) "Script reported success (created: $(@($result.Created).Count), skipped: $(@($result.Skipped).Count), failed: $(@($result.Failed).Count))"
        foreach ($fail in @($result.Failed)) {
            Write-Host "        failed policy: $($fail.Name) — $($fail.Error)" -ForegroundColor Red
        }
    }

    # ========================================================================
    # Independently verify tenant state via Graph
    # ========================================================================
    Write-Host "`n== Verifying created policies in tenant ==" -ForegroundColor Cyan
    $noMfaGroup = Get-MgGroup -Filter "displayName eq '${E2EPrefix}NoMFA Exclusion Group'" -ErrorAction SilentlyContinue
    Write-Result ([bool]$noMfaGroup) "${E2EPrefix}NoMFA Exclusion Group exists (created by Security-Groups.ps1)"
    $byodGroup = Get-MgGroup -Filter "displayName eq '${E2EPrefix}CA-BYOD-Mobile'" -ErrorAction SilentlyContinue
    Write-Result ([bool]$byodGroup) "${E2EPrefix}CA-BYOD-Mobile group was auto-created (required assignment target)"

    $expectedPolicies = @(
        @{ Name = "${E2EPrefix}Android App Protection Policy"; Endpoint = 'androidManagedAppProtections' }
        @{ Name = "${E2EPrefix}iOS App Protection Policy"; Endpoint = 'iosManagedAppProtections' }
    )

    foreach ($expected in $expectedPolicies) {
        $allPolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/$($expected.Endpoint)" -Method GET -ErrorAction Stop
        $policy = $allPolicies.value | Where-Object { $_.displayName -eq $expected.Name }

        if (!$policy) {
            Write-Result $false "$($expected.Name) exists"
            continue
        }
        Write-Result $true "$($expected.Name) exists"
        Write-Result ($policy.pinRequired -eq $true) "$($expected.Name) requires an app-level PIN"
        Write-Result ($policy.dataBackupBlocked -eq $true) "$($expected.Name) blocks data backup"

        # Targeted apps
        $apps = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/$($expected.Endpoint)('$($policy.id)')/apps" -Method GET -ErrorAction Stop
        Write-Result (@($apps.value).Count -ge 7) "$($expected.Name) has at least 7 targeted apps (actual: $(@($apps.value).Count))"

        # Assignment: CA-BYOD-Mobile group + NoMFA exclusion group
        $assignments = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/$($expected.Endpoint)('$($policy.id)')/assignments" -Method GET -ErrorAction Stop
        if ($byodGroup) {
            $includeAssignment = $assignments.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' }
            Write-Result ($includeAssignment -and $includeAssignment.target.groupId -eq $byodGroup.Id) "$($expected.Name) is assigned to the E2E CA-BYOD-Mobile group"
        }

        if ($noMfaGroup) {
            $exclusionAssignment = $assignments.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget' }
            Write-Result ($exclusionAssignment -and $exclusionAssignment.target.groupId -eq $noMfaGroup.Id) "$($expected.Name) excludes the E2E NoMFA group"
        }
    }

    # ========================================================================
    # Idempotency: a second run must skip everything and create nothing
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run skips all) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Intune/App-Protection-Policies.ps1') `
        -NonInteractive -ConfigFile $AppConfigPath -ResultPath $AppResultPath

    $second = Get-Content $AppResultPath -Raw | ConvertFrom-Json -AsHashtable
    Write-Result ([bool]$second.Success -and @($second.Created).Count -eq 0 -and @($second.Skipped).Count -eq $expectedPolicies.Count) `
        "Second run created nothing and skipped all $($expectedPolicies.Count) policies"
}
finally {
    # ========================================================================
    # Cleanup — always runs; deletes ONLY prefix-matched objects
    # ========================================================================
    Write-Host "`n== Cleaning up E2E app protection policies ==" -ForegroundColor Cyan
    foreach ($endpoint in @('androidManagedAppProtections', 'iosManagedAppProtections')) {
        try {
            $allPolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/$endpoint" -Method GET -ErrorAction Stop
            $e2ePolicies = @($allPolicies.value | Where-Object { $_.displayName -like "$E2EPrefix*" })
            foreach ($policy in $e2ePolicies) {
                try {
                    $null = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/$endpoint('$($policy.id)')" -Method DELETE -ErrorAction Stop
                    Write-Host "  Deleted policy $($policy.displayName)" -ForegroundColor Gray
                }
                catch {
                    Write-Host "  WARNING: could not delete policy $($policy.displayName): $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
            Write-Host "  Removed $($e2ePolicies.Count) polic(y/ies) from $endpoint" -ForegroundColor Green
        }
        catch {
            Write-Host "  WARNING: policy cleanup query failed for ${endpoint}: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "  Manually delete app protection policies prefixed '$E2EPrefix' in the test tenant" -ForegroundColor Yellow
        }
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

    Remove-Item $GroupResultPath, $AppResultPath -ErrorAction SilentlyContinue
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
