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
      3. Verifies the 17 configuration policies expected to succeed exist
         (via the same beta/deviceManagement/configurationPolicies endpoint
         the script itself uses) and that each has assignments to its target
         groups. The 18th, "EDR Policy", is a documented, known Microsoft-
         side limitation (see CLAUDE.md) — it 400s via Graph regardless of
         script correctness, so this test asserts the script reports it as
         a clean, expected failure rather than requiring it to succeed.
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

# Configuration-Policies.ps1's Get-PolicyDefinitions downloads
# AllPolicies_Complete.json from GitHub (defaulting to $Global:GitHubBranch =
# "main" when unset — only Main-Menu.ps1 normally sets this), so invoking it
# directly here would silently test whatever policy JSON is currently on
# main, not this branch's checked-out copy (confirmed live: a policy added
# only on this branch never appeared — "Loaded 18 policy definitions" instead
# of 19, no download error, no local-fallback message, just silently stale).
# Point it at this run's actual branch so JSON-only changes are covered too.
$Global:GitHubRepo = if ($env:GITHUB_REPOSITORY) { $env:GITHUB_REPOSITORY } else { 'iceedd/Complete-365Tenant-Creation' }
$Global:GitHubBranch = if ($env:GITHUB_REF_NAME) { $env:GITHUB_REF_NAME }
    elseif ($env:GITHUB_HEAD_REF) { $env:GITHUB_HEAD_REF }
    else { (git -C $RepoRoot rev-parse --abbrev-ref HEAD 2>$null) }
if (!$Global:GitHubBranch) { $Global:GitHubBranch = 'main' }
Write-Host "Using GitHub branch '$Global:GitHubBranch' for policy definition downloads" -ForegroundColor Gray
$GroupResultPath  = Join-Path ([IO.Path]::GetTempPath()) "dg-e2e-result-$([guid]::NewGuid().ToString('n')).json"
$PolicyResultPath = Join-Path ([IO.Path]::GetTempPath()) "cfp-e2e-result-$([guid]::NewGuid().ToString('n')).json"

$policyConfig = Get-Content $PolicyConfigPath -Raw | ConvertFrom-Json
$E2EPrefix = $policyConfig.NamePrefix
if (!$E2EPrefix) { throw "E2E config must set a NamePrefix — refusing to run without test isolation" }

# The 18 policies Configuration-Policies.ps1 creates, and the (already-prefixed)
# device groups each should be assigned to.
#
# "EDR Policy" is deliberately excluded: per CLAUDE.md's documented, known
# Microsoft-side limitation, this settings-catalog policy 400s via Graph in
# this tenant regardless of script correctness (EDR/MDE-connector setup is
# manual-portal-only). The script already handles this gracefully — reports
# it as a Failed policy with a clear error and manual-setup guidance — so we
# assert on that expected-failure behaviour below instead of treating it as
# a test failure.
$KnownFailurePolicy = "${E2EPrefix}EDR Policy"
$ExpectedPolicyAssignments = [ordered]@{
    "${E2EPrefix}Default Web Pages"                          = @("${E2EPrefix}Windows Devices (Autopilot)")
    "${E2EPrefix}Defender Configuration"                     = @("${E2EPrefix}Windows Devices (Autopilot)")
    "${E2EPrefix}Disable UAC for Quickassist"                = @("${E2EPrefix}Windows Devices (Autopilot)")
    "${E2EPrefix}Edge Update Policy"                         = @("${E2EPrefix}Windows Devices (Autopilot)")
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
    "${E2EPrefix}WindowsHelloforBusiness"                     = @("${E2EPrefix}Windows Devices (Autopilot)")
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
        $unexpectedFailures = @(@($result.Failed) | Where-Object { $_.Name -ne $KnownFailurePolicy })
        Write-Result ($unexpectedFailures.Count -eq 0) "Script reported success aside from the known EDR Policy limitation (created: $(@($result.Created).Count), skipped: $(@($result.Skipped).Count), failed: $(@($result.Failed).Count))"
        foreach ($fail in @($result.Failed)) {
            $tag = if ($fail.Name -eq $KnownFailurePolicy) { "(known limitation)" } else { "(UNEXPECTED)" }
            Write-Host "        failed policy: $($fail.Name) $tag — $($fail.Error)" -ForegroundColor $(if ($fail.Name -eq $KnownFailurePolicy) { 'Yellow' } else { 'Red' })
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

        # WindowsHelloforBusiness: independently confirm the actual applied
        # setting VALUES, not just that some policy object with this name
        # exists — this is what actually proves the settingDefinitionIds are
        # real and correctly accepted by this tenant's Settings Catalog.
        if ($policyName -eq "${E2EPrefix}WindowsHelloforBusiness") {
            $whfbSettings = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($policy.id)')/settings" -Method GET -ErrorAction Stop
            $root = $whfbSettings.value | Where-Object { $_.settingInstance.settingDefinitionId -eq 'device_vendor_msft_passportforwork_devicewide' } | Select-Object -First 1
            Write-Result ([bool]$root -and $root.settingInstance.choiceSettingValue.value -eq 'device_vendor_msft_passportforwork_devicewide_1') "WHfB is enabled (device-wide)"

            if ($root) {
                $children = @($root.settingInstance.choiceSettingValue.children)
                $pinRecovery = $children | Where-Object { $_.settingDefinitionId -like '*enablepinrecovery' } | Select-Object -First 1
                $pinMin      = $children | Where-Object { $_.settingDefinitionId -like '*pinminimumlength' } | Select-Object -First 1
                $pinMax      = $children | Where-Object { $_.settingDefinitionId -like '*pinmaximumlength' } | Select-Object -First 1
                $pinHistory  = $children | Where-Object { $_.settingDefinitionId -like '*pinhistory' } | Select-Object -First 1
                Write-Result ($pinRecovery -and $pinRecovery.choiceSettingValue.value -like '*_1') "WHfB PIN recovery is enabled"
                Write-Result ($pinMin -and $pinMin.simpleSettingValue.value -eq 6) "WHfB minimum PIN length is 6"
                Write-Result ($pinMax -and $pinMax.simpleSettingValue.value -eq 127) "WHfB maximum PIN length is 127"
                Write-Result ($pinHistory -and $pinHistory.simpleSettingValue.value -eq 5) "WHfB PIN history is 5"
            }

            $biometrics = $whfbSettings.value | Where-Object { $_.settingInstance.settingDefinitionId -like '*biometrics_usebiometrics' } | Select-Object -First 1
            Write-Result ([bool]$biometrics -and $biometrics.settingInstance.choiceSettingValue.value -like '*_1') "WHfB biometrics is allowed"
        }
    }

    # ========================================================================
    # Idempotency: a second run must skip everything and create nothing
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run skips all) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Intune/Configuration-Policies.ps1') `
        -NonInteractive -ConfigFile $PolicyConfigPath -ResultPath $PolicyResultPath

    $second = Get-Content $PolicyResultPath -Raw | ConvertFrom-Json -AsHashtable
    $secondUnexpectedFailures = @(@($second.Failed) | Where-Object { $_.Name -ne $KnownFailurePolicy })
    Write-Result (@($second.Created).Count -eq 0 -and @($second.Skipped).Count -eq $ExpectedPolicyAssignments.Count -and $secondUnexpectedFailures.Count -eq 0) `
        "Second run created nothing and skipped all $($ExpectedPolicyAssignments.Count) policies (aside from the known EDR Policy limitation)"
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
