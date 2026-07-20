#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs Intune/Compliance-Policies.ps1 unattended against
    the dedicated M365 test tenant and verifies the compliance policies it
    creates.
.DESCRIPTION
    Connects to Microsoft Graph with certificate-based app-only auth, then:
      1. Runs Intune/Device-Groups.ps1 non-interactively (E2E- prefix) to
         create the prerequisite dynamic device groups this script assigns
         policies to
      2. Runs Intune/Compliance-Policies.ps1 non-interactively (NamePrefix
         and GroupNamePrefix E2E-) — the real script, same file the menu
         calls
      3. Verifies the 4 expected compliance policies exist (via the same
         beta/deviceManagement/deviceCompliancePolicies endpoint the script
         itself uses — the SDK cmdlets have a known assignment bug, see
         CLAUDE.md) and that each has assignments to its target groups
      4. Re-runs the script to prove idempotency
      5. Deletes every E2E- prefixed compliance policy and device group in a
         finally block that always runs, so cleanup happens even on failure
.EXAMPLE
    ./Invoke-CompliancePoliciesE2E.ps1 -TenantId $env:M365_TENANT_ID -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
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
$PolicyConfigPath = Join-Path $PSScriptRoot 'compliance-policies.e2e.json'
$GroupResultPath  = Join-Path ([IO.Path]::GetTempPath()) "dg-e2e-result-$([guid]::NewGuid().ToString('n')).json"
$PolicyResultPath = Join-Path ([IO.Path]::GetTempPath()) "cp-e2e-result-$([guid]::NewGuid().ToString('n')).json"

# Compliance-Policies.ps1's Get-PolicyDefinitions downloads
# CompliancePolicies_Complete.json from GitHub (defaulting to
# $Global:GitHubBranch = "main" when unset — only Main-Menu.ps1 normally
# sets this), so invoking it directly here would silently test whatever
# policy JSON is on main, not this branch's checked-out copy. Confirmed
# live: this is what made the earlier Windows-policy-trim run look like a
# read-after-write consistency bug — it was actually reconciling against
# main's still-untrimmed definition the whole time. Point it at this run's
# actual branch so JSON-only changes are covered too.
$Global:GitHubRepo = if ($env:GITHUB_REPOSITORY) { $env:GITHUB_REPOSITORY } else { 'iceedd/Complete-365Tenant-Creation' }
$Global:GitHubBranch = if ($env:GITHUB_REF_NAME) { $env:GITHUB_REF_NAME }
    elseif ($env:GITHUB_HEAD_REF) { $env:GITHUB_HEAD_REF }
    else { (git -C $RepoRoot rev-parse --abbrev-ref HEAD 2>$null) }
if (!$Global:GitHubBranch) { $Global:GitHubBranch = 'main' }
Write-Host "Using GitHub branch '$Global:GitHubBranch' for policy definition downloads" -ForegroundColor Gray

$policyConfig = Get-Content $PolicyConfigPath -Raw | ConvertFrom-Json
$E2EPrefix = $policyConfig.NamePrefix
if (!$E2EPrefix) { throw "E2E config must set a NamePrefix — refusing to run without test isolation" }

# The 4 policies Compliance-Policies.ps1 creates, and the (already-prefixed)
# device groups each should be assigned to
$ExpectedPolicyAssignments = [ordered]@{
    "${E2EPrefix}Android Basic Compliance"          = @("${E2EPrefix}Android Devices", "${E2EPrefix}Corporate Owned Devices")
    "${E2EPrefix}iOS Basic Compliance"               = @("${E2EPrefix}iOS Devices", "${E2EPrefix}Corporate Owned Devices")
    "${E2EPrefix}macOS Basic Compliance"             = @("${E2EPrefix}macOS Devices", "${E2EPrefix}Corporate Owned Devices")
    "${E2EPrefix}Windows 10/11 Basic Compliance"     = @("${E2EPrefix}Windows Devices (Autopilot)", "${E2EPrefix}Corporate Owned Devices")
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
    # Prerequisite: create the device groups Compliance-Policies depends on
    # ========================================================================
    Write-Host "`n== Creating prerequisite device groups (Device-Groups.ps1) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Intune/Device-Groups.ps1') `
        -NonInteractive -ConfigFile $GroupConfigPath -ResultPath $GroupResultPath

    Write-Host "`n== Waiting 30s for directory replication ==" -ForegroundColor Cyan
    Start-Sleep -Seconds 30

    # ========================================================================
    # Pre-create the Windows policy under its OLD (pre-trim) definition, to
    # prove New-CompliancePolicy's "already exists" path actually reconciles
    # settings on a tenant that has the policy from before it was trimmed to
    # BitLocker + minimum OS only — not just skips silently forever.
    # ========================================================================
    Write-Host "`n== Pre-creating Windows policy under its old (untrimmed) definition ==" -ForegroundColor Cyan
    $oldWindowsPolicyBody = @{
        '@odata.type'      = '#microsoft.graph.windows10CompliancePolicy'
        displayName        = "${E2EPrefix}Windows 10/11 Basic Compliance"
        passwordRequired   = $true
        passwordMinimumLength = 8
        passwordRequiredType = 'alphanumeric'
        osMinimumVersion   = '10.0.18362'
        bitLockerEnabled   = $false
        storageRequireEncryption = $true
        scheduledActionsForRule = @(
            @{ ruleName = 'PasswordRequired'; scheduledActionConfigurations = @(@{ actionType = 'block'; gracePeriodHours = 0 }) }
        )
    } | ConvertTo-Json -Depth 10
    $oldWindowsPolicy = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies" -Method POST -Body $oldWindowsPolicyBody -ErrorAction Stop
    Write-Host "  Created old-style policy (ID: $($oldWindowsPolicy.id)), passwordRequired=true, bitLockerEnabled=false" -ForegroundColor Gray

    # Assign it too — an already-existing policy in a real tenant would have
    # been assigned when the script first created it. Without this, the
    # "reconcile settings but leave assignment alone" behaviour has nothing
    # to actually leave alone, and the assignment assertions below would
    # fail for a reason unrelated to what they're meant to test.
    $oldWindowsAssignTargets = @()
    foreach ($groupName in $ExpectedPolicyAssignments["${E2EPrefix}Windows 10/11 Basic Compliance"]) {
        $g = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue
        if ($g) { $oldWindowsAssignTargets += @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $g.Id } } }
    }
    if ($oldWindowsAssignTargets.Count -gt 0) {
        Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$($oldWindowsPolicy.id)')/assign" `
            -Method POST -Body (@{ assignments = $oldWindowsAssignTargets } | ConvertTo-Json -Depth 10) -ErrorAction Stop
        Write-Host "  Assigned old-style policy to $($oldWindowsAssignTargets.Count) group(s)" -ForegroundColor Gray
    }

    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running Compliance-Policies.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Intune/Compliance-Policies.ps1') `
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
    # Independently verify tenant state via Graph. Uses Invoke-MgGraphRequest
    # against the beta endpoint directly — the same approach the product
    # script uses, since the SDK cmdlets have a known assignment bug (see
    # CLAUDE.md's "Microsoft Graph SDK Bug" note)
    # ========================================================================
    Write-Host "`n== Verifying created policies in tenant ==" -ForegroundColor Cyan
    $allPolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies" -Method GET -ErrorAction Stop

    foreach ($policyName in $ExpectedPolicyAssignments.Keys) {
        $policy = $allPolicies.value | Where-Object { $_.displayName -eq $policyName }

        if (!$policy) {
            Write-Result $false "$policyName exists"
            continue
        }
        Write-Result $true "$policyName exists"

        $assignments = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$($policy.id)')/assignments" -Method GET -ErrorAction Stop
        $assignedGroupIds = @($assignments.value | ForEach-Object { $_.target.groupId })

        foreach ($groupName in $ExpectedPolicyAssignments[$policyName]) {
            $group = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue
            Write-Result ($group -and ($assignedGroupIds -contains $group.Id)) "$policyName is assigned to $groupName"
        }

        # Windows: confirm the script's PATCH-reconcile path actually
        # overwrote the old (pre-created above) fuller definition with the
        # trimmed BitLocker + minimum-OS-only settings, and left the
        # assignment (checked above) untouched in doing so.
        if ($policyName -eq "${E2EPrefix}Windows 10/11 Basic Compliance") {
            Write-Result ($policy.bitLockerEnabled -eq $true) "$policyName has bitLockerEnabled=true"
            Write-Result ([bool]$policy.osMinimumVersion) "$policyName has an osMinimumVersion set (actual: $($policy.osMinimumVersion))"
            Write-Result ($policy.passwordRequired -eq $false) "$policyName reconciled passwordRequired to false (was true pre-existing)"
            Write-Result ($policy.storageRequireEncryption -eq $false) "$policyName reconciled storageRequireEncryption to false (was true pre-existing)"
        }
    }

    # ========================================================================
    # Idempotency: a second run must skip everything and create nothing
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run skips all) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Intune/Compliance-Policies.ps1') `
        -NonInteractive -ConfigFile $PolicyConfigPath -ResultPath $PolicyResultPath

    $second = Get-Content $PolicyResultPath -Raw | ConvertFrom-Json -AsHashtable
    Write-Result ([bool]$second.Success -and @($second.Created).Count -eq 0 -and @($second.Skipped).Count -eq $ExpectedPolicyAssignments.Count) `
        "Second run created nothing and skipped all $($ExpectedPolicyAssignments.Count) policies"
}
finally {
    # ========================================================================
    # Cleanup — always runs; deletes ONLY prefix-matched objects
    # ========================================================================
    Write-Host "`n== Cleaning up E2E compliance policies ==" -ForegroundColor Cyan
    try {
        $allPolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies" -Method GET -ErrorAction Stop
        $e2ePolicies = @($allPolicies.value | Where-Object { $_.displayName -like "$E2EPrefix*" })
        foreach ($policy in $e2ePolicies) {
            try {
                $null = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$($policy.id)')" -Method DELETE -ErrorAction Stop
                Write-Host "  Deleted policy $($policy.displayName)" -ForegroundColor Gray
            }
            catch {
                Write-Host "  WARNING: could not delete policy $($policy.displayName): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        Write-Host "  Removed $($e2ePolicies.Count) polic(y/ies)" -ForegroundColor Green
    }
    catch {
        Write-Host "  WARNING: policy cleanup query failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Manually delete compliance policies prefixed '$E2EPrefix' in the test tenant" -ForegroundColor Yellow
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
