#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs Purview/Retention-Policies.ps1 unattended against
    the dedicated M365 test tenant and verifies the retention policy/rule it
    creates.
.DESCRIPTION
    Connects to both Microsoft Graph and Security & Compliance (IPPS) with
    certificate-based app-only auth — the real script's Connect-SecurityCompliance
    probes for an already-active IPPS session before attempting its own
    (parameterless, interactive-only) Connect-IPPSSession call, so this test
    establishes that session itself first. Then:
      1. Writes a throwaway config file with NamePrefix = "E2E-", so the real
         script creates/verifies/deletes a throwaway prefixed policy and rule
         instead of the tenant's real default policy
      2. Runs Purview/Retention-Policies.ps1 non-interactively — the real
         script, same file the menu calls
      3. Verifies the policy and rule exist via Get-RetentionCompliancePolicy /
         Get-RetentionComplianceRule with the expected settings
      4. Re-runs the script to prove idempotency (second run must skip the
         already-existing policy, not create a duplicate)
      5. Deletes the rule and policy in a finally block that always runs, so
         cleanup happens even on failure
.EXAMPLE
    ./Invoke-RetentionPoliciesE2E.ps1 -TenantId $env:M365_TENANT_ID -TenantDomain $env:M365_TENANT_DOMAIN -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $TenantId,
    [Parameter(Mandatory)] [string] $TenantDomain,
    [Parameter(Mandatory)] [string] $AppId,
    [Parameter(Mandatory)] [string] $CertificateThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot   = $PSScriptRoot | Split-Path | Split-Path
$E2EPrefix  = "E2E-"
$PolicyName = "${E2EPrefix}7 Year Archive"
$RuleName   = "${E2EPrefix}7 Year Archive Rule"

$RPConfigPath = Join-Path ([IO.Path]::GetTempPath()) "retention-e2e-config-$([guid]::NewGuid().ToString('n')).json"
$ResultPath   = Join-Path ([IO.Path]::GetTempPath()) "retention-e2e-result-$([guid]::NewGuid().ToString('n')).json"

@{ NamePrefix = $E2EPrefix } | ConvertTo-Json -Depth 5 | Set-Content -Path $RPConfigPath -Encoding UTF8

$failures = 0

function Write-Result {
    param([bool]$Pass, [string]$Message)
    if ($Pass) { Write-Host "  PASS  $Message" -ForegroundColor Green }
    else       { Write-Host "  FAIL  $Message" -ForegroundColor Red; $script:failures++ }
}

function Wait-ForRetentionRule {
    <#
    .SYNOPSIS
        Polls Get-RetentionComplianceRule with backoff — matches the
        Exchange Online / Security & Compliance replication lag confirmed
        elsewhere in this repo's E2E tests (e.g. Anti-Phishing, Shared-MB).
    #>
    param([string]$Identity, [int]$MaxAttempts = 6, [int]$DelaySeconds = 10)

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $rule = Get-RetentionComplianceRule -Identity $Identity -ErrorAction SilentlyContinue
        if ($rule) { return $rule }
        if ($attempt -lt $MaxAttempts) { Start-Sleep -Seconds $DelaySeconds }
    }
    return $null
}

# ============================================================================
# Connect — both Graph (for the script's own prerequisite check) and IPPS
# (Security & Compliance) so Connect-SecurityCompliance's probe finds an
# already-active session instead of attempting its own interactive-only call.
# ============================================================================
Write-Host "`n== Connecting to test tenant (Security & Compliance + Graph, app-only) ==" -ForegroundColor Cyan

# Connect Graph first (known-working) to check the app's Entra directory role
# assignments before attempting IPPS. Per Microsoft's own app-only-auth docs
# (learn.microsoft.com/powershell/exchange/app-only-auth-powershell-v2), the
# roles that grant Exchange Online PowerShell access (Exchange Administrator,
# Exchange Recipient Administrator, Helpdesk Administrator) are NOT the same
# set that grant Security & Compliance PowerShell access (Compliance
# Administrator, Security Administrator, Security Reader, Global Reader,
# Global Administrator). If this app only has an EXO-only role, Connect-EXO
# works but Connect-IPPSSession fails — plausibly explaining the "Object
# reference not set" crash inside NewEXOModule.ProcessRecord() seen on every
# prior attempt (token acquisition always succeeded; only RBAC/session-module
# construction failed).
Connect-MgGraph -ClientId $AppId -TenantId $TenantId `
    -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
$ctx = Get-MgContext
if (!$ctx) { throw "Failed to establish Graph context" }
Write-Host "  Connected to Graph tenant $($ctx.TenantId)" -ForegroundColor Green

Write-Host "`n== DEBUG: checking this app's Entra directory role assignments ==" -ForegroundColor Magenta
try {
    $sp = Get-MgServicePrincipal -Filter "appId eq '$AppId'" -ErrorAction Stop
    Write-Host "DEBUG Service principal object ID: $($sp.Id)" -ForegroundColor Magenta
    $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($sp.Id)'" -ExpandProperty "roleDefinition" -ErrorAction Stop
    if (@($roleAssignments).Count -eq 0) {
        Write-Host "DEBUG No Entra directory role assignments found for this service principal at all" -ForegroundColor Magenta
    }
    else {
        foreach ($ra in $roleAssignments) {
            Write-Host "DEBUG Role assigned: $($ra.RoleDefinition.DisplayName)" -ForegroundColor Magenta
        }
    }
}
catch {
    Write-Host "DEBUG Could not query role assignments: $($_.Exception.Message)" -ForegroundColor Magenta
}

# -DisableWAM is for the interactive WAM/RuntimeBroker conflict between a
# delegated Connect-MgGraph and Connect-IPPSSession in the same session (see
# CLAUDE.md) — it doesn't apply to app-only certificate auth, where WAM (an
# interactive Windows Account Manager broker) never enters the picture at
# all. Confirmed live: adding -DisableWAM to this app-only call itself threw
# "Object reference not set to an instance of an object" on the very first
# connection attempt, before Graph was even touched. Microsoft's own
# documented example for unattended cert-based Connect-IPPSSession omits it.
try {
    Connect-IPPSSession -AppId $AppId -CertificateThumbprint $CertificateThumbprint `
        -Organization $TenantDomain -ErrorAction Stop -ShowBanner:$false
}
catch {
    Write-Host "DEBUG Exception message: $($_.Exception.Message)" -ForegroundColor Magenta
    Write-Host "DEBUG ScriptStackTrace: $($_.ScriptStackTrace)" -ForegroundColor Magenta
    throw
}
$null = Get-RetentionCompliancePolicy -ResultSize 1 -ErrorAction Stop
Write-Host "  Connected to Security & Compliance Center" -ForegroundColor Green

# Pre-clean any stray leftovers from a previous run's incomplete cleanup.
Write-Host "`n== Pre-cleaning any stray E2E policy/rule ==" -ForegroundColor Cyan
try {
    if (Get-RetentionComplianceRule -Identity $RuleName -ErrorAction SilentlyContinue) {
        Remove-RetentionComplianceRule -Identity $RuleName -Confirm:$false -ErrorAction Stop
        Write-Host "  Removed stray rule $RuleName" -ForegroundColor Gray
    }
}
catch { Write-Host "  (no stray rule to remove, or removal failed: $($_.Exception.Message))" -ForegroundColor Gray }
try {
    if (Get-RetentionCompliancePolicy -Identity $PolicyName -ErrorAction SilentlyContinue) {
        Remove-RetentionCompliancePolicy -Identity $PolicyName -Confirm:$false -ErrorAction Stop
        Write-Host "  Removed stray policy $PolicyName" -ForegroundColor Gray
    }
}
catch { Write-Host "  (no stray policy to remove, or removal failed: $($_.Exception.Message))" -ForegroundColor Gray }

try {
    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running Retention-Policies.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Purview/Retention-Policies.ps1') `
        -NonInteractive -ConfigFile $RPConfigPath -ResultPath $ResultPath

    # ========================================================================
    # Assert on the script's own reported results
    # ========================================================================
    Write-Host "`n== Verifying script results ==" -ForegroundColor Cyan
    if (!(Test-Path $ResultPath)) {
        Write-Result $false "Script produced no results file — it likely aborted early"
    }
    else {
        $result = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
        Write-Result ([bool]$result.Success -and (@($result.Created) -contains $PolicyName)) `
            "Script reported success and created $PolicyName"
        foreach ($fail in @($result.Failed)) {
            Write-Host "        failed policy: $($fail.Name) — $($fail.Error)" -ForegroundColor Red
        }
    }

    # ========================================================================
    # Independently verify tenant state
    # ========================================================================
    Write-Host "`n== Verifying created retention policy/rule in tenant ==" -ForegroundColor Cyan
    $policy = Get-RetentionCompliancePolicy -Identity $PolicyName -ErrorAction SilentlyContinue
    Write-Result ([bool]$policy) "$PolicyName exists"
    if ($policy) {
        Write-Result ($policy.Enabled -eq $true) "$PolicyName is enabled"
    }

    $rule = Wait-ForRetentionRule -Identity $RuleName
    Write-Result ([bool]$rule) "$RuleName exists"
    if ($rule) {
        Write-Result ($rule.RetentionDuration -eq 2555) "$RuleName has the expected retention duration (2555 days)"
        Write-Result ($rule.RetentionComplianceAction -eq 'Keep') "$RuleName has the expected retention action (Keep)"
    }

    # ========================================================================
    # Idempotency: a second run must skip the already-existing policy
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run skips) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Purview/Retention-Policies.ps1') `
        -NonInteractive -ConfigFile $RPConfigPath -ResultPath $ResultPath

    $second = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
    Write-Result ([bool]$second.Success -and @($second.Created).Count -eq 0 -and (@($second.Skipped) -contains $PolicyName)) `
        "Second run created nothing and skipped the already-existing policy"
}
finally {
    # ========================================================================
    # Cleanup — always runs
    # ========================================================================
    Write-Host "`n== Cleaning up E2E retention policy/rule ==" -ForegroundColor Cyan
    try {
        if (Get-RetentionComplianceRule -Identity $RuleName -ErrorAction SilentlyContinue) {
            Remove-RetentionComplianceRule -Identity $RuleName -Confirm:$false -ErrorAction Stop
            Write-Host "  Deleted rule $RuleName" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  WARNING: could not delete rule $($RuleName): $($_.Exception.Message)" -ForegroundColor Yellow
    }
    try {
        if (Get-RetentionCompliancePolicy -Identity $PolicyName -ErrorAction SilentlyContinue) {
            Remove-RetentionCompliancePolicy -Identity $PolicyName -Confirm:$false -ErrorAction Stop
            Write-Host "  Deleted policy $PolicyName" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  WARNING: could not delete policy $($PolicyName): $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Manually delete the '$PolicyName' retention policy in the test tenant" -ForegroundColor Yellow
    }

    Remove-Item $RPConfigPath, $ResultPath -ErrorAction SilentlyContinue
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
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
