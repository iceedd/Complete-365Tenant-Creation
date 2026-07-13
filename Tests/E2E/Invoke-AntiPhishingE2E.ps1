#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs Security/Anti-Phishing.ps1 unattended against the
    dedicated M365 test tenant and verifies the policy/rule it creates.
.DESCRIPTION
    Connects to Exchange Online with certificate-based app-only auth, then:
      1. Writes a throwaway config file with NamePrefix = "E2E-", so the real
         script creates/verifies/deletes a throwaway prefixed policy and rule
         instead of the tenant's real default anti-phishing policy
      2. Runs Security/Anti-Phishing.ps1 non-interactively — the real script,
         same file the menu calls
      3. Verifies the policy and rule exist via Get-AntiPhishPolicy /
         Get-AntiPhishRule with the expected settings
      4. Re-runs the script to prove idempotency (second run must update the
         existing policy and skip rule creation, not create duplicates)
      5. Deletes the rule and policy in a finally block that always runs, so
         cleanup happens even on failure
.EXAMPLE
    ./Invoke-AntiPhishingE2E.ps1 -TenantId $env:M365_TENANT_ID -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
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
$PolicyName = "${E2EPrefix}Default Anti-Phishing Policy"
$RuleName   = "${E2EPrefix}Default Anti-Phishing Rule"

$APConfigPath = Join-Path ([IO.Path]::GetTempPath()) "antiphish-e2e-config-$([guid]::NewGuid().ToString('n')).json"
$ResultPath   = Join-Path ([IO.Path]::GetTempPath()) "antiphish-e2e-result-$([guid]::NewGuid().ToString('n')).json"

@{ NamePrefix = $E2EPrefix } | ConvertTo-Json -Depth 5 | Set-Content -Path $APConfigPath -Encoding UTF8

$failures = 0

function Write-Result {
    param([bool]$Pass, [string]$Message)
    if ($Pass) { Write-Host "  PASS  $Message" -ForegroundColor Green }
    else       { Write-Host "  FAIL  $Message" -ForegroundColor Red; $script:failures++ }
}

function Wait-ForAntiPhishRule {
    <#
    .SYNOPSIS
        Polls Get-AntiPhishRule with backoff — Exchange Online has a short
        directory-replication lag between rule creation and the object being
        consistently queryable (confirmed live: New-AntiPhishRule can
        immediately-afterwards report "already has rule ... associated with
        it" while Get-AntiPhishRule still returns nothing for that rule).
    #>
    param([string]$Identity, [int]$MaxAttempts = 6, [int]$DelaySeconds = 10)

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $rule = Get-AntiPhishRule -Identity $Identity -ErrorAction SilentlyContinue
        if ($rule) { return $rule }
        if ($attempt -lt $MaxAttempts) { Start-Sleep -Seconds $DelaySeconds }
    }
    return $null
}

# ============================================================================
# Connect
# ============================================================================
Write-Host "`n== Connecting to test tenant Exchange Online (app-only) ==" -ForegroundColor Cyan
Connect-ExchangeOnline -AppId $AppId -CertificateThumbprint $CertificateThumbprint `
    -Organization $TenantDomain -ShowBanner:$false -ErrorAction Stop
$conn = Get-ConnectionInformation
if (!$conn -or $conn.State -ne 'Connected') { throw "Expected Connected state, got $($conn.State)" }
Write-Host "  Connected to $($conn.Organization)" -ForegroundColor Green

# Pre-clean any stray leftovers from a previous run's incomplete cleanup, so
# this run's "created a new policy and rule" assertion is reliable.
Write-Host "`n== Pre-cleaning any stray E2E policy/rule ==" -ForegroundColor Cyan
try {
    if (Get-AntiPhishRule -Identity $RuleName -ErrorAction SilentlyContinue) {
        Remove-AntiPhishRule -Identity $RuleName -Confirm:$false -ErrorAction Stop
        Write-Host "  Removed stray rule $RuleName" -ForegroundColor Gray
    }
}
catch { Write-Host "  (no stray rule to remove, or removal failed: $($_.Exception.Message))" -ForegroundColor Gray }
try {
    if (Get-AntiPhishPolicy -Identity $PolicyName -ErrorAction SilentlyContinue) {
        Remove-AntiPhishPolicy -Identity $PolicyName -Confirm:$false -ErrorAction Stop
        Write-Host "  Removed stray policy $PolicyName" -ForegroundColor Gray
    }
}
catch { Write-Host "  (no stray policy to remove, or removal failed: $($_.Exception.Message))" -ForegroundColor Gray }

try {
    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running Anti-Phishing.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Security/Anti-Phishing.ps1') `
        -NonInteractive -ConfigFile $APConfigPath -ResultPath $ResultPath

    # ========================================================================
    # Assert on the script's own reported results
    # ========================================================================
    Write-Host "`n== Verifying script results ==" -ForegroundColor Cyan
    if (!(Test-Path $ResultPath)) {
        Write-Result $false "Script produced no results file — it likely aborted early"
    }
    else {
        $result = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
        Write-Result ([bool]$result.Success -and $result.PolicyAction -eq 'Created' -and $result.RuleAction -eq 'Created') `
            "Script reported success and created a new policy and rule"
    }

    # ========================================================================
    # Independently verify tenant state
    # ========================================================================
    Write-Host "`n== Verifying policy/rule in tenant ==" -ForegroundColor Cyan
    $policy = Get-AntiPhishPolicy -Identity $PolicyName -ErrorAction SilentlyContinue
    Write-Result ([bool]$policy) "$PolicyName exists"
    if ($policy) {
        Write-Result ($policy.Enabled -eq $true) "$PolicyName is enabled"
        Write-Result ($policy.EnableMailboxIntelligence -eq $true) "$PolicyName has mailbox intelligence enabled"
        Write-Result ($policy.PhishThresholdLevel -eq 2) "$PolicyName has the expected phish threshold level"
    }

    $rule = Wait-ForAntiPhishRule -Identity $RuleName
    Write-Result ([bool]$rule) "$RuleName exists"
    if ($rule) {
        Write-Result ($rule.AntiPhishPolicy -eq $PolicyName) "$RuleName is linked to $PolicyName"
        Write-Result ($rule.State -eq 'Enabled') "$RuleName is enabled"
    }

    # ========================================================================
    # Idempotency: a second run must update the policy, not duplicate it,
    # and must skip rule creation since one already exists
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run updates, doesn't duplicate) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Security/Anti-Phishing.ps1') `
        -NonInteractive -ConfigFile $APConfigPath -ResultPath $ResultPath

    $second = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
    Write-Result ([bool]$second.Success -and $second.PolicyAction -eq 'Updated' -and $second.RuleAction -eq 'Skipped') `
        "Second run updated the existing policy and skipped rule creation"
}
finally {
    # ========================================================================
    # Cleanup — always runs
    # ========================================================================
    Write-Host "`n== Cleaning up E2E anti-phishing policy/rule ==" -ForegroundColor Cyan
    try {
        if (Get-AntiPhishRule -Identity $RuleName -ErrorAction SilentlyContinue) {
            Remove-AntiPhishRule -Identity $RuleName -Confirm:$false -ErrorAction Stop
            Write-Host "  Deleted rule $RuleName" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  WARNING: could not delete rule $($RuleName): $($_.Exception.Message)" -ForegroundColor Yellow
    }
    try {
        if (Get-AntiPhishPolicy -Identity $PolicyName -ErrorAction SilentlyContinue) {
            Remove-AntiPhishPolicy -Identity $PolicyName -Confirm:$false -ErrorAction Stop
            Write-Host "  Deleted policy $PolicyName" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  WARNING: could not delete policy $($PolicyName): $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Manually delete the '$PolicyName' anti-phish policy in the test tenant" -ForegroundColor Yellow
    }

    Remove-Item $APConfigPath, $ResultPath -ErrorAction SilentlyContinue
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
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
