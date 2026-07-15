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
# Unique per-run prefix: Exchange Online Defender object reads are not
# monotonic across sessions — a rule deleted by the pre-clean (and confirmed
# gone by polling) was STILL returned to the script's own Get-*Rule seconds
# later (confirmed live), so no amount of test-side waiting makes a reused
# fixed name safe. A name that has never existed cannot produce stale reads.
# Fully-deleted leftovers from older runs are swept best-effort below.
$E2EPrefix  = "E2E-$([guid]::NewGuid().ToString('n').Substring(0, 6))-"
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

# Exchange Online Defender policy/rule reads are eventually consistent in
# BOTH directions (confirmed live across full-sweep runs): a just-created
# object can be invisible to Get-* for up to ~a minute, and a just-DELETED
# object can keep appearing — one run's Get-AntiPhishRule still returned a
# rule 6 seconds after the pre-clean deleted it, making the script skip rule
# creation entirely. Every existence decision therefore polls.
function Wait-ForDefenderObject {
    param([scriptblock]$Probe, [int]$MaxAttempts = 6, [int]$DelaySeconds = 10)
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $obj = & $Probe
        if ($obj) { return $obj }
        if ($attempt -lt $MaxAttempts) { Start-Sleep -Seconds $DelaySeconds }
    }
    return $null
}

function Wait-ForDefenderObjectGone {
    param([scriptblock]$Probe, [int]$MaxAttempts = 12, [int]$DelaySeconds = 10)
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        if (-not (& $Probe)) { return $true }
        if ($attempt -lt $MaxAttempts) { Start-Sleep -Seconds $DelaySeconds }
    }
    return $false
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

# Sweep stray E2E-* leftovers from previous runs' incomplete cleanups. This
# run's own names are unique, so strays can't break it — the sweep just
# keeps the test tenant tidy, best-effort.
Write-Host "`n== Sweeping stray E2E anti-phishing policies/rules ==" -ForegroundColor Cyan
try {
    foreach ($stray in @(Get-AntiPhishRule -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'E2E-*' })) {
        try { Remove-AntiPhishRule -Identity $stray.Name -Confirm:$false -ErrorAction Stop; Write-Host "  Removed stray rule $($stray.Name)" -ForegroundColor Gray }
        catch { Write-Host "  (stray rule $($stray.Name) not removable: $($_.Exception.Message))" -ForegroundColor Gray }
    }
    foreach ($stray in @(Get-AntiPhishPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'E2E-*' })) {
        try { Remove-AntiPhishPolicy -Identity $stray.Name -Confirm:$false -ErrorAction Stop; Write-Host "  Removed stray policy $($stray.Name)" -ForegroundColor Gray }
        catch { Write-Host "  (stray policy $($stray.Name) not removable: $($_.Exception.Message))" -ForegroundColor Gray }
    }
}
catch { Write-Host "  (stray sweep failed: $($_.Exception.Message))" -ForegroundColor Gray }

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
    $policy = Wait-ForDefenderObject { Get-AntiPhishPolicy -Identity $PolicyName -ErrorAction SilentlyContinue }
    Write-Result ([bool]$policy) "$PolicyName exists"
    if ($policy) {
        Write-Result ($policy.Enabled -eq $true) "$PolicyName is enabled"
        Write-Result ($policy.EnableMailboxIntelligence -eq $true) "$PolicyName has mailbox intelligence enabled"
        Write-Result ($policy.PhishThresholdLevel -eq 2) "$PolicyName has the expected phish threshold level"
    }

    $rule = Wait-ForDefenderObject { Get-AntiPhishRule -Identity $RuleName -ErrorAction SilentlyContinue }
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
    # Both the find and the delete need retries: an object created seconds
    # ago may not be visible yet (skipping it seeds a stray), and the delete
    # itself can land on a domain controller the object hasn't replicated to
    # ("couldn't be found on <DC>" for an object that demonstrably exists —
    # both confirmed live).
    $ruleDeleted = $false
    for ($cleanupAttempt = 1; $cleanupAttempt -le 4 -and -not $ruleDeleted; $cleanupAttempt++) {
        try {
            if (Wait-ForDefenderObject { Get-AntiPhishRule -Identity $RuleName -ErrorAction SilentlyContinue } -MaxAttempts 3) {
                Remove-AntiPhishRule -Identity $RuleName -Confirm:$false -ErrorAction Stop
                Write-Host "  Deleted rule $RuleName" -ForegroundColor Gray
            }
            $ruleDeleted = $true
        }
        catch {
            if ($cleanupAttempt -lt 4) { Write-Host "  Rule delete failed — retrying in 15s ($cleanupAttempt/4)..." -ForegroundColor Gray; Start-Sleep -Seconds 15 }
            else { Write-Host "  WARNING: could not delete rule $($RuleName): $($_.Exception.Message)" -ForegroundColor Yellow }
        }
    }
    $policyDeleted = $false
    for ($cleanupAttempt = 1; $cleanupAttempt -le 4 -and -not $policyDeleted; $cleanupAttempt++) {
        try {
            if (Get-AntiPhishPolicy -Identity $PolicyName -ErrorAction SilentlyContinue) {
                Remove-AntiPhishPolicy -Identity $PolicyName -Confirm:$false -ErrorAction Stop
                Write-Host "  Deleted policy $PolicyName" -ForegroundColor Gray
            }
            $policyDeleted = $true
        }
        catch {
            if ($cleanupAttempt -lt 4) { Write-Host "  Policy delete failed — retrying in 15s ($cleanupAttempt/4)..." -ForegroundColor Gray; Start-Sleep -Seconds 15 }
            else {
                Write-Host "  WARNING: could not delete policy $($PolicyName): $($_.Exception.Message)" -ForegroundColor Yellow
                Write-Host "  Manually delete the '$PolicyName' anti-phish policy in the test tenant" -ForegroundColor Yellow
            }
        }
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
