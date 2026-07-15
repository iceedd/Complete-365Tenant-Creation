#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs Security/Safe-Attachments.ps1 unattended against
    the dedicated M365 test tenant and verifies the Safe Attachments and
    Safe Links policies/rules it creates.
.DESCRIPTION
    Connects to Exchange Online with certificate-based app-only auth, then:
      1. Pre-cleans any stray "E2E-" prefixed policies/rules left over from
         a previous run's incomplete cleanup
      2. Writes a throwaway config file with NamePrefix = "E2E-", so the real
         script creates/verifies/deletes throwaway prefixed policies and
         rules instead of the tenant's real default policies
      3. Runs Security/Safe-Attachments.ps1 non-interactively — the real
         script, same file the menu calls
      4. Verifies both policies and rules exist with the expected settings
      5. Re-runs the script to prove idempotency (second run must update the
         existing policies and skip rule creation, not duplicate anything)
      6. Deletes both rules and policies in a finally block that always
         runs, so cleanup happens even on failure
.EXAMPLE
    ./Invoke-SafeAttachmentsE2E.ps1 -TenantId $env:M365_TENANT_ID -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
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

$RepoRoot  = $PSScriptRoot | Split-Path | Split-Path
$E2EPrefix = "E2E-"

$SAPolicyName = "${E2EPrefix}Default Safe Attachments Policy"
$SARuleName   = "${E2EPrefix}Default Safe Attachments Rule"
$SLPolicyName = "${E2EPrefix}Default Safe Links Policy"
$SLRuleName   = "${E2EPrefix}Default Safe Links Rule"

$SAConfigPath = Join-Path ([IO.Path]::GetTempPath()) "safeattach-e2e-config-$([guid]::NewGuid().ToString('n')).json"
$ResultPath   = Join-Path ([IO.Path]::GetTempPath()) "safeattach-e2e-result-$([guid]::NewGuid().ToString('n')).json"

@{ NamePrefix = $E2EPrefix } | ConvertTo-Json -Depth 5 | Set-Content -Path $SAConfigPath -Encoding UTF8

$failures = 0

function Write-Result {
    param([bool]$Pass, [string]$Message)
    if ($Pass) { Write-Host "  PASS  $Message" -ForegroundColor Green }
    else       { Write-Host "  FAIL  $Message" -ForegroundColor Red; $script:failures++ }
}

function Wait-ForRule {
    <#
    .SYNOPSIS
        Polls a Get-*Rule cmdlet with backoff — Exchange Online has a short
        directory-replication lag between rule creation and the object being
        consistently queryable (confirmed live in Anti-Phishing.ps1's E2E
        test — New-*Rule can report "already has rule ... associated" right
        after a successful creation while Get-*Rule still returns nothing).
    #>
    param([scriptblock]$GetRule, [int]$MaxAttempts = 6, [int]$DelaySeconds = 10)

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $rule = & $GetRule
        if ($rule) { return $rule }
        if ($attempt -lt $MaxAttempts) { Start-Sleep -Seconds $DelaySeconds }
    }
    return $null
}

function Wait-ForObjectGone {
    <#
    .SYNOPSIS
        Polls until a Get-* probe stops returning an object — Defender
        deletions are also eventually consistent (confirmed live in the
        Anti-Phishing E2E: Get-AntiPhishRule still returned a rule 6 seconds
        after it was deleted, making the script under test skip creation).
    #>
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

# Pre-clean any stray leftovers from a previous run's incomplete cleanup, so
# this run's "created a new policy and rule" assertions are reliable.
Write-Host "`n== Pre-cleaning any stray E2E policies/rules ==" -ForegroundColor Cyan
foreach ($cleanup in @(
    @{ Get = { Get-SafeAttachmentRule -Identity $SARuleName -ErrorAction SilentlyContinue }; Remove = { Remove-SafeAttachmentRule -Identity $SARuleName -Confirm:$false -ErrorAction Stop }; Name = $SARuleName }
    @{ Get = { Get-SafeAttachmentPolicy -Identity $SAPolicyName -ErrorAction SilentlyContinue }; Remove = { Remove-SafeAttachmentPolicy -Identity $SAPolicyName -Confirm:$false -ErrorAction Stop }; Name = $SAPolicyName }
    @{ Get = { Get-SafeLinksRule -Identity $SLRuleName -ErrorAction SilentlyContinue }; Remove = { Remove-SafeLinksRule -Identity $SLRuleName -Confirm:$false -ErrorAction Stop }; Name = $SLRuleName }
    @{ Get = { Get-SafeLinksPolicy -Identity $SLPolicyName -ErrorAction SilentlyContinue }; Remove = { Remove-SafeLinksPolicy -Identity $SLPolicyName -Confirm:$false -ErrorAction Stop }; Name = $SLPolicyName }
)) {
    try {
        if (& $cleanup.Get) {
            & $cleanup.Remove
            Write-Host "  Removed stray $($cleanup.Name)" -ForegroundColor Gray
            if (!(Wait-ForObjectGone -Probe $cleanup.Get)) {
                Write-Host "  WARNING: deleted $($cleanup.Name) still visible after wait — run may misbehave" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  (no stray $($cleanup.Name) to remove, or removal failed: $($_.Exception.Message))" -ForegroundColor Gray }
}

try {
    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running Safe-Attachments.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Security/Safe-Attachments.ps1') `
        -NonInteractive -ConfigFile $SAConfigPath -ResultPath $ResultPath

    # ========================================================================
    # Assert on the script's own reported results
    # ========================================================================
    Write-Host "`n== Verifying script results ==" -ForegroundColor Cyan
    if (!(Test-Path $ResultPath)) {
        Write-Result $false "Script produced no results file — it likely aborted early"
    }
    else {
        $result = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
        Write-Result ([bool]$result.Success) "Script reported overall success"
        # Guard on .Success first (short-circuits -and) — the failure-path
        # result hashtable has no PolicyAction/RuleAction keys, so accessing
        # them unconditionally throws under strict mode (confirmed live).
        Write-Result ([bool]$result.SafeAttachments.Success -and $result.SafeAttachments.PolicyAction -eq 'Created' -and $result.SafeAttachments.RuleAction -eq 'Created') `
            "Safe Attachments: created a new policy and rule"
        Write-Result ([bool]$result.SafeLinks.Success -and $result.SafeLinks.PolicyAction -eq 'Created' -and $result.SafeLinks.RuleAction -eq 'Created') `
            "Safe Links: created a new policy and rule"
    }

    # ========================================================================
    # Independently verify tenant state
    # ========================================================================
    Write-Host "`n== Verifying Safe Attachments policy/rule in tenant ==" -ForegroundColor Cyan
    $saPolicy = Wait-ForRule -GetRule { Get-SafeAttachmentPolicy -Identity $SAPolicyName -ErrorAction SilentlyContinue }
    Write-Result ([bool]$saPolicy) "$SAPolicyName exists"
    if ($saPolicy) {
        Write-Result ($saPolicy.Enable -eq $true) "$SAPolicyName is enabled"
        Write-Result ($saPolicy.Action -eq 'DynamicDelivery') "$SAPolicyName uses DynamicDelivery"
    }
    $saRule = Wait-ForRule -GetRule { Get-SafeAttachmentRule -Identity $SARuleName -ErrorAction SilentlyContinue }
    Write-Result ([bool]$saRule) "$SARuleName exists"
    if ($saRule) {
        Write-Result ($saRule.SafeAttachmentPolicy -eq $SAPolicyName) "$SARuleName is linked to $SAPolicyName"
    }

    Write-Host "`n== Verifying Safe Links policy/rule in tenant ==" -ForegroundColor Cyan
    $slPolicy = Wait-ForRule -GetRule { Get-SafeLinksPolicy -Identity $SLPolicyName -ErrorAction SilentlyContinue }
    Write-Result ([bool]$slPolicy) "$SLPolicyName exists"
    if ($slPolicy) {
        # Safe Links policies have no top-level enabled toggle (confirmed
        # live — Set-SafeLinksPolicy has no IsEnabled parameter); check a
        # setting the script actually configures instead.
        Write-Result ($slPolicy.EnableSafeLinksForEmail -eq $true) "$SLPolicyName has Safe Links for email enabled"
        Write-Result ($slPolicy.ScanUrls -eq $true) "$SLPolicyName scans URLs"
    }
    $slRule = Wait-ForRule -GetRule { Get-SafeLinksRule -Identity $SLRuleName -ErrorAction SilentlyContinue }
    Write-Result ([bool]$slRule) "$SLRuleName exists"
    if ($slRule) {
        Write-Result ($slRule.SafeLinksPolicy -eq $SLPolicyName) "$SLRuleName is linked to $SLPolicyName"
    }

    # ========================================================================
    # Idempotency: a second run must update the policies, not duplicate them,
    # and must skip rule creation since they already exist
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run updates, doesn't duplicate) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Security/Safe-Attachments.ps1') `
        -NonInteractive -ConfigFile $SAConfigPath -ResultPath $ResultPath

    $second = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
    Write-Result (
        [bool]$second.Success -and
        $second.SafeAttachments.PolicyAction -eq 'Updated' -and $second.SafeAttachments.RuleAction -eq 'Skipped' -and
        $second.SafeLinks.PolicyAction -eq 'Updated' -and $second.SafeLinks.RuleAction -eq 'Skipped'
    ) "Second run updated both existing policies and skipped rule creation"
}
finally {
    # ========================================================================
    # Cleanup — always runs
    # ========================================================================
    Write-Host "`n== Cleaning up E2E Safe Attachments/Links policies and rules ==" -ForegroundColor Cyan
    foreach ($cleanup in @(
        @{ Get = { Get-SafeAttachmentRule -Identity $SARuleName -ErrorAction SilentlyContinue }; Remove = { Remove-SafeAttachmentRule -Identity $SARuleName -Confirm:$false -ErrorAction Stop }; Name = $SARuleName }
        @{ Get = { Get-SafeAttachmentPolicy -Identity $SAPolicyName -ErrorAction SilentlyContinue }; Remove = { Remove-SafeAttachmentPolicy -Identity $SAPolicyName -Confirm:$false -ErrorAction Stop }; Name = $SAPolicyName }
        @{ Get = { Get-SafeLinksRule -Identity $SLRuleName -ErrorAction SilentlyContinue }; Remove = { Remove-SafeLinksRule -Identity $SLRuleName -Confirm:$false -ErrorAction Stop }; Name = $SLRuleName }
        @{ Get = { Get-SafeLinksPolicy -Identity $SLPolicyName -ErrorAction SilentlyContinue }; Remove = { Remove-SafeLinksPolicy -Identity $SLPolicyName -Confirm:$false -ErrorAction Stop }; Name = $SLPolicyName }
    )) {
        try {
            # Poll before concluding there's nothing to delete — an object
            # created seconds ago by the second run may not be visible yet,
            # and skipping it here seeds the next run's stray.
            if (Wait-ForRule -GetRule $cleanup.Get) {
                & $cleanup.Remove
                Write-Host "  Deleted $($cleanup.Name)" -ForegroundColor Gray
            }
        }
        catch {
            Write-Host "  WARNING: could not delete $($cleanup.Name): $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "  Manually delete '$($cleanup.Name)' in the test tenant" -ForegroundColor Yellow
        }
    }

    Remove-Item $SAConfigPath, $ResultPath -ErrorAction SilentlyContinue
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
