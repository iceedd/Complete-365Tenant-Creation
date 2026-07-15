#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs Exchange/Archive-Policies.ps1 unattended against
    the dedicated M365 test tenant, scoped to a single existing mailbox.
.DESCRIPTION
    Archive-Policies.ps1 operates on every UserMailbox-type mailbox in the
    tenant — there's no per-item config to point it at throwaway "E2E-"
    prefixed objects the way other scripts' E2E tests do. Instead, this test:
      1. Connects to Exchange Online with certificate-based app-only auth
      2. Finds one existing UserMailbox in the test tenant (the tenant's
         initial admin account always has one) and snapshots its current
         ArchiveStatus/quota settings so they can be restored afterwards
      3. Writes a throwaway config file with MailboxUPNs = @(that one UPN),
         so the real script only touches that single mailbox, not the whole
         tenant
      4. Runs Exchange/Archive-Policies.ps1 non-interactively — the real
         script, same file the menu calls
      5. Verifies via Get-Mailbox: archive is Active, and the three quotas
         match $QuotaConfig in the script
      6. Re-runs the script to prove idempotency (second run must report
         AlreadyEnabled/AlreadyConfigured, not Newly enabled/Updated)
      7. Restores the mailbox's original quota settings in a finally block,
         and disables the archive again if this test was the one that
         newly enabled it (never touches an archive that pre-dates the test)
.EXAMPLE
    ./Invoke-ArchivePoliciesE2E.ps1 -TenantId $env:M365_TENANT_ID -TenantDomain $env:M365_TENANT_DOMAIN -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
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

$RepoRoot = $PSScriptRoot | Split-Path | Split-Path

$APConfigPath = Join-Path ([IO.Path]::GetTempPath()) "ap-e2e-config-$([guid]::NewGuid().ToString('n')).json"
$ResultPath   = Join-Path ([IO.Path]::GetTempPath()) "ap-e2e-result-$([guid]::NewGuid().ToString('n')).json"

# The quotas Archive-Policies.ps1 applies (kept in sync with $QuotaConfig there)
$ExpectedWarningQuotaBytes             = 40GB
$ExpectedProhibitSendQuotaBytes        = 45GB
$ExpectedProhibitSendReceiveQuotaBytes = 49GB

$failures = 0
$originalMailboxState = $null
$newlyEnabledArchive = $false

function Write-Result {
    param([bool]$Pass, [string]$Message)
    if ($Pass) { Write-Host "  PASS  $Message" -ForegroundColor Green }
    else       { Write-Host "  FAIL  $Message" -ForegroundColor Red; $script:failures++ }
}

function Get-QuotaBytes {
    <#
    .SYNOPSIS
        Extracts a byte count from a mailbox quota value, regardless of which
        shape Get-Mailbox returned it in — mirrors Archive-Policies.ps1's own
        Get-QuotaByteCount.
    .DESCRIPTION
        Confirmed live: this tenant's ExchangeOnlineManagement backend returns
        quota values as plain strings like "40 GB (42,949,672,960 bytes)" or
        "Unlimited", not as rich objects with IsUnlimited/ToBytes() — hence the
        string-parsing branch below. The object-shape branch is kept for
        other ExchangeOnlineManagement backends that do return rich objects.
    #>
    param($Quota)
    if ($null -eq $Quota) { return $null }

    if ($Quota -is [string]) {
        if ($Quota -eq 'Unlimited') { return $null }
        if ($Quota -match '\(([\d,]+)\s*bytes\)') {
            return [long]($Matches[1] -replace ',', '')
        }
        return $null
    }

    # PSObject.Properties[] indexing never throws under strict mode when the
    # property is absent, unlike dot-notation.
    $isUnlimitedProp = $Quota.PSObject.Properties['IsUnlimited']
    if ($isUnlimitedProp -and $isUnlimitedProp.Value) { return $null }

    try { return $Quota.ToBytes() } catch { return $null }
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

try {
    # ========================================================================
    # Pick an existing UserMailbox to scope this test to
    # ========================================================================
    Write-Host "`n== Finding a UserMailbox to test against ==" -ForegroundColor Cyan
    $testMailbox = @(Get-Mailbox -RecipientTypeDetails UserMailbox -ResultSize 1 -ErrorAction Stop) | Select-Object -First 1
    if (!$testMailbox) {
        throw "No UserMailbox found in the test tenant — Archive-Policies.ps1 needs at least one licensed user mailbox to test against"
    }
    $testUpn = $testMailbox.UserPrincipalName
    Write-Host "  Using $testUpn" -ForegroundColor Gray

    $originalMailboxState = [pscustomobject]@{
        ArchiveStatus            = $testMailbox.ArchiveStatus
        UseDatabaseQuotaDefaults = $testMailbox.UseDatabaseQuotaDefaults
        IssueWarningQuota        = $testMailbox.IssueWarningQuota
        ProhibitSendQuota        = $testMailbox.ProhibitSendQuota
        ProhibitSendReceiveQuota = $testMailbox.ProhibitSendReceiveQuota
    }
    Write-Host "  Snapshotted original state (ArchiveStatus=$($originalMailboxState.ArchiveStatus), UseDatabaseQuotaDefaults=$($originalMailboxState.UseDatabaseQuotaDefaults))" -ForegroundColor Gray

    @{ MailboxUPNs = @($testUpn) } | ConvertTo-Json -Depth 5 | Set-Content -Path $APConfigPath -Encoding UTF8

    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running Archive-Policies.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Exchange/Archive-Policies.ps1') `
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
        Write-Result ([bool]$result.Success -and $result.MailboxCount -eq 1) "Script reported success and processed exactly 1 mailbox"
        Write-Result (($result.ArchiveStats.Failed -eq 0) -and ($result.QuotaStats.Failed -eq 0)) "No archive or quota failures reported"
        $newlyEnabledArchive = ($result.ArchiveStats.NewlyEnabled -eq 1)
    }

    # ========================================================================
    # Independently verify tenant state
    # ========================================================================
    Write-Host "`n== Verifying mailbox state in tenant ==" -ForegroundColor Cyan
    $verifyMailbox = Get-Mailbox -Identity $testUpn -ErrorAction Stop
    Write-Result ($verifyMailbox.ArchiveStatus -eq 'Active') "$testUpn archive is Active"
    Write-Result ((Get-QuotaBytes $verifyMailbox.IssueWarningQuota) -eq $ExpectedWarningQuotaBytes) "$testUpn has the expected warning quota"
    Write-Result ((Get-QuotaBytes $verifyMailbox.ProhibitSendQuota) -eq $ExpectedProhibitSendQuotaBytes) "$testUpn has the expected prohibit-send quota"
    Write-Result ((Get-QuotaBytes $verifyMailbox.ProhibitSendReceiveQuota) -eq $ExpectedProhibitSendReceiveQuotaBytes) "$testUpn has the expected prohibit-send-receive quota"

    # ========================================================================
    # Idempotency: a second run must report AlreadyEnabled/AlreadyConfigured
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run reports already-configured) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Exchange/Archive-Policies.ps1') `
        -NonInteractive -ConfigFile $APConfigPath -ResultPath $ResultPath

    $second = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
    Write-Result (
        [bool]$second.Success -and
        $second.ArchiveStats.AlreadyEnabled -eq 1 -and $second.ArchiveStats.NewlyEnabled -eq 0 -and
        $second.QuotaStats.AlreadyConfigured -eq 1 -and $second.QuotaStats.Updated -eq 0
    ) "Second run made no changes and reported already-configured for archive and quotas"
}
finally {
    # ========================================================================
    # Restore original mailbox state — always runs
    # ========================================================================
    Write-Host "`n== Restoring original mailbox state ==" -ForegroundColor Cyan
    if ($originalMailboxState) {
        try {
            if ($originalMailboxState.UseDatabaseQuotaDefaults) {
                Set-Mailbox -Identity $testUpn -UseDatabaseQuotaDefaults $true -ErrorAction Stop
                Write-Host "  Restored database-default quotas on $testUpn" -ForegroundColor Gray
            }
            else {
                Set-Mailbox -Identity $testUpn `
                    -IssueWarningQuota $originalMailboxState.IssueWarningQuota `
                    -ProhibitSendQuota $originalMailboxState.ProhibitSendQuota `
                    -ProhibitSendReceiveQuota $originalMailboxState.ProhibitSendReceiveQuota `
                    -UseDatabaseQuotaDefaults $false `
                    -ErrorAction Stop
                Write-Host "  Restored original explicit quotas on $testUpn" -ForegroundColor Gray
            }

            if ($newlyEnabledArchive -and $originalMailboxState.ArchiveStatus -ne 'Active') {
                Disable-Mailbox -Identity $testUpn -Archive -Confirm:$false -ErrorAction Stop
                Write-Host "  Disabled the archive this test newly enabled on $testUpn" -ForegroundColor Gray
            }
        }
        catch {
            Write-Host "  WARNING: could not fully restore $($testUpn): $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "  Manually verify quota/archive settings on '$testUpn' in the test tenant" -ForegroundColor Yellow
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
