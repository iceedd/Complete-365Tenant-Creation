#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs Exchange/Shared-MB-Creation.ps1 unattended against
    the dedicated M365 test tenant and verifies the shared mailbox it
    creates.
.DESCRIPTION
    Connects to Exchange Online with certificate-based app-only auth, then:
      1. Writes a throwaway config file describing one E2E- prefixed shared
         mailbox in the test tenant's own initial domain (always an
         accepted/authoritative domain, so no prior setup is needed)
      2. Runs Exchange/Shared-MB-Creation.ps1 non-interactively — the real
         script, same file the menu calls
      3. Verifies the mailbox exists via Get-Mailbox: correct
         RecipientTypeDetails, PrimarySmtpAddress, and the
         MessageCopyForSentAsEnabled/MessageCopyForSendOnBehalfEnabled
         settings the script configures
      4. Re-runs the script to prove idempotency (second run must skip the
         already-existing mailbox)
      5. Deletes the mailbox in a finally block that always runs, so cleanup
         happens even on failure

    Note: Exchange Online soft-deletes mailboxes for ~30 days after
    Remove-Mailbox, so a mailbox recreated immediately after a prior test's
    cleanup can in rare cases collide with its own soft-deleted predecessor.
    This is an inherent Exchange Online limitation, not a script bug.
.EXAMPLE
    ./Invoke-SharedMBCreationE2E.ps1 -TenantId $env:M365_TENANT_ID -TenantDomain $env:M365_TENANT_DOMAIN -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
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

$RepoRoot       = $PSScriptRoot | Split-Path | Split-Path
$E2EPrefix      = "e2e-sharedmb-"
$E2EEmail       = "${E2EPrefix}test@$TenantDomain"
$E2EDisplayName = "E2E Test Shared Mailbox"

$MBConfigPath = Join-Path ([IO.Path]::GetTempPath()) "smb-e2e-config-$([guid]::NewGuid().ToString('n')).json"
$ResultPath   = Join-Path ([IO.Path]::GetTempPath()) "smb-e2e-result-$([guid]::NewGuid().ToString('n')).json"

@{
    Mailboxes = @(
        @{
            EmailAddress = $E2EEmail
            DisplayName  = $E2EDisplayName
            Alias        = "${E2EPrefix}test"
            Description  = "Created by Invoke-SharedMBCreationE2E.ps1"
        }
    )
} | ConvertTo-Json -Depth 5 | Set-Content -Path $MBConfigPath -Encoding UTF8

$failures = 0

function Write-Result {
    param([bool]$Pass, [string]$Message)
    if ($Pass) { Write-Host "  PASS  $Message" -ForegroundColor Green }
    else       { Write-Host "  FAIL  $Message" -ForegroundColor Red; $script:failures++ }
}

function Wait-ForMailbox {
    <#
    .SYNOPSIS
        Polls Get-Mailbox with backoff — Exchange Online has a short
        directory-replication lag between mailbox creation and the object
        being consistently queryable.
    #>
    param([string]$Identity, [int]$MaxAttempts = 6, [int]$DelaySeconds = 10)

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $mbx = Get-Mailbox -Identity $Identity -ErrorAction SilentlyContinue
        if ($mbx) { return $mbx }
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

try {
    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running Shared-MB-Creation.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Exchange/Shared-MB-Creation.ps1') `
        -NonInteractive -ConfigFile $MBConfigPath -ResultPath $ResultPath

    # ========================================================================
    # Assert on the script's own reported results
    # ========================================================================
    Write-Host "`n== Verifying script results ==" -ForegroundColor Cyan
    if (!(Test-Path $ResultPath)) {
        Write-Result $false "Script produced no results file — it likely aborted early"
    }
    else {
        # Tolerate a stray mailbox surviving from a prior run whose cleanup
        # raced the same replication lag being fixed here — either Created
        # (normal case) or Skipped (already existed) is an acceptable outcome
        # as long as the script reported overall success.
        $result = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
        $handledThisEmail = (@($result.Created) -contains $E2EEmail) -or (@($result.Skipped) -contains $E2EEmail)
        Write-Result ([bool]$result.Success -and $handledThisEmail) "Script reported success and created/skipped $E2EEmail"
        foreach ($fail in @($result.Failed)) {
            Write-Host "        failed mailbox: $($fail.Name) — $($fail.Error)" -ForegroundColor Red
        }
    }

    # ========================================================================
    # Independently verify tenant state
    # ========================================================================
    Write-Host "`n== Verifying created mailbox in tenant ==" -ForegroundColor Cyan
    $mailbox = Wait-ForMailbox -Identity $E2EEmail
    Write-Result ([bool]$mailbox) "$E2EEmail exists"
    if ($mailbox) {
        Write-Result ($mailbox.RecipientTypeDetails -eq 'SharedMailbox') "$E2EEmail is a shared mailbox (RecipientTypeDetails: $($mailbox.RecipientTypeDetails))"
        Write-Result ($mailbox.PrimarySmtpAddress -eq $E2EEmail) "$E2EEmail has the correct primary SMTP address"
        Write-Result ($mailbox.MessageCopyForSentAsEnabled -eq $true) "$E2EEmail has MessageCopyForSentAsEnabled"
        Write-Result ($mailbox.MessageCopyForSendOnBehalfEnabled -eq $true) "$E2EEmail has MessageCopyForSendOnBehalfEnabled"
    }

    # ========================================================================
    # Idempotency: a second run must skip the already-existing mailbox
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run skips) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Exchange/Shared-MB-Creation.ps1') `
        -NonInteractive -ConfigFile $MBConfigPath -ResultPath $ResultPath

    $second = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
    Write-Result ([bool]$second.Success -and @($second.Created).Count -eq 0 -and (@($second.Skipped) -contains $E2EEmail)) `
        "Second run created nothing and skipped the already-existing mailbox"
}
finally {
    # ========================================================================
    # Cleanup — always runs
    # ========================================================================
    Write-Host "`n== Cleaning up E2E shared mailbox ==" -ForegroundColor Cyan
    try {
        if (Wait-ForMailbox -Identity $E2EEmail -MaxAttempts 3 -DelaySeconds 10) {
            Remove-Mailbox -Identity $E2EEmail -Confirm:$false -ErrorAction Stop
            Write-Host "  Deleted mailbox $E2EEmail" -ForegroundColor Gray
        }
        else {
            Write-Host "  No mailbox to delete" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  WARNING: could not delete mailbox $($E2EEmail): $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Manually delete the '$E2EEmail' shared mailbox in the test tenant" -ForegroundColor Yellow
    }

    Remove-Item $MBConfigPath, $ResultPath -ErrorAction SilentlyContinue
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
