#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs Exchange/Distribution-Lists.ps1 unattended against
    the dedicated M365 test tenant and verifies the distribution list it
    creates.
.DESCRIPTION
    Connects to Exchange Online with certificate-based app-only auth, then:
      1. Writes a throwaway config file describing one E2E- prefixed
         distribution list in the test tenant's own initial domain (always
         accepted, so no prior setup is needed)
      2. Runs Exchange/Distribution-Lists.ps1 non-interactively — the real
         script, same file the menu calls
      3. Verifies the group exists via Get-DistributionGroup: correct
         RecipientTypeDetails (MailUniversalDistributionGroup, i.e. a
         classic distribution list, not a security group), and the
         expected primary SMTP address
      4. Re-runs the script to prove idempotency (second run must skip the
         already-existing list)
      5. Deletes the group in a finally block that always runs, so cleanup
         happens even on failure

    Note: this script was rewritten (v3.0) from a Microsoft Graph-based
    approach to Exchange Online cmdlets after a live E2E run proved the
    Graph approach could never work — Microsoft Graph's groups API is
    read-only for distribution groups. See Distribution-Lists.ps1's version
    history for detail.
.EXAMPLE
    ./Invoke-DistributionListsE2E.ps1 -TenantId $env:M365_TENANT_ID -TenantDomain $env:M365_TENANT_DOMAIN -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
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

$RepoRoot        = $PSScriptRoot | Split-Path | Split-Path
$E2EPrefix       = "e2e-dl-"
$E2EMailNickname = "${E2EPrefix}test"
$E2EEmail        = "$E2EMailNickname@$TenantDomain"
$E2EDisplayName  = "E2E Test Distribution List"

$DLConfigPath = Join-Path ([IO.Path]::GetTempPath()) "dl-e2e-config-$([guid]::NewGuid().ToString('n')).json"
$ResultPath   = Join-Path ([IO.Path]::GetTempPath()) "dl-e2e-result-$([guid]::NewGuid().ToString('n')).json"

@{
    DistributionLists = @(
        @{
            DisplayName  = $E2EDisplayName
            PrimaryEmail = $E2EEmail
            MailNickname = $E2EMailNickname
            Description  = "Created by Invoke-DistributionListsE2E.ps1"
        }
    )
} | ConvertTo-Json -Depth 5 | Set-Content -Path $DLConfigPath -Encoding UTF8

$failures = 0

function Write-Result {
    param([bool]$Pass, [string]$Message)
    if ($Pass) { Write-Host "  PASS  $Message" -ForegroundColor Green }
    else       { Write-Host "  FAIL  $Message" -ForegroundColor Red; $script:failures++ }
}

function Wait-ForDistributionGroup {
    <#
    .SYNOPSIS
        Polls Get-DistributionGroup with backoff — Exchange Online has a
        short directory-replication lag between object creation and the
        object being consistently queryable (confirmed for shared mailboxes
        in Invoke-SharedMBCreationE2E.ps1; the same lag applies here).
    #>
    param([string]$Identity, [int]$MaxAttempts = 6, [int]$DelaySeconds = 10)

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $grp = Get-DistributionGroup -Identity $Identity -ErrorAction SilentlyContinue
        if ($grp) { return $grp }
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

# Pre-clean any stray leftover from a previous run's incomplete cleanup —
# a lingering list makes the first run report "skipped" instead of
# "created" and fails the assertion (confirmed live in the full-sweep run).
Write-Host "`n== Pre-cleaning any stray E2E distribution list ==" -ForegroundColor Cyan
try {
    if (Get-DistributionGroup -Identity $E2EMailNickname -ErrorAction SilentlyContinue) {
        Remove-DistributionGroup -Identity $E2EMailNickname -Confirm:$false -ErrorAction Stop
        Write-Host "  Removed stray list $E2EMailNickname" -ForegroundColor Gray
        for ($attempt = 1; $attempt -le 6; $attempt++) {
            if (!(Get-DistributionGroup -Identity $E2EMailNickname -ErrorAction SilentlyContinue)) { break }
            Start-Sleep -Seconds 10
        }
    }
}
catch { Write-Host "  (no stray list to remove, or removal failed: $($_.Exception.Message))" -ForegroundColor Gray }

try {
    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running Distribution-Lists.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Exchange/Distribution-Lists.ps1') `
        -NonInteractive -ConfigFile $DLConfigPath -ResultPath $ResultPath

    # ========================================================================
    # Assert on the script's own reported results
    # ========================================================================
    Write-Host "`n== Verifying script results ==" -ForegroundColor Cyan
    if (!(Test-Path $ResultPath)) {
        Write-Result $false "Script produced no results file — it likely aborted early"
    }
    else {
        $result = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
        Write-Result ([bool]$result.Success -and @($result.Created) -contains $E2EEmail) "Script reported success and created $E2EEmail"
        foreach ($fail in @($result.Failed)) {
            Write-Host "        failed list: $($fail.Name) — $($fail.Error)" -ForegroundColor Red
        }
    }

    # ========================================================================
    # Independently verify tenant state
    # ========================================================================
    Write-Host "`n== Verifying created distribution list in tenant ==" -ForegroundColor Cyan
    $group = Wait-ForDistributionGroup -Identity $E2EMailNickname
    Write-Result ([bool]$group) "$E2EDisplayName exists"
    if ($group) {
        Write-Result ($group.RecipientTypeDetails -eq 'MailUniversalDistributionGroup') "$E2EDisplayName is a distribution group (RecipientTypeDetails: $($group.RecipientTypeDetails))"
        Write-Result ($group.PrimarySmtpAddress -eq $E2EEmail) "$E2EDisplayName has the expected primary SMTP address"
    }

    # ========================================================================
    # Idempotency: a second run must skip the already-existing list
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run skips) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Exchange/Distribution-Lists.ps1') `
        -NonInteractive -ConfigFile $DLConfigPath -ResultPath $ResultPath

    $second = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
    Write-Result ([bool]$second.Success -and @($second.Created).Count -eq 0 -and (@($second.Skipped) -contains $E2EEmail)) `
        "Second run created nothing and skipped the already-existing list"
}
finally {
    # ========================================================================
    # Cleanup — always runs
    # ========================================================================
    Write-Host "`n== Cleaning up E2E distribution list ==" -ForegroundColor Cyan
    try {
        if (Wait-ForDistributionGroup -Identity $E2EMailNickname -MaxAttempts 3 -DelaySeconds 10) {
            Remove-DistributionGroup -Identity $E2EMailNickname -Confirm:$false -ErrorAction Stop
            Write-Host "  Deleted group $E2EDisplayName" -ForegroundColor Gray
        }
        else {
            Write-Host "  No group to delete" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  WARNING: could not delete group $($E2EDisplayName): $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Manually delete the '$E2EDisplayName' distribution list in the test tenant" -ForegroundColor Yellow
    }

    Remove-Item $DLConfigPath, $ResultPath -ErrorAction SilentlyContinue
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
