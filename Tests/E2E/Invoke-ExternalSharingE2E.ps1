#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs SharePoint/External-Sharing.ps1 unattended against
    the dedicated M365 test tenant and verifies the tenant-wide sharing
    settings it applies.
.DESCRIPTION
    Unlike the other SharePoint E2E tests, this script's target isn't a
    throwaway "E2E-" prefixed object — External-Sharing.ps1 changes real
    tenant-wide SharePoint sharing configuration (Set-SPOTenant), which
    affects every site in the tenant. This test therefore uses a
    snapshot/restore pattern (the same approach Invoke-ArchivePoliciesE2E.ps1
    uses for mailbox quota settings): it records the tenant's current
    sharing settings before touching anything, and restores them in a
    finally block that always runs, so the test tenant is left exactly as
    it found it regardless of outcome.

    Connects to SharePoint Online Management Shell (app-only cert auth),
    then:
      1. Snapshots the tenant's current SharingCapability,
         ExternalUserExpirationRequired/ExternalUserExpireInDays,
         DefaultSharingLinkType, and DefaultLinkPermission
      2. Picks a SharingCapability value guaranteed to differ from the
         current one (a two-way toggle between
         ExistingExternalUserSharingOnly and ExternalUserSharingOnly), so
         the test proves an actual change took effect rather than
         coincidentally matching what was already set
      3. Runs SharePoint/External-Sharing.ps1 non-interactively — the real
         script, same file the menu calls
      4. Verifies via Get-SPOTenant that the sharing capability, guest
         expiration, default link type, and default link permission all
         changed to the requested values
      5. Re-runs the script with the same config to prove it doesn't error
         on a second application of the same settings
      6. Restores the original snapshot in a finally block that always runs
.EXAMPLE
    ./Invoke-ExternalSharingE2E.ps1 -TenantId $env:M365_TENANT_ID -TenantDomain $env:M365_TENANT_DOMAIN -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
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

$RepoRoot    = $PSScriptRoot | Split-Path | Split-Path
$tenantName  = $TenantDomain -replace '\.onmicrosoft\.com$', ''
$SpoAdminUrl = "https://$tenantName-admin.sharepoint.com"

$ESConfigPath = Join-Path ([IO.Path]::GetTempPath()) "external-sharing-e2e-config-$([guid]::NewGuid().ToString('n')).json"
$ResultPath   = Join-Path ([IO.Path]::GetTempPath()) "external-sharing-e2e-result-$([guid]::NewGuid().ToString('n')).json"

$failures = 0

function Write-Result {
    param([bool]$Pass, [string]$Message)
    if ($Pass) { Write-Host "  PASS  $Message" -ForegroundColor Green }
    else       { Write-Host "  FAIL  $Message" -ForegroundColor Red; $script:failures++ }
}

# ============================================================================
# Connect
# ============================================================================
Write-Host "`n== Connecting to test tenant (SharePoint Online, app-only) ==" -ForegroundColor Cyan
Connect-SPOService -Url $SpoAdminUrl -ClientId $AppId -TenantId $TenantId `
    -CertificateThumbprint $CertificateThumbprint -ErrorAction Stop
Write-Host "  Connected to $SpoAdminUrl" -ForegroundColor Green

# ============================================================================
# Snapshot current tenant sharing settings — restored in the finally block
# ============================================================================
Write-Host "`n== Snapshotting current tenant sharing settings ==" -ForegroundColor Cyan
$before = Get-SPOTenant -ErrorAction Stop
$originalSharingCapability = $before.SharingCapability
$originalExpirationRequired = $before.ExternalUserExpirationRequired
$originalExpirationDays = $before.ExternalUserExpireInDays
$originalLinkType = $before.DefaultSharingLinkType
$originalLinkPermission = $before.DefaultLinkPermission
Write-Host "  Current: SharingCapability=$originalSharingCapability, ExpirationRequired=$originalExpirationRequired, ExpireInDays=$originalExpirationDays, LinkType=$originalLinkType, LinkPermission=$originalLinkPermission" -ForegroundColor Gray

# Two-way toggle: guarantees the target differs from whatever's currently set.
$targetSharingCapability = if ($originalSharingCapability -eq 'ExistingExternalUserSharingOnly') {
    'ExternalUserSharingOnly'
}
else {
    'ExistingExternalUserSharingOnly'
}
Write-Host "  Target for this test: $targetSharingCapability" -ForegroundColor Gray

@{
    SharingLevel           = $targetSharingCapability
    GuestExpirationEnabled = $true
    GuestExpirationDays    = 45
    DefaultLinkType        = 'Internal'
    DefaultLinkPermission  = 'View'
} | ConvertTo-Json -Depth 5 | Set-Content -Path $ESConfigPath -Encoding UTF8

try {
    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running External-Sharing.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'SharePoint/External-Sharing.ps1') `
        -NonInteractive -ConfigFile $ESConfigPath -ResultPath $ResultPath

    # ========================================================================
    # Assert on the script's own reported results
    # ========================================================================
    Write-Host "`n== Verifying script results ==" -ForegroundColor Cyan
    if (!(Test-Path $ResultPath)) {
        Write-Result $false "Script produced no results file — it likely aborted early"
    }
    else {
        $result = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
        Write-Result ([bool]$result.Success -and $result.SharingLevel -eq $targetSharingCapability) `
            "Script reported success and applied SharingLevel=$targetSharingCapability"
    }

    # ========================================================================
    # Independently verify tenant state
    # ========================================================================
    Write-Host "`n== Verifying tenant sharing settings changed ==" -ForegroundColor Cyan
    $after = Get-SPOTenant -ErrorAction Stop
    Write-Result ($after.SharingCapability -eq $targetSharingCapability) `
        "SharingCapability changed to $targetSharingCapability (was $originalSharingCapability, now $($after.SharingCapability))"
    Write-Result ($after.ExternalUserExpirationRequired -eq $true -and $after.ExternalUserExpireInDays -eq 45) `
        "Guest expiration set to 45 days"
    Write-Result ($after.DefaultSharingLinkType -eq 'Internal') "Default link type set to Internal"
    Write-Result ($after.DefaultLinkPermission -eq 'View') "Default link permission set to View"

    # ========================================================================
    # Re-run: applying the same settings again must not error
    # ========================================================================
    Write-Host "`n== Verifying a second application of the same settings doesn't error ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'SharePoint/External-Sharing.ps1') `
        -NonInteractive -ConfigFile $ESConfigPath -ResultPath $ResultPath

    $second = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
    Write-Result ([bool]$second.Success) "Second run with identical settings also reported success"
}
finally {
    # ========================================================================
    # Restore the tenant's original sharing settings — always runs, since
    # this test mutates real tenant-wide configuration, not a throwaway
    # prefixed object.
    # ========================================================================
    Write-Host "`n== Restoring original tenant sharing settings ==" -ForegroundColor Cyan
    try {
        Set-SPOTenant -SharingCapability $originalSharingCapability -ErrorAction Stop
        if ($originalExpirationRequired) {
            Set-SPOTenant -ExternalUserExpirationRequired $true -ExternalUserExpireInDays $originalExpirationDays -ErrorAction Stop
        }
        else {
            Set-SPOTenant -ExternalUserExpirationRequired $false -ErrorAction Stop
        }
        Set-SPOTenant -DefaultSharingLinkType $originalLinkType -ErrorAction Stop
        Set-SPOTenant -DefaultLinkPermission $originalLinkPermission -ErrorAction Stop
        Write-Host "  Restored: SharingCapability=$originalSharingCapability, ExpirationRequired=$originalExpirationRequired, ExpireInDays=$originalExpirationDays, LinkType=$originalLinkType, LinkPermission=$originalLinkPermission" -ForegroundColor Gray
    }
    catch {
        Write-Host "  WARNING: could not fully restore original tenant sharing settings: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Manually verify tenant sharing settings in the test tenant match: SharingCapability=$originalSharingCapability, ExpirationRequired=$originalExpirationRequired, ExpireInDays=$originalExpirationDays, LinkType=$originalLinkType, LinkPermission=$originalLinkPermission" -ForegroundColor Yellow
    }

    Remove-Item $ESConfigPath, $ResultPath -ErrorAction SilentlyContinue
    try { Disconnect-SPOService -ErrorAction SilentlyContinue } catch {}
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
