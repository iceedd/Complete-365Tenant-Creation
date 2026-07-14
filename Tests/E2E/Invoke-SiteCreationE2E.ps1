#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs SharePoint/Site-Creation.ps1 unattended against the
    dedicated M365 test tenant and verifies the site it creates.
.DESCRIPTION
    Connects to Microsoft Graph (to discover a real licensed user to use as
    site owner — New-SPOSite requires an actual UPN, not a service
    principal) and to SharePoint Online Management Shell, both with
    certificate-based app-only auth. Then:
      1. Writes a throwaway config file describing one E2E- prefixed Team
         Site, owned by the discovered user
      2. Runs SharePoint/Site-Creation.ps1 non-interactively — the real
         script, same file the menu calls
      3. Verifies the site exists via Get-SPOSite with the expected template
      4. Re-runs the script to prove idempotency (second run must skip the
         already-existing site)
      5. Deletes the site and purges it from the recycle bin in a finally
         block that always runs, so a re-run doesn't collide with a
         recycle-bin-held site at the same URL
.EXAMPLE
    ./Invoke-SiteCreationE2E.ps1 -TenantId $env:M365_TENANT_ID -TenantDomain $env:M365_TENANT_DOMAIN -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
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

# The SPO Management Shell is a Windows PowerShell module — Microsoft's own
# docs require importing it with -UseWindowsPowerShell in a PowerShell 7
# console (learn.microsoft.com/powershell/sharepoint/sharepoint-online/connect-sharepoint-online;
# confirmed live: without this, Connect-SPOService is simply not recognized).
# The CI workflow installs the module from Windows PowerShell 5.1 so it lands
# in a module path the compatibility session can see.
Import-Module Microsoft.Online.SharePoint.PowerShell -UseWindowsPowerShell -WarningAction SilentlyContinue -ErrorAction Stop


$RepoRoot     = $PSScriptRoot | Split-Path | Split-Path
$E2ETitle     = "E2E Test Site"
$E2EUrlAlias  = "e2e-test-site"
$tenantName   = $TenantDomain -replace '\.onmicrosoft\.com$', ''
$SpoAdminUrl  = "https://$tenantName-admin.sharepoint.com"
$TenantRootUrl = "https://$tenantName.sharepoint.com"
$E2EFullUrl   = "$TenantRootUrl/sites/$E2EUrlAlias"

$SCConfigPath = Join-Path ([IO.Path]::GetTempPath()) "site-e2e-config-$([guid]::NewGuid().ToString('n')).json"
$ResultPath   = Join-Path ([IO.Path]::GetTempPath()) "site-e2e-result-$([guid]::NewGuid().ToString('n')).json"

$failures = 0

function Write-Result {
    param([bool]$Pass, [string]$Message)
    if ($Pass) { Write-Host "  PASS  $Message" -ForegroundColor Green }
    else       { Write-Host "  FAIL  $Message" -ForegroundColor Red; $script:failures++ }
}

function Wait-ForSite {
    <#
    .SYNOPSIS
        Polls Get-SPOSite with backoff — site provisioning is asynchronous
        and the script's own comments note Team Sites can take 2-5 minutes
        to fully provision.
    #>
    param([string]$Url, [int]$MaxAttempts = 18, [int]$DelaySeconds = 20)

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $site = Get-SPOSite -Identity $Url -ErrorAction SilentlyContinue
        if ($site) { return $site }
        if ($attempt -lt $MaxAttempts) { Start-Sleep -Seconds $DelaySeconds }
    }
    return $null
}

# ============================================================================
# Connect — Graph first (to discover a real user for site ownership), then
# SharePoint Online Management Shell (both app-only cert auth)
# ============================================================================
Write-Host "`n== Connecting to test tenant (Graph, app-only) ==" -ForegroundColor Cyan
Connect-MgGraph -ClientId $AppId -TenantId $TenantId `
    -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
$ctx = Get-MgContext
if (!$ctx) { throw "Failed to establish Graph context" }
Write-Host "  Connected to Graph tenant $($ctx.TenantId)" -ForegroundColor Green

Write-Host "`n== Discovering a real user to use as site owner ==" -ForegroundColor Cyan
$ownerUser = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users?`$filter=accountEnabled eq true&`$top=1" -ErrorAction Stop
$ownerUpn = $ownerUser.value[0].userPrincipalName
if ([string]::IsNullOrWhiteSpace($ownerUpn)) { throw "Could not find any enabled user in the tenant to use as site owner" }
Write-Host "  Using $ownerUpn as site owner" -ForegroundColor Green

@{
    Sites = @(
        @{
            Title       = $E2ETitle
            Type        = 'TeamSite'
            UrlAlias    = $E2EUrlAlias
            Description = "Created by Invoke-SiteCreationE2E.ps1"
            Owner       = $ownerUpn
        }
    )
} | ConvertTo-Json -Depth 5 | Set-Content -Path $SCConfigPath -Encoding UTF8

Write-Host "`n== Connecting to test tenant (SharePoint Online, app-only) ==" -ForegroundColor Cyan
# Connect-SPOService's -CertificateThumbprint is broken — it throws "No
# certificate was found matching the specified parameters" even when the
# cert is demonstrably in Cert:\CurrentUser\My (confirmed live: Connect-MgGraph
# succeeded with the identical thumbprint seconds earlier), a known module
# issue. Use -CertificatePath with the PFX instead (Microsoft's documented
# approach), re-materialised from the same env vars the workflow's
# import-certificate step uses.
if (!$env:M365_PFX_BASE64 -or !$env:M365_PFX_PASSWORD) { throw "M365_PFX_BASE64 and M365_PFX_PASSWORD env vars are required for the SPO connection" }
$spoPfxPath = Join-Path ([IO.Path]::GetTempPath()) "spo-e2e-$([guid]::NewGuid().ToString('n')).pfx"
[IO.File]::WriteAllBytes($spoPfxPath, [Convert]::FromBase64String($env:M365_PFX_BASE64))
try {
    $spoPfxPassword = ConvertTo-SecureString $env:M365_PFX_PASSWORD -AsPlainText -Force
    Connect-SPOService -Url $SpoAdminUrl -ClientId $AppId -TenantId $TenantId `
        -CertificatePath $spoPfxPath -CertificatePassword $spoPfxPassword -ErrorAction Stop
}
finally {
    Remove-Item $spoPfxPath -Force -ErrorAction SilentlyContinue
}
$null = Get-SPOTenant -ErrorAction Stop
Write-Host "  Connected to $SpoAdminUrl" -ForegroundColor Green

# Pre-clean any stray leftover from a previous run's incomplete cleanup.
Write-Host "`n== Pre-cleaning any stray E2E site ==" -ForegroundColor Cyan
try {
    if (Get-SPOSite -Identity $E2EFullUrl -ErrorAction SilentlyContinue) {
        Remove-SPOSite -Identity $E2EFullUrl -Confirm:$false -ErrorAction Stop
        Write-Host "  Removed stray site $E2EFullUrl (now in recycle bin)" -ForegroundColor Gray
    }
    if (Get-SPODeletedSite -Identity $E2EFullUrl -ErrorAction SilentlyContinue) {
        Remove-SPODeletedSite -Identity $E2EFullUrl -Confirm:$false -ErrorAction Stop
        Write-Host "  Purged stray site $E2EFullUrl from recycle bin" -ForegroundColor Gray
    }
}
catch { Write-Host "  (no stray site to remove, or removal failed: $($_.Exception.Message))" -ForegroundColor Gray }

try {
    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running Site-Creation.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'SharePoint/Site-Creation.ps1') `
        -NonInteractive -ConfigFile $SCConfigPath -ResultPath $ResultPath

    # ========================================================================
    # Assert on the script's own reported results
    # ========================================================================
    Write-Host "`n== Verifying script results ==" -ForegroundColor Cyan
    if (!(Test-Path $ResultPath)) {
        Write-Result $false "Script produced no results file — it likely aborted early"
    }
    else {
        $result = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
        Write-Result ([bool]$result.Success -and (@($result.Created) -contains $E2ETitle)) `
            "Script reported success and created $E2ETitle"
        foreach ($fail in @($result.Failed)) {
            Write-Host "        failed site: $($fail.Name) — $($fail.Error)" -ForegroundColor Red
        }
    }

    # ========================================================================
    # Independently verify tenant state
    # ========================================================================
    Write-Host "`n== Verifying created site in tenant (may take a few minutes to provision) ==" -ForegroundColor Cyan
    $site = Wait-ForSite -Url $E2EFullUrl
    Write-Result ([bool]$site) "$E2EFullUrl exists"
    if ($site) {
        Write-Result ($site.Template -eq 'STS#3') "$E2EFullUrl is a Team Site (Template: $($site.Template))"
        Write-Result ($site.Title -eq $E2ETitle) "$E2EFullUrl has the expected title"
    }

    # ========================================================================
    # Idempotency: a second run must skip the already-existing site
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run skips) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'SharePoint/Site-Creation.ps1') `
        -NonInteractive -ConfigFile $SCConfigPath -ResultPath $ResultPath

    $second = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
    Write-Result ([bool]$second.Success -and @($second.Created).Count -eq 0 -and (@($second.Skipped) -contains $E2ETitle)) `
        "Second run created nothing and skipped the already-existing site"
}
finally {
    # ========================================================================
    # Cleanup — always runs. Purge from the recycle bin too, so a future
    # run doesn't collide with a recycle-bin-held site at the same URL.
    # ========================================================================
    Write-Host "`n== Cleaning up E2E site ==" -ForegroundColor Cyan
    try {
        if (Get-SPOSite -Identity $E2EFullUrl -ErrorAction SilentlyContinue) {
            Remove-SPOSite -Identity $E2EFullUrl -Confirm:$false -ErrorAction Stop
            Write-Host "  Deleted site $E2EFullUrl (now in recycle bin)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  WARNING: could not delete site $($E2EFullUrl): $($_.Exception.Message)" -ForegroundColor Yellow
    }
    try {
        # Give the recycle bin a moment to register the deletion before purging.
        for ($attempt = 1; $attempt -le 6; $attempt++) {
            if (Get-SPODeletedSite -Identity $E2EFullUrl -ErrorAction SilentlyContinue) { break }
            Start-Sleep -Seconds 10
        }
        if (Get-SPODeletedSite -Identity $E2EFullUrl -ErrorAction SilentlyContinue) {
            Remove-SPODeletedSite -Identity $E2EFullUrl -Confirm:$false -ErrorAction Stop
            Write-Host "  Purged site $E2EFullUrl from recycle bin" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  WARNING: could not purge site $($E2EFullUrl) from recycle bin: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Manually purge the deleted '$E2EFullUrl' site in the test tenant" -ForegroundColor Yellow
    }

    Remove-Item $SCConfigPath, $ResultPath -ErrorAction SilentlyContinue
    try { Disconnect-SPOService -ErrorAction SilentlyContinue } catch {}
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
