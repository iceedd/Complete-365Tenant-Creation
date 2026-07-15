#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs SharePoint/Permission-Groups.ps1 unattended against
    the dedicated M365 test tenant and verifies its audit-and-repair logic.
.DESCRIPTION
    Connects to Microsoft Graph and SharePoint Online Management Shell (both
    app-only cert auth), then:
      1. Creates a throwaway "E2E-" prefixed site directly and waits for it
         to provision. A freshly provisioned Team Site auto-creates its
         three standard permission groups (Owners/Members/Visitors), so the
         test deliberately removes the "Visitors" (Read) group to create a
         genuine "missing group" scenario for the script to detect and repair
      2. Writes a throwaway config file targeting that site with
         AutoRepair enabled
      3. Runs SharePoint/Permission-Groups.ps1 non-interactively — the real
         script, same file the menu calls
      4. Verifies the script's results report exactly one repaired group,
         and independently confirms via Get-SPOSiteGroup that a Read-level
         group now exists again
      5. Re-runs the script to prove idempotency (second run must find no
         missing groups, since the first run already repaired it)
      6. Deletes the site (purging it from the recycle bin) in a finally
         block that always runs
.EXAMPLE
    ./Invoke-PermissionGroupsE2E.ps1 -TenantId $env:M365_TENANT_ID -TenantDomain $env:M365_TENANT_DOMAIN -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
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


$RepoRoot      = $PSScriptRoot | Split-Path | Split-Path
$E2ETitle      = "E2E Test Permission Groups"
$E2EUrlAlias   = "e2e-test-permission-groups"
$tenantName    = $TenantDomain -replace '\.onmicrosoft\.com$', ''
$SpoAdminUrl   = "https://$tenantName-admin.sharepoint.com"
$TenantRootUrl = "https://$tenantName.sharepoint.com"
$E2EFullUrl    = "$TenantRootUrl/sites/$E2EUrlAlias"

$PGConfigPath = Join-Path ([IO.Path]::GetTempPath()) "perm-groups-e2e-config-$([guid]::NewGuid().ToString('n')).json"
$ResultPath   = Join-Path ([IO.Path]::GetTempPath()) "perm-groups-e2e-result-$([guid]::NewGuid().ToString('n')).json"

$failures = 0

function Write-Result {
    param([bool]$Pass, [string]$Message)
    if ($Pass) { Write-Host "  PASS  $Message" -ForegroundColor Green }
    else       { Write-Host "  FAIL  $Message" -ForegroundColor Red; $script:failures++ }
}

function Wait-ForSite {
    param([string]$Url, [int]$MaxAttempts = 18, [int]$DelaySeconds = 20)
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $site = Get-SPOSite -Identity $Url -ErrorAction SilentlyContinue
        if ($site) { return $site }
        if ($attempt -lt $MaxAttempts) { Start-Sleep -Seconds $DelaySeconds }
    }
    return $null
}

# ============================================================================
# Connect
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

# ============================================================================
# Pre-clean any stray leftover from a previous run's incomplete cleanup.
# ============================================================================
Write-Host "`n== Pre-cleaning any stray E2E site ==" -ForegroundColor Cyan
try {
    if (Get-SPOSite -Identity $E2EFullUrl -ErrorAction SilentlyContinue) {
        Remove-SPOSite -Identity $E2EFullUrl -Confirm:$false -ErrorAction Stop
    }
    if (Get-SPODeletedSite -Identity $E2EFullUrl -ErrorAction SilentlyContinue) {
        Remove-SPODeletedSite -Identity $E2EFullUrl -Confirm:$false -ErrorAction Stop
    }
}
catch { Write-Host "  (no stray site to remove, or removal failed: $($_.Exception.Message))" -ForegroundColor Gray }

# ============================================================================
# Set up a throwaway site with a deliberately-missing standard group
# ============================================================================
Write-Host "`n== Creating throwaway site for the test (may take a few minutes to provision) ==" -ForegroundColor Cyan
New-SPOSite -Url $E2EFullUrl -Owner $ownerUpn -Title $E2ETitle -Template 'STS#3' `
    -StorageQuota 1024 -ErrorAction Stop
$site = Wait-ForSite -Url $E2EFullUrl
if (!$site) { throw "Throwaway site $E2EFullUrl never finished provisioning" }
Write-Host "  Site ready: $E2EFullUrl" -ForegroundColor Green

Write-Host "`n== Deliberately removing the Read-level group to create a 'missing group' scenario ==" -ForegroundColor Cyan
$readGroup = Get-SPOSiteGroup -Site $E2EFullUrl -ErrorAction Stop | Where-Object { $_.Roles -contains 'Read' } | Select-Object -First 1
if (!$readGroup) { throw "Freshly provisioned site has no Read-level group to remove — cannot set up the test scenario" }
Remove-SPOSiteGroup -Site $E2EFullUrl -Identity $readGroup.Title -ErrorAction Stop
Write-Host "  Removed group: $($readGroup.Title)" -ForegroundColor Gray

@{
    ScopeChoice = '2'
    SiteUrl     = $E2EFullUrl
    AutoRepair  = $true
} | ConvertTo-Json -Depth 5 | Set-Content -Path $PGConfigPath -Encoding UTF8

try {
    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running Permission-Groups.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'SharePoint/Permission-Groups.ps1') `
        -NonInteractive -ConfigFile $PGConfigPath -ResultPath $ResultPath

    # ========================================================================
    # Assert on the script's own reported results
    # ========================================================================
    Write-Host "`n== Verifying script results ==" -ForegroundColor Cyan
    if (!(Test-Path $ResultPath)) {
        Write-Result $false "Script produced no results file — it likely aborted early"
    }
    else {
        $result = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
        # A failure-shaped result (@{Success=$false; Error=...}) lacks the
        # detail keys, and strict mode makes missing-key access throw — guard
        # every optional key with ContainsKey.
        # @() wraps the WHOLE if: `$x = if (...) { @() }` assigns $null when
        # the branch emits an empty array (empty pipeline output), and
        # $null.Count then throws under strict mode (confirmed live).
        $created = @(if ($result.ContainsKey('Created')) { $result.Created })
        Write-Result ([bool]$result.Success -and $created.Count -eq 1) `
            "Script reported success and repaired exactly 1 missing group"
        if ($result.ContainsKey('Error') -and $result.Error) {
            Write-Host "        script error: $($result.Error)" -ForegroundColor Red
        }
        if ($result.ContainsKey('Failed')) {
            foreach ($fail in @($result.Failed)) {
                Write-Host "        failed repair: $($fail.Group) — $($fail.Error)" -ForegroundColor Red
            }
        }
    }

    # ========================================================================
    # Independently verify tenant state
    # ========================================================================
    Write-Host "`n== Verifying repaired group in tenant ==" -ForegroundColor Cyan
    $repairedGroup = Get-SPOSiteGroup -Site $E2EFullUrl -ErrorAction Stop | Where-Object { $_.Roles -contains 'Read' } | Select-Object -First 1
    Write-Result ([bool]$repairedGroup) "A Read-level group exists again on $E2EFullUrl"

    # ========================================================================
    # Idempotency: a second run must find nothing left to repair
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run finds nothing to repair) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'SharePoint/Permission-Groups.ps1') `
        -NonInteractive -ConfigFile $PGConfigPath -ResultPath $ResultPath

    $second = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
    # @() wraps the WHOLE if — see comment on $created above.
    $secondCreated = @(if ($second.ContainsKey('Created')) { $second.Created })
    Write-Result ([bool]$second.Success -and $secondCreated.Count -eq 0) `
        "Second run found no missing groups and created nothing"
}
finally {
    # ========================================================================
    # Cleanup — always runs
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

    Remove-Item $PGConfigPath, $ResultPath -ErrorAction SilentlyContinue
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
