#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs SharePoint/Site-Groups.ps1 unattended against the
    dedicated M365 test tenant and verifies the Entra security groups it
    creates and assigns to a site.
.DESCRIPTION
    Connects to Microsoft Graph and SharePoint Online Management Shell (both
    app-only cert auth), then:
      1. Creates a throwaway "E2E-" prefixed site directly (not via
         Site-Creation.ps1 — that script's own creation path is already
         covered by Invoke-SiteCreationE2E.ps1; this test focuses on the
         group-creation and permission-assignment logic that's unique to
         Site-Groups.ps1) and waits for it to provision
      2. Writes a throwaway config file targeting that site in "existing"
         mode
      3. Runs SharePoint/Site-Groups.ps1 non-interactively — the real
         script, same file the menu calls
      4. Verifies the three Entra security groups
         (SPO-<alias>-Owners/Members/Guests) exist via Microsoft Graph
      5. Re-runs the script to prove idempotency (second run must skip the
         already-existing groups, not create duplicates)
      6. Deletes the groups and the site (purging it from the recycle bin)
         in a finally block that always runs
.EXAMPLE
    ./Invoke-SiteGroupsE2E.ps1 -TenantId $env:M365_TENANT_ID -TenantDomain $env:M365_TENANT_DOMAIN -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
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
$E2ETitle      = "E2E Test Site Groups"
$E2EUrlAlias   = "e2e-test-site-groups"
$tenantName    = $TenantDomain -replace '\.onmicrosoft\.com$', ''
$SpoAdminUrl   = "https://$tenantName-admin.sharepoint.com"
$TenantRootUrl = "https://$tenantName.sharepoint.com"
$E2EFullUrl    = "$TenantRootUrl/sites/$E2EUrlAlias"

$GroupNames = @{
    Owners  = "SPO-$E2EUrlAlias-Owners"
    Members = "SPO-$E2EUrlAlias-Members"
    Guests  = "SPO-$E2EUrlAlias-Guests"
}

$SGConfigPath = Join-Path ([IO.Path]::GetTempPath()) "site-groups-e2e-config-$([guid]::NewGuid().ToString('n')).json"
$ResultPath   = Join-Path ([IO.Path]::GetTempPath()) "site-groups-e2e-result-$([guid]::NewGuid().ToString('n')).json"

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

function Get-EntraGroupByName {
    param([string]$DisplayName, [int]$MaxAttempts = 6, [int]$DelaySeconds = 10)
    $encoded = [System.Uri]::EscapeDataString($DisplayName)
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $response = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$encoded'" -ErrorAction SilentlyContinue
        if ($response -and @($response.value).Count -gt 0) { return $response.value[0] }
        if ($attempt -lt $MaxAttempts) { Start-Sleep -Seconds $DelaySeconds }
    }
    return $null
}

function Remove-EntraGroupByName {
    param([string]$DisplayName)
    $group = Get-EntraGroupByName -DisplayName $DisplayName -MaxAttempts 1
    if ($group) {
        Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)" -ErrorAction Stop
        Write-Host "  Deleted group $DisplayName" -ForegroundColor Gray
    }
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
# Pre-clean any stray leftovers from a previous run's incomplete cleanup.
# ============================================================================
Write-Host "`n== Pre-cleaning any stray E2E site/groups ==" -ForegroundColor Cyan
foreach ($groupName in $GroupNames.Values) {
    try { Remove-EntraGroupByName -DisplayName $groupName } catch { Write-Host "  (no stray group '$groupName', or removal failed: $($_.Exception.Message))" -ForegroundColor Gray }
}
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
# Set up a throwaway site for Site-Groups.ps1 to target in "existing" mode
# ============================================================================
Write-Host "`n== Creating throwaway site for the test (may take a few minutes to provision) ==" -ForegroundColor Cyan
New-SPOSite -Url $E2EFullUrl -Owner $ownerUpn -Title $E2ETitle -Template 'STS#3' `
    -StorageQuota 1024 -ErrorAction Stop
$site = Wait-ForSite -Url $E2EFullUrl
if (!$site) { throw "Throwaway site $E2EFullUrl never finished provisioning" }
Write-Host "  Site ready: $E2EFullUrl" -ForegroundColor Green

@{
    Mode              = 'existing'
    ExistingSiteUrl   = $E2EFullUrl
    SharingCapability = $null
    AdminUpn          = ''
} | ConvertTo-Json -Depth 5 | Set-Content -Path $SGConfigPath -Encoding UTF8

try {
    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running Site-Groups.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'SharePoint/Site-Groups.ps1') `
        -NonInteractive -ConfigFile $SGConfigPath -ResultPath $ResultPath

    # ========================================================================
    # Assert on the script's own reported results
    # ========================================================================
    Write-Host "`n== Verifying script results ==" -ForegroundColor Cyan
    if (!(Test-Path $ResultPath)) {
        Write-Result $false "Script produced no results file — it likely aborted early"
    }
    else {
        $result = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
        Write-Result ([bool]$result.Success -and @($result.GroupsCreated).Count -eq 3) `
            "Script reported success and created all 3 groups"
        foreach ($fail in @($result.GroupsFailed)) {
            Write-Host "        failed group: $fail" -ForegroundColor Red
        }
        foreach ($fail in @($result.PermsFailed)) {
            Write-Host "        failed permission assignment: $fail" -ForegroundColor Red
        }
    }

    # ========================================================================
    # Independently verify tenant state
    # ========================================================================
    Write-Host "`n== Verifying created Entra groups in tenant ==" -ForegroundColor Cyan
    foreach ($roleName in @('Owners', 'Members', 'Guests')) {
        $groupName = $GroupNames[$roleName]
        $group = Get-EntraGroupByName -DisplayName $groupName
        Write-Result ([bool]$group) "$groupName exists"
    }

    # ========================================================================
    # Idempotency: a second run must skip the already-existing groups
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run skips) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'SharePoint/Site-Groups.ps1') `
        -NonInteractive -ConfigFile $SGConfigPath -ResultPath $ResultPath

    $second = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
    Write-Result ([bool]$second.Success -and @($second.GroupsCreated).Count -eq 0 -and @($second.GroupsSkipped).Count -eq 3) `
        "Second run created nothing and skipped all 3 already-existing groups"
}
finally {
    # ========================================================================
    # Cleanup — always runs
    # ========================================================================
    Write-Host "`n== Cleaning up E2E groups and site ==" -ForegroundColor Cyan
    foreach ($groupName in $GroupNames.Values) {
        try { Remove-EntraGroupByName -DisplayName $groupName }
        catch {
            Write-Host "  WARNING: could not delete group $($groupName): $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "  Manually delete the '$groupName' Entra group in the test tenant" -ForegroundColor Yellow
        }
    }
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

    Remove-Item $SGConfigPath, $ResultPath -ErrorAction SilentlyContinue
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
