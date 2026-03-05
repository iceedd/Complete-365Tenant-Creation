#Requires -Version 7.0

<#
.SYNOPSIS
    Creates Entra security groups for SharePoint sites and assigns permissions
.DESCRIPTION
    For each site (new or existing), creates three Entra security groups:
      SPO-<alias>-Owners   → Full Control
      SPO-<alias>-Members  → Edit (Write)
      SPO-<alias>-Guests   → Read
    Assigns groups to the site via Microsoft Graph.
    Optionally configures per-site external sharing and confirms site collection admin.
.AUTHOR
    CB & Claude Partnership
.VERSION
    1.0 - Initial implementation
#>

# Suppress rules that are incompatible with this interactive console script style.
# Write-Host is required for coloured interactive output; these config variables are
# stubs intentionally reserved for use in later tasks.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseBOMForUnicodeEncodedFile', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Config stubs consumed by later tasks')]
param()

# ============================================================================
# CONFIGURATION
# ============================================================================

# SPO module enables site creation, sharing settings, and admin management.
# Graph-based operations (Entra groups, permissions) work without it.
$Script:SpoAvailable = $false

$PermissionRoleMap = @{
    Owners  = @{ Role = 'owner'; Label = 'Full Control' }
    Members = @{ Role = 'write'; Label = 'Edit'         }
    Guests  = @{ Role = 'read';  Label = 'Read'         }
}

$SharingOptions = [ordered]@{
    '1' = @{ Value = 'Disabled';                        Label = 'Disabled (internal only)'     }
    '2' = @{ Value = 'ExistingExternalUserSharingOnly'; Label = 'Existing guests only'         }
    '3' = @{ Value = 'ExternalUserSharingOnly';         Label = 'New and existing guests'      }
    '4' = @{ Value = 'ExternalUserAndGuestSharing';     Label = 'Anyone (most permissive)'     }
    'K' = @{ Value = $null;                             Label = 'Keep tenant default'          }
}

$SiteTemplates = @{
    TeamSite          = 'STS#3'
    CommunicationSite = 'SITEPAGEPUBLISHING#0'
}

# ============================================================================
# MODULE INIT
# ============================================================================

function Initialize-ScriptModules {
    Write-Host "   Checking required modules..." -ForegroundColor Yellow

    # Graph is required — must be connected via main menu
    $graphCtx = Get-MgContext -ErrorAction SilentlyContinue
    if ($null -eq $graphCtx) {
        Write-Host "   Microsoft Graph: not connected — please use the main menu first" -ForegroundColor Red
        return $false
    }
    Write-Host "   Microsoft Graph: connected" -ForegroundColor Green

    # SPO module — best-effort; degrades gracefully when unavailable
    $spoModule = 'Microsoft.Online.SharePoint.PowerShell'
    try {
        if (!(Get-Module -ListAvailable -Name $spoModule)) {
            Write-Host "   Installing $spoModule..." -ForegroundColor Yellow
            Install-Module $spoModule -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
        }
        if (!(Get-Module -Name $spoModule)) {
            Import-Module $spoModule -Force -ErrorAction Stop
        }
        $null = Get-SPOTenant -ErrorAction Stop
        $Script:SpoAvailable = $true
        Write-Host "   SPO module: connected" -ForegroundColor Green
    }
    catch {
        $Script:SpoAvailable = $false
        Write-Host "   SPO module: unavailable — site creation, sharing settings, and admin management disabled" -ForegroundColor Yellow
        Write-Host "   Entra group creation and Graph permission assignment will still work" -ForegroundColor Gray
    }

    return $true
}

# ============================================================================
# PREREQUISITES
# ============================================================================

function Test-Prerequisites {
    Write-Host ""
    Write-Host "   PREREQUISITES CHECK" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    # Graph connection (required)
    Write-Host "   Checking Microsoft Graph connection..." -ForegroundColor Gray
    $graphCtx = Get-MgContext -ErrorAction SilentlyContinue
    if ($null -eq $graphCtx) {
        Write-Host "   Not connected to Microsoft Graph" -ForegroundColor Red
        Write-Host "   Please connect using the main menu first" -ForegroundColor Yellow
        return @{ Success = $false }
    }
    Write-Host "   Microsoft Graph: connected ($($graphCtx.Account))" -ForegroundColor Green

    # SPO status (informational)
    if ($Script:SpoAvailable) {
        Write-Host "   SharePoint Online module: connected" -ForegroundColor Green
    }
    else {
        Write-Host "   SharePoint Online module: unavailable" -ForegroundColor Yellow
        Write-Host "   (Site creation, sharing settings, and admin management are disabled)" -ForegroundColor Gray
    }

    # Detect tenant root URL via Global set by Connect-SharePointOnline, then Graph fallback
    Write-Host "   Detecting tenant URL..." -ForegroundColor Gray
    $tenantRootUrl = $null

    if ($Global:SPOTenantName) {
        $tenantRootUrl = "https://$($Global:SPOTenantName).sharepoint.com"
        Write-Host "   Tenant root URL: $tenantRootUrl" -ForegroundColor Green
    }
    else {
        try {
            $rootSite = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/sites/root" -Method GET -ErrorAction Stop
            $tenantRootUrl = "https://$($rootSite.siteCollection.hostname)"
            Write-Host "   Tenant root URL: $tenantRootUrl" -ForegroundColor Green
        }
        catch {
            Write-Host "   Could not auto-detect tenant URL: $($_.Exception.Message)" -ForegroundColor Yellow
            $tenantName = Read-Host "   Enter your tenant name (e.g. 'contoso')"
            $tenantRootUrl = "https://$($tenantName.Trim()).sharepoint.com"
        }
    }

    Write-Host ""
    return @{
        Success        = $true
        TenantRootUrl  = $tenantRootUrl
        TenantHostname = ([System.Uri]$tenantRootUrl).Host
    }
}

# ============================================================================
# MODE SELECTION & SITE INPUT
# ============================================================================

function Show-ModeSelection {
    Write-Host ""
    Write-Host "   Select mode:" -ForegroundColor White
    Write-Host "   1. Create new site + groups" -ForegroundColor Gray
    Write-Host "   2. Target existing site(s)" -ForegroundColor Gray
    Write-Host "   Q. Cancel" -ForegroundColor Gray
    Write-Host ""
    return Read-Host "   Selection"
}

function Get-NewSiteDefinition {
    param([string]$TenantRootUrl)

    $title = Read-Host "   Site title (required)"
    if ([string]::IsNullOrWhiteSpace($title)) {
        Write-Host "   Title is required" -ForegroundColor Yellow
        return $null
    }

    Write-Host ""
    Write-Host "   Site type:" -ForegroundColor White
    Write-Host "   1. Team Site" -ForegroundColor Gray
    Write-Host "   2. Communication Site" -ForegroundColor Gray
    $typeChoice = Read-Host "   Selection (1 or 2)"
    $siteType   = if ($typeChoice -eq '2') { 'CommunicationSite' } else { 'TeamSite' }

    $suggestedAlias = ($title -replace '[^a-zA-Z0-9]', '-' -replace '-+', '-').Trim('-').ToLower()
    Write-Host ""
    Write-Host "   Suggested URL: $TenantRootUrl/sites/$suggestedAlias" -ForegroundColor Gray
    $aliasInput = Read-Host "   URL alias (Enter to accept)"
    $urlAlias   = if ([string]::IsNullOrWhiteSpace($aliasInput)) {
        $suggestedAlias
    } else {
        ($aliasInput.Trim() -replace '[^a-zA-Z0-9\-]', '').Trim('-').ToLower()
    }

    Write-Host ""
    $owner = Read-Host "   Site owner UPN (e.g. admin@contoso.com)"
    if ([string]::IsNullOrWhiteSpace($owner)) {
        Write-Host "   Owner is required" -ForegroundColor Yellow
        return $null
    }

    Write-Host ""
    $description = Read-Host "   Description (optional)"

    return @{
        Title       = $title
        Type        = $siteType
        UrlAlias    = $urlAlias
        FullUrl     = "$TenantRootUrl/sites/$urlAlias"
        Owner       = $owner
        Description = $description
        IsNew       = $true
    }
}

function Get-GraphSiteDetails {
    param([string]$SiteUrl)
    try {
        $uri      = [System.Uri]$SiteUrl
        $hostname = $uri.Host
        $path     = $uri.PathAndQuery.TrimEnd('/')
        return Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/sites/${hostname}:${path}" -Method GET -ErrorAction Stop
    }
    catch { return $null }
}

function Get-ExistingSiteTargets {
    param([string]$TenantRootUrl)

    Write-Host ""
    Write-Host "   Select existing sites:" -ForegroundColor White
    Write-Host "   1. All site collections (excluding OneDrive)" -ForegroundColor Gray
    Write-Host "   2. Enter specific site URL" -ForegroundColor Gray
    Write-Host ""
    $scopeChoice = Read-Host "   Selection"

    $sites = @()

    switch ($scopeChoice) {
        '1' {
            Write-Host "   Retrieving sites..." -ForegroundColor Gray
            if ($Script:SpoAvailable) {
                try {
                    $all = Get-SPOSite -Limit All -ErrorAction Stop |
                           Where-Object { $_.Url -notlike '*-my.sharepoint.com*' }
                    foreach ($s in $all) {
                        $alias = $s.Url -replace '.*/sites/', ''
                        $sites += @{
                            Title    = $s.Title
                            FullUrl  = $s.Url
                            UrlAlias = $alias
                            Owner    = $s.Owner
                            IsNew    = $false
                        }
                    }
                    Write-Host "   Found $($sites.Count) site(s)" -ForegroundColor Green
                }
                catch {
                    Write-Host "   Failed to retrieve sites: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            else {
                # Graph fallback
                try {
                    $response = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/sites?search=*&`$top=50" -Method GET -ErrorAction Stop
                    foreach ($s in $response.value) {
                        if ($s.webUrl -notlike '*-my.sharepoint.com*' -and $s.webUrl -like '*/sites/*') {
                            $alias = $s.webUrl -replace '.*/sites/', ''
                            $sites += @{
                                Title    = $s.displayName
                                FullUrl  = $s.webUrl
                                UrlAlias = $alias
                                Owner    = ''
                                IsNew    = $false
                            }
                        }
                    }
                    Write-Host "   Found $($sites.Count) site(s) via Graph" -ForegroundColor Green
                }
                catch {
                    Write-Host "   Failed to retrieve sites: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
        '2' {
            $url = Read-Host "   Site URL (e.g. https://contoso.sharepoint.com/sites/marketing)"
            if ($url -match '^https://') {
                $alias = $url -replace '.*/sites/', ''
                if ($Script:SpoAvailable) {
                    $site = Get-SPOSite -Identity $url -ErrorAction SilentlyContinue
                    if ($null -ne $site) {
                        $sites += @{
                            Title    = $site.Title
                            FullUrl  = $url
                            UrlAlias = $alias
                            Owner    = $site.Owner
                            IsNew    = $false
                        }
                        Write-Host "   Found: $($site.Title)" -ForegroundColor Green
                    }
                    else {
                        Write-Host "   Site not found: $url" -ForegroundColor Red
                    }
                }
                else {
                    $graphSite = Get-GraphSiteDetails -SiteUrl $url
                    if ($null -ne $graphSite) {
                        $sites += @{
                            Title    = $graphSite.displayName
                            FullUrl  = $url
                            UrlAlias = $alias
                            Owner    = ''
                            IsNew    = $false
                        }
                        Write-Host "   Found: $($graphSite.displayName)" -ForegroundColor Green
                    }
                    else {
                        # User provided URL but Graph couldn't verify — add with alias as title
                        $titleGuess = (Get-Culture).TextInfo.ToTitleCase(($alias -replace '-', ' '))
                        $sites += @{
                            Title    = $titleGuess
                            FullUrl  = $url
                            UrlAlias = $alias
                            Owner    = ''
                            IsNew    = $false
                        }
                        Write-Host "   Site added (unverified): $url" -ForegroundColor Yellow
                    }
                }
            }
            else {
                Write-Host "   Invalid URL format" -ForegroundColor Red
            }
        }
        default {
            Write-Host "   Invalid selection" -ForegroundColor Yellow
        }
    }

    return $sites
}

# ============================================================================
# SITE CREATION
# ============================================================================

function Invoke-SiteCreation {
    param([hashtable]$SiteDefinition)

    try {
        $existing = Get-SPOSite -Identity $SiteDefinition.FullUrl -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Write-Host "     Site already exists — skipping creation" -ForegroundColor Yellow
            return @{ Success = $true; Skipped = $true }
        }

        $template = $SiteTemplates[$SiteDefinition.Type]

        New-SPOSite `
            -Url                      $SiteDefinition.FullUrl `
            -Owner                    $SiteDefinition.Owner `
            -Title                    $SiteDefinition.Title `
            -Template                 $template `
            -StorageQuota             1024 `
            -StorageQuotaWarningLevel 512 `
            -ErrorAction              Stop

        Write-Host "     Created: $($SiteDefinition.FullUrl)" -ForegroundColor Green
        return @{ Success = $true; Skipped = $false }
    }
    catch {
        Write-Host "     Failed to create site: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ============================================================================
# GROUP NAMES & PREVIEW
# ============================================================================

function Get-SiteGroupNames {
    param([string]$UrlAlias)

    # Sanitise alias: lowercase, alphanumeric + hyphens, max 40 chars
    $safe = ($UrlAlias -replace '[^a-zA-Z0-9\-]', '-' -replace '-+', '-').Trim('-').ToLower()
    if ($safe.Length -gt 40) { $safe = $safe.Substring(0, 40).TrimEnd('-') }

    return @{
        Owners  = "SPO-$safe-Owners"
        Members = "SPO-$safe-Members"
        Guests  = "SPO-$safe-Guests"
    }
}

function Show-ProvisioningPreview {
    param([array]$Sites)

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  PREVIEW: Sites and Groups to Provision" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""

    foreach ($site in $Sites) {
        $groupNames = Get-SiteGroupNames -UrlAlias $site.UrlAlias
        $newLabel   = if ($site.IsNew) { " [NEW SITE]" } else { "" }
        Write-Host "  Site: $($site.Title)$newLabel" -ForegroundColor White
        Write-Host "  URL:  $($site.FullUrl)" -ForegroundColor Gray
        Write-Host ""
        Write-Host ("  {0,-45} {1}" -f $groupNames.Owners,  "-> Full Control") -ForegroundColor Green
        Write-Host ("  {0,-45} {1}" -f $groupNames.Members, "-> Edit")         -ForegroundColor Cyan
        Write-Host ("  {0,-45} {1}" -f $groupNames.Guests,  "-> Read")         -ForegroundColor Gray
        Write-Host ""
    }
}

# ============================================================================
# ENTRA GROUP CREATION
# ============================================================================

function New-EntraSiteGroup {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Interactive console script; ShouldProcess not applicable')]
    param(
        [string]$DisplayName,
        [string]$Description
    )

    # Check if group already exists
    $encoded  = [System.Uri]::EscapeDataString($DisplayName)
    $existing = Invoke-MgGraphRequest `
        -Uri    "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$encoded'" `
        -Method GET `
        -ErrorAction SilentlyContinue

    if ($existing -and $existing.value.Count -gt 0) {
        $existingId = $existing.value[0].id
        Write-Host "     Group exists (skipped): $DisplayName" -ForegroundColor Yellow
        return @{ Success = $true; Skipped = $true; GroupId = $existingId }
    }

    try {
        $body = @{
            displayName     = $DisplayName
            description     = $Description
            mailEnabled     = $false
            mailNickname    = ($DisplayName -replace '[^a-zA-Z0-9]', '')
            securityEnabled = $true
        } | ConvertTo-Json

        $result = Invoke-MgGraphRequest `
            -Uri         "https://graph.microsoft.com/v1.0/groups" `
            -Method      POST `
            -Body        $body `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Host "     Created group: $DisplayName" -ForegroundColor Green
        return @{ Success = $true; Skipped = $false; GroupId = $result.id }
    }
    catch {
        Write-Host "     Failed to create group '$DisplayName': $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ============================================================================
# GRAPH SITE ID
# ============================================================================

function Get-GraphSiteId {
    param([string]$SiteUrl)

    try {
        $uri      = [System.Uri]$SiteUrl
        $hostname = $uri.Host
        $path     = $uri.PathAndQuery.TrimEnd('/')

        $response = Invoke-MgGraphRequest `
            -Uri    "https://graph.microsoft.com/v1.0/sites/${hostname}:${path}" `
            -Method GET `
            -ErrorAction Stop

        return $response.id
    }
    catch {
        Write-Host "     Failed to resolve site ID for $SiteUrl : $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# ============================================================================
# SITE PERMISSIONS
# ============================================================================

function Set-SiteGroupPermission {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Interactive console script; ShouldProcess not applicable')]
    param(
        [string]$SiteId,
        [string]$GroupId,
        [string]$GroupDisplayName,
        [string]$Role
    )

    try {
        $body = @{
            roles               = @($Role)
            grantedToIdentities = @(
                @{
                    group = @{
                        id          = $GroupId
                        displayName = $GroupDisplayName
                    }
                }
            )
        } | ConvertTo-Json -Depth 5

        $null = Invoke-MgGraphRequest `
            -Uri         "https://graph.microsoft.com/v1.0/sites/$SiteId/permissions" `
            -Method      POST `
            -Body        $body `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Host "     Assigned $GroupDisplayName -> $Role" -ForegroundColor Green
        return @{ Success = $true }
    }
    catch {
        Write-Host "     Failed to assign $GroupDisplayName : $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ============================================================================
# EXTERNAL SHARING
# ============================================================================

function Get-SiteSharingChoice {
    param([string]$SiteTitle)

    Write-Host ""
    Write-Host "   External sharing for '$SiteTitle':" -ForegroundColor White
    foreach ($key in $SharingOptions.Keys) {
        Write-Host ("   {0}. {1}" -f $key, $SharingOptions[$key].Label) -ForegroundColor Gray
    }
    Write-Host ""
    $choice = Read-Host "   Selection"

    $choice = $choice.ToUpper().Trim()
    if ($SharingOptions.ContainsKey($choice)) {
        return $SharingOptions[$choice]
    }
    return $SharingOptions['K']
}

function Set-SiteSharingOverride {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Interactive console script; ShouldProcess not applicable')]
    param(
        [string]$SiteUrl,
        [string]$SharingCapability
    )

    try {
        Set-SPOSite -Identity $SiteUrl -SharingCapability $SharingCapability -ErrorAction Stop
        Write-Host "     External sharing set: $SharingCapability" -ForegroundColor Green
        return @{ Success = $true }
    }
    catch {
        Write-Host "     Failed to set sharing: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ============================================================================
# SITE ADMIN
# ============================================================================

function Confirm-SiteCollectionAdmin {
    param([hashtable]$SiteDefinition)

    try {
        $site = Get-SPOSite -Identity $SiteDefinition.FullUrl -ErrorAction Stop
        Write-Host "     Site collection admin: $($site.Owner)" -ForegroundColor Gray

        $addAdmin = Read-Host "     Add/change site collection admin? (Y/N)"
        if ($addAdmin -like 'Y*') {
            $adminUpn = Read-Host "     Admin UPN"
            if (![string]::IsNullOrWhiteSpace($adminUpn)) {
                Set-SPOSite -Identity $SiteDefinition.FullUrl -Owner $adminUpn -ErrorAction Stop
                Write-Host "     Site collection admin set: $adminUpn" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Host "     Could not confirm admin: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ============================================================================
# MAIN ORCHESTRATION
# ============================================================================

function Start-SiteGroups {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Interactive console entry-point; ShouldProcess not applicable')]
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  SHAREPOINT SITE GROUPS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Creates Entra security groups for sites and assigns permissions" -ForegroundColor Gray
    Write-Host ""

    # Step 1 - Prerequisites
    Write-Host "  STEP 1: Prerequisites" -ForegroundColor Yellow
    $prereq = Test-Prerequisites
    if (!$prereq.Success) {
        Write-Host "  Prerequisites not met. Please resolve issues and try again." -ForegroundColor Red
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep 2 }
        return
    }

    # Step 2 - Mode selection
    Write-Host ""
    Write-Host "  STEP 2: Mode" -ForegroundColor Yellow
    $mode = Show-ModeSelection

    if ($mode -like 'Q*') {
        Write-Host "  Cancelled by user" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep 2 }
        return
    }

    # Step 3 - Collect sites
    $sites = @()
    if ($mode -eq '1') {
        if (-not $Script:SpoAvailable) {
            Write-Host ""
            Write-Host "  ⚠️  Site creation requires the SharePoint Online module" -ForegroundColor Yellow
            Write-Host "     The SPO module is currently unavailable on this session." -ForegroundColor Gray
            Write-Host "     To create new sites, fix the SPO connection first." -ForegroundColor Gray
            Write-Host "     Select mode 2 (existing sites) to create groups for sites that already exist." -ForegroundColor Gray
            Write-Host ""
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep 2 }
            return
        }

        Write-Host ""
        Write-Host "  STEP 3: New Site Details" -ForegroundColor Yellow
        Write-Host ("   " + "-" * 50) -ForegroundColor Gray

        $addMore = $true
        while ($addMore) {
            $site = Get-NewSiteDefinition -TenantRootUrl $prereq.TenantRootUrl
            if ($null -ne $site) { $sites += $site }
            Write-Host ""
            $more = Read-Host "   Add another site? (Y/N)"
            $addMore = $more -like 'Y*'
        }
    }
    else {
        Write-Host ""
        Write-Host "  STEP 3: Select Existing Sites" -ForegroundColor Yellow
        Write-Host ("   " + "-" * 50) -ForegroundColor Gray
        $sites = Get-ExistingSiteTargets -TenantRootUrl $prereq.TenantRootUrl
    }

    if ($sites.Count -eq 0) {
        Write-Host "  No sites selected. Exiting." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep 2 }
        return
    }

    # Step 4 - Preview and confirm
    Write-Host ""
    Write-Host "  STEP 4: Preview" -ForegroundColor Yellow
    Show-ProvisioningPreview -Sites $sites

    Write-Host "  [Y] Proceed  [N] Cancel" -ForegroundColor Gray
    Write-Host ""
    $confirm = Read-Host "  Proceed? (Y/N)"
    if ($confirm -notlike 'Y*') {
        Write-Host "  Cancelled by user" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep 2 }
        return
    }

    # Tracking
    $results = @{
        SitesCreated  = @()
        SitesSkipped  = @()
        SitesFailed   = @()
        GroupsCreated = @()
        GroupsSkipped = @()
        GroupsFailed  = @()
        PermsFailed   = @()
    }

    $siteIndex = 0
    foreach ($site in $sites) {
        $siteIndex++
        Write-Host ""
        Write-Host "  [$siteIndex/$($sites.Count)] $($site.Title)" -ForegroundColor White
        Write-Host ("  " + "-" * 60) -ForegroundColor Gray

        # Create site if new mode
        if ($site.IsNew) {
            Write-Host "   Creating site..." -ForegroundColor Yellow
            $createResult = Invoke-SiteCreation -SiteDefinition $site
            if (!$createResult.Success) {
                $results.SitesFailed += $site.Title
                Write-Host "   Skipping groups for failed site." -ForegroundColor Yellow
                continue
            }
            if ($createResult.Skipped) { $results.SitesSkipped += $site.Title }
            else                       { $results.SitesCreated += $site.Title }
        }

        # Create Entra groups
        Write-Host "   Creating Entra security groups..." -ForegroundColor Yellow
        $groupNames = Get-SiteGroupNames -UrlAlias $site.UrlAlias
        $groupIds   = @{}
        $groupDesc  = "SharePoint site group for $($site.Title)"

        foreach ($roleName in @('Owners', 'Members', 'Guests')) {
            $gName  = $groupNames[$roleName]
            $result = New-EntraSiteGroup -DisplayName $gName -Description $groupDesc
            if ($result.Success) {
                $groupIds[$roleName] = $result.GroupId
                if ($result.Skipped) { $results.GroupsSkipped += $gName }
                else                 { $results.GroupsCreated += $gName }
            }
            else {
                $results.GroupsFailed += $gName
            }
        }

        # Assign groups to site
        Write-Host "   Assigning permissions..." -ForegroundColor Yellow
        $siteId = Get-GraphSiteId -SiteUrl $site.FullUrl

        if ($null -ne $siteId) {
            foreach ($roleName in @('Owners', 'Members', 'Guests')) {
                if ($groupIds.ContainsKey($roleName)) {
                    $role       = $PermissionRoleMap[$roleName].Role
                    $permResult = Set-SiteGroupPermission `
                        -SiteId           $siteId `
                        -GroupId          $groupIds[$roleName] `
                        -GroupDisplayName $groupNames[$roleName] `
                        -Role             $role
                    if (!$permResult.Success) {
                        $results.PermsFailed += "$($groupNames[$roleName]) -> $($site.Title)"
                    }
                }
            }
        }
        else {
            Write-Host "   Could not resolve site ID - permission assignment skipped" -ForegroundColor Yellow
        }

        # External sharing override (SPO module required)
        if ($Script:SpoAvailable) {
            Write-Host ""
            $sharingChoice = Get-SiteSharingChoice -SiteTitle $site.Title
            if ($null -ne $sharingChoice.Value) {
                Set-SiteSharingOverride -SiteUrl $site.FullUrl -SharingCapability $sharingChoice.Value | Out-Null
            }
            else {
                Write-Host "   External sharing: keeping tenant default" -ForegroundColor Gray
            }
        }
        else {
            Write-Host "   External sharing settings: skipped (SPO module unavailable)" -ForegroundColor Yellow
        }

        # Site collection admin (SPO module required)
        if ($Script:SpoAvailable) {
            Write-Host ""
            Write-Host "   Site collection admin:" -ForegroundColor Yellow
            Confirm-SiteCollectionAdmin -SiteDefinition $site
        }
        else {
            Write-Host "   Site collection admin: skipped (SPO module unavailable)" -ForegroundColor Yellow
        }
    }

    # Summary
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Sites created:      $($results.SitesCreated.Count)"  -ForegroundColor Green
    Write-Host "  Sites skipped:      $($results.SitesSkipped.Count)"  -ForegroundColor Yellow
    Write-Host "  Sites failed:       $($results.SitesFailed.Count)"   -ForegroundColor $(if ($results.SitesFailed.Count  -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  Groups created:     $($results.GroupsCreated.Count)" -ForegroundColor Green
    Write-Host "  Groups skipped:     $($results.GroupsSkipped.Count)" -ForegroundColor Yellow
    Write-Host "  Groups failed:      $($results.GroupsFailed.Count)"  -ForegroundColor $(if ($results.GroupsFailed.Count  -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  Perm assign failed: $($results.PermsFailed.Count)"   -ForegroundColor $(if ($results.PermsFailed.Count   -gt 0) { 'Red' } else { 'Green' })
    Write-Host ""

    if ($results.GroupsCreated.Count -gt 0) {
        Write-Host "  Created Groups:" -ForegroundColor Green
        foreach ($g in $results.GroupsCreated) { Write-Host "    - $g" -ForegroundColor White }
        Write-Host ""
    }

    if ($results.PermsFailed.Count -gt 0) {
        Write-Host "  Permission Assignment Failures:" -ForegroundColor Red
        foreach ($f in $results.PermsFailed) { Write-Host "    - $f" -ForegroundColor Red }
        Write-Host ""
        Write-Host "  Note: Assign these manually in SharePoint admin centre." -ForegroundColor Yellow
        Write-Host ""
    }

    Write-Host "  IMPORTANT:" -ForegroundColor Yellow
    Write-Host "    - Groups are created empty - add members via User Provisioning Tool" -ForegroundColor Gray
    Write-Host "    - New sites may take 2-5 minutes to fully provision" -ForegroundColor Gray
    Write-Host "    - Visit https://admin.sharepoint.com to manage sites further" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
    try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep 2 }
}

# ============================================================================
# ENTRY POINT  (main function added in a later task)
# ============================================================================

try {
    if (!(Initialize-ScriptModules)) {
        Write-Host "Failed to initialize required modules. Exiting." -ForegroundColor Red
        return
    }
    Start-SiteGroups
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
}
