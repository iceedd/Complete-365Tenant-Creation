#Requires -Version 7.0

<#
.SYNOPSIS
    Creates SharePoint Team Sites and Communication Sites
.DESCRIPTION
    Interactive wizard for creating SharePoint Online sites. Supports
    Team Sites (STS#3) and Communication Sites (SITEPAGEPUBLISHING#0).
    Previews all sites before creation and reports results.
.AUTHOR
    BITS
.VERSION
    1.1 - Implemented Team Site and Communication Site creation. Adds
          non-interactive mode (-NonInteractive/-ConfigFile) for unattended
          E2E testing.
.PARAMETER NonInteractive
    Run unattended: skip all prompts and "press any key" pauses, creating
    exactly the sites listed in -ConfigFile. Used by CI E2E tests.
.PARAMETER ConfigFile
    Required in non-interactive mode. JSON file with a "Sites" array, each
    entry: Title, Type ('TeamSite' or 'CommunicationSite'), UrlAlias
    (optional, derived from Title if omitted), Description (optional),
    Owner (required UPN).
.PARAMETER ResultPath
    Optional path to write a JSON results summary, so a CI runner can assert
    on the outcome.
#>

param(
    [switch] $NonInteractive,
    [string] $ConfigFile,
    [string] $ResultPath
)

# ============================================================================
# CONFIGURATION
# ============================================================================

$script:NonInteractive = [bool]$NonInteractive

# Run-behaviour config — overridable via -ConfigFile JSON
$script:RunConfig = @{
    Sites = @()
}

if ($ConfigFile) {
    if (!(Test-Path $ConfigFile)) {
        Write-Host "Config file not found: $ConfigFile" -ForegroundColor Red
        if ($script:NonInteractive) { exit 2 } else { return }
    }
    try {
        $userConfig = Get-Content $ConfigFile -Raw | ConvertFrom-Json -AsHashtable
        if ($userConfig.ContainsKey('Sites')) { $script:RunConfig.Sites = @($userConfig.Sites) }
        Write-Host "Loaded config from $ConfigFile" -ForegroundColor Gray
    }
    catch {
        Write-Host "Failed to parse config file: $($_.Exception.Message)" -ForegroundColor Red
        if ($script:NonInteractive) { exit 2 } else { return }
    }
}

$RequiredModules = @('Microsoft.Online.SharePoint.PowerShell')

$SiteTemplates = @{
    'TeamSite' = @{
        DisplayName = 'Team Site'
        Description = 'Collaborative workspace for a team or project'
        Template    = 'STS#3'
    }
    'CommunicationSite' = @{
        DisplayName = 'Communication Site'
        Description = 'Broadcast site for sharing news and content broadly'
        Template    = 'SITEPAGEPUBLISHING#0'
    }
}

# NOTE: New-SPOSite no longer accepts -StorageQuotaWarningLevel (confirmed
# live and against current Microsoft docs — the storage-quota-warning
# feature was retired), so only the quota itself is configurable.
$StorageQuotaMB = 1024

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Initialize-ScriptModules {
    Write-Host "   Checking required modules..." -ForegroundColor Yellow

    try {
        foreach ($Module in $RequiredModules) {
            try {
                if (!(Get-Module -ListAvailable -Name $Module)) {
                    Write-Host "   Installing $Module..." -ForegroundColor Yellow
                    Install-Module $Module -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
                }
                if (!(Get-Module -Name $Module)) {
                    Import-Module $Module -Force -ErrorAction Stop
                }
                Write-Host "   $Module ready" -ForegroundColor Green
            }
            catch {
                Write-Host "   Failed to initialize ${Module}: $($_.Exception.Message)" -ForegroundColor Red
                return $false
            }
        }
        Write-Host "   All modules ready!" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "   Module initialization error: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ============================================================================
# PREREQUISITES
# ============================================================================

function Test-Prerequisites {
    Write-Host ""
    Write-Host "   PREREQUISITES CHECK" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    Write-Host "   Checking SharePoint Online connection..." -ForegroundColor Gray
    try {
        $null = Get-SPOTenant -ErrorAction Stop
        Write-Host "   SharePoint Online connection verified" -ForegroundColor Green
    }
    catch {
        Write-Host "   Not connected to SharePoint Online" -ForegroundColor Red
        Write-Host "   Please connect using the main menu first" -ForegroundColor Yellow
        return @{ Success = $false }
    }

    # Detect tenant root URL from existing sites
    Write-Host "   Detecting tenant URL..." -ForegroundColor Gray
    try {
        $sampleSites = Get-SPOSite -Limit 5 -ErrorAction Stop
        $sampleSite  = $sampleSites | Where-Object { $_.Url -notlike '*-my.sharepoint.com*' } | Select-Object -First 1

        $tenantRootUrl = if ($null -ne $sampleSite) {
            $sampleSite.Url -replace '(https://[^/]+).*', '$1'
        }
        else {
            Write-Host "   Could not auto-detect tenant URL" -ForegroundColor Yellow
            $tenantName = Read-Host "   Enter your tenant name (e.g. 'contoso' for contoso.sharepoint.com)"
            "https://$tenantName.sharepoint.com"
        }

        Write-Host "   Tenant root URL: $tenantRootUrl" -ForegroundColor Green
    }
    catch {
        Write-Host "   Failed to detect tenant URL: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false }
    }

    Write-Host ""
    return @{
        Success       = $true
        TenantRootUrl = $tenantRootUrl
    }
}

# ============================================================================
# SITE DEFINITION COLLECTION
# ============================================================================

function Get-SiteDefinitions {
    param([string]$TenantRootUrl)

    $siteList = @()
    $addMore  = $true

    while ($addMore) {
        Write-Host ""
        Write-Host ("   " + "-" * 50) -ForegroundColor Gray
        Write-Host "   New Site Definition" -ForegroundColor White
        Write-Host ""

        # Title
        $title = Read-Host "   Site title (required)"
        if ([string]::IsNullOrWhiteSpace($title)) {
            Write-Host "   Title is required - skipping" -ForegroundColor Yellow
        }
        else {
            # Site type
            Write-Host ""
            Write-Host "   Site type:" -ForegroundColor White
            Write-Host "   1. Team Site          - $($SiteTemplates.TeamSite.Description)" -ForegroundColor Gray
            Write-Host "   2. Communication Site - $($SiteTemplates.CommunicationSite.Description)" -ForegroundColor Gray
            $typeChoice = Read-Host "   Selection (1 or 2)"

            $siteType = switch ($typeChoice) {
                '2'     { 'CommunicationSite' }
                default { 'TeamSite' }
            }

            # URL alias
            $suggestedAlias = ($title -replace '[^a-zA-Z0-9]', '-' -replace '-+', '-').Trim('-').ToLower()
            Write-Host ""
            Write-Host "   Suggested URL: $TenantRootUrl/sites/$suggestedAlias" -ForegroundColor Gray
            $aliasInput = Read-Host "   URL alias (Enter to accept, or type a different alias)"
            $urlAlias = if ([string]::IsNullOrWhiteSpace($aliasInput)) {
                $suggestedAlias
            }
            else {
                ($aliasInput.Trim() -replace '[^a-zA-Z0-9\-]', '').Trim('-').ToLower()
            }

            # Description
            Write-Host ""
            $description = Read-Host "   Description (optional, Enter to skip)"

            # Owner UPN
            Write-Host ""
            $owner = Read-Host "   Site owner UPN (e.g. admin@contoso.com)"
            if ([string]::IsNullOrWhiteSpace($owner)) {
                Write-Host "   Owner is required - skipping this site" -ForegroundColor Yellow
                $owner = $null
            }

            if ($null -ne $owner) {
                $siteList += @{
                    Title       = $title
                    Type        = $siteType
                    UrlAlias    = $urlAlias
                    FullUrl     = "$TenantRootUrl/sites/$urlAlias"
                    Description = $description
                    Owner       = $owner
                }
                Write-Host "   Site added to list" -ForegroundColor Green
            }
        }

        Write-Host ""
        $moreAnswer = Read-Host "   Add another site? (Y/N)"
        $addMore    = $moreAnswer -like "Y*"
    }

    return $siteList
}

# ============================================================================
# PREVIEW
# ============================================================================

function Show-SitePreview {
    param([array]$Sites)

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  PREVIEW: Sites to Create" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  The following $($Sites.Count) site(s) will be created:" -ForegroundColor White
    Write-Host ""
    Write-Host "  # | Title                     | Type              | Owner" -ForegroundColor Yellow
    Write-Host "  --|---------------------------|-------------------|------------------------------" -ForegroundColor Gray

    $index = 1
    foreach ($site in $Sites) {
        $titleDisplay = $site.Title
        if ($titleDisplay.Length -gt 25) { $titleDisplay = $titleDisplay.Substring(0, 22) + "..." }

        $typeDisplay = $SiteTemplates[$site.Type].DisplayName
        if ($typeDisplay.Length -gt 17) { $typeDisplay = $typeDisplay.Substring(0, 14) + "..." }

        $ownerDisplay = $site.Owner
        if ($ownerDisplay.Length -gt 30) { $ownerDisplay = $ownerDisplay.Substring(0, 27) + "..." }

        Write-Host ("  {0,2} | {1,-27}| {2,-19}| {3}" -f $index, $titleDisplay, $typeDisplay, $ownerDisplay) -ForegroundColor White
        $index++
    }

    Write-Host ""
    Write-Host "  Full URLs:" -ForegroundColor Yellow
    foreach ($site in $Sites) {
        Write-Host "    $($site.Title): $($site.FullUrl)" -ForegroundColor Gray
    }
    Write-Host ""
}

# ============================================================================
# SITE CREATION
# ============================================================================

function New-SharePointSite {
    param([hashtable]$SiteDefinition)

    $template = $SiteTemplates[$SiteDefinition.Type]

    try {
        # Check if site already exists
        $existing = Get-SPOSite -Identity $SiteDefinition.FullUrl -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Write-Host "     Already exists (skipped)" -ForegroundColor Yellow
            return @{ Success = $true; Skipped = $true }
        }

        # $null = : any pipeline output here would corrupt this function's
        # hashtable return value (strict mode then crashes on .Success — same
        # class of bug confirmed live with Add-SPOUser in Site-Groups.ps1).
        $null = New-SPOSite `
            -Url          $SiteDefinition.FullUrl `
            -Owner        $SiteDefinition.Owner `
            -StorageQuota $StorageQuotaMB `
            -Template     $template.Template `
            -Title        $SiteDefinition.Title `
            -ErrorAction  Stop

        Write-Host "     Created: $($SiteDefinition.FullUrl)" -ForegroundColor Green
        return @{ Success = $true; Skipped = $false }
    }
    catch {
        Write-Host "     Failed: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Write-Result-File {
    param([hashtable]$Result)
    if (!$ResultPath) { return }
    $Result | ConvertTo-Json -Depth 10 | Set-Content -Path $ResultPath -Encoding UTF8
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-SiteCreation {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  SHAREPOINT SITE CREATION" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Creates Team Sites and Communication Sites in SharePoint Online" -ForegroundColor Gray
    Write-Host ""

    # Step 1: Prerequisites
    Write-Host "  STEP 1: Prerequisites" -ForegroundColor Yellow
    $prereqResult = Test-Prerequisites

    if (!$prereqResult.Success) {
        Write-Host ""
        Write-Host "  Prerequisites not met. Please resolve issues and try again." -ForegroundColor Red
        Write-Host ""
        Write-Result-File -Result @{ Success = $false; Error = "Prerequisites not met" }
        if ($script:NonInteractive) { return }
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    # Step 2: Collect site definitions
    Write-Host ""
    Write-Host "  STEP 2: Define Sites" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    if ($script:NonInteractive) {
        $siteList = @(foreach ($siteConfig in $script:RunConfig.Sites) {
            $urlAlias = if ($siteConfig.ContainsKey('UrlAlias') -and $siteConfig.UrlAlias) {
                $siteConfig.UrlAlias
            }
            else {
                ($siteConfig.Title -replace '[^a-zA-Z0-9]', '-' -replace '-+', '-').Trim('-').ToLower()
            }
            @{
                Title       = $siteConfig.Title
                Type        = $siteConfig.Type
                UrlAlias    = $urlAlias
                FullUrl     = "$($prereqResult.TenantRootUrl)/sites/$urlAlias"
                Description = if ($siteConfig.ContainsKey('Description')) { $siteConfig.Description } else { '' }
                Owner       = $siteConfig.Owner
            }
        })
        Write-Host "   Loaded $($siteList.Count) site definition(s) from config" -ForegroundColor Green
    }
    else {
        Write-Host "   Enter the details for each site to create." -ForegroundColor Gray
        Write-Host "   You will be shown a preview before anything is created." -ForegroundColor Gray
        $siteList = Get-SiteDefinitions -TenantRootUrl $prereqResult.TenantRootUrl
    }

    if ($siteList.Count -eq 0) {
        Write-Host ""
        Write-Host "  No sites defined. Exiting." -ForegroundColor Yellow
        Write-Host ""
        Write-Result-File -Result @{ Success = $false; Error = "No sites defined" }
        if ($script:NonInteractive) { return }
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    # Step 3: Preview
    Write-Host ""
    Write-Host "  STEP 3: Preview" -ForegroundColor Yellow
    Show-SitePreview -Sites $siteList

    # Confirmation
    if (!$script:NonInteractive) {
        Write-Host "  [Y] Create sites  [N] Cancel" -ForegroundColor Gray
        Write-Host ""
        $confirm = Read-Host "  Create these sites? (Y/N)"

        if ($confirm -notlike "Y*") {
            Write-Host ""
            Write-Host "  Cancelled by user" -ForegroundColor Yellow
            Write-Host ""
            Write-Result-File -Result @{ Success = $false; Error = "Cancelled by user" }
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
            return
        }
    }

    # Step 4: Create sites
    Write-Host ""
    Write-Host "  STEP 4: Creating Sites" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    $results = @{
        Created = @()
        Skipped = @()
        Failed  = @()
    }

    $siteIndex = 0
    foreach ($site in $siteList) {
        $siteIndex++
        Write-Host "   [$siteIndex/$($siteList.Count)] $($site.Title)..." -ForegroundColor White
        $result = New-SharePointSite -SiteDefinition $site

        if ($result.Success) {
            if ($result.Skipped) {
                $results.Skipped += @{ Name = $site.Title; Url = $site.FullUrl }
            }
            else {
                $results.Created += @{ Name = $site.Title; Url = $site.FullUrl }
            }
        }
        else {
            $results.Failed += @{ Name = $site.Title; Url = $site.FullUrl; Error = $result.Error }
        }

        if ($siteIndex -lt $siteList.Count) {
            Start-Sleep -Milliseconds 1000
        }
    }

    # Summary
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  Created:            $($results.Created.Count)" -ForegroundColor Green
    Write-Host "  Skipped (existing): $($results.Skipped.Count)" -ForegroundColor Yellow
    Write-Host "  Failed:             $($results.Failed.Count)" -ForegroundColor $(if ($results.Failed.Count -gt 0) { "Red" } else { "Green" })
    Write-Host ""

    if ($results.Created.Count -gt 0) {
        Write-Host "  Created Sites:" -ForegroundColor Green
        foreach ($item in $results.Created) {
            Write-Host "    - $($item.Name)" -ForegroundColor White
            Write-Host "      $($item.Url)" -ForegroundColor Gray
        }
        Write-Host ""
    }

    if ($results.Skipped.Count -gt 0) {
        Write-Host "  Skipped (already exist):" -ForegroundColor Yellow
        foreach ($item in $results.Skipped) {
            Write-Host "    - $($item.Name)" -ForegroundColor Gray
        }
        Write-Host ""
    }

    if ($results.Failed.Count -gt 0) {
        Write-Host "  Failed:" -ForegroundColor Red
        foreach ($fail in $results.Failed) {
            Write-Host "    - $($fail.Name): $($fail.Error)" -ForegroundColor Red
        }
        Write-Host ""
    }

    Write-Host "  IMPORTANT:" -ForegroundColor Yellow
    Write-Host "    - Team sites may take 2-5 minutes to fully provision" -ForegroundColor Gray
    Write-Host "    - Communication sites may take up to 2 minutes to provision" -ForegroundColor Gray
    Write-Host "    - Site URLs cannot be changed after creation" -ForegroundColor Gray
    Write-Host "    - Default storage quota: 1 GB per site" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  Next Steps:" -ForegroundColor Yellow
    Write-Host "    1. Run Permission-Groups script to verify group setup on new sites" -ForegroundColor Gray
    Write-Host "    2. Run External-Sharing script to configure sharing policies" -ForegroundColor Gray
    Write-Host "    3. Add site members via SharePoint admin centre or site settings" -ForegroundColor Gray
    Write-Host "    4. Visit https://admin.sharepoint.com for additional configuration" -ForegroundColor Gray
    Write-Host ""

    Write-Result-File -Result @{
        Success = ($results.Failed.Count -eq 0)
        Created = @($results.Created | ForEach-Object { $_.Name })
        Skipped = @($results.Skipped | ForEach-Object { $_.Name })
        Failed  = $results.Failed
    }

    if ($script:NonInteractive) { return }
    Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
    try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
}

# ============================================================================
# ENTRY POINT
# ============================================================================

try {
    if (!(Initialize-ScriptModules)) {
        Write-Host "Failed to initialize required modules. Exiting." -ForegroundColor Red
        Write-Result-File -Result @{ Success = $false; Error = "Failed to initialize required modules" }
        if ($script:NonInteractive) { exit 1 } else { return }
    }

    Start-SiteCreation
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Result-File -Result @{ Success = $false; Error = $_.Exception.Message }
    if ($script:NonInteractive) { exit 1 }
}
