#Requires -Version 7.0

<#
.SYNOPSIS
    Audits and repairs SharePoint site permission groups
.DESCRIPTION
    Checks all SharePoint site collections for standard permission groups
    (Full Control / Edit / Read). Reports on group status and offers to
    create missing standard groups where needed.
.AUTHOR
    LYON Tech
.VERSION
    1.0 - Implemented permission group audit and repair
#>

# ============================================================================
# CONFIGURATION
# ============================================================================

$RequiredModules = @('Microsoft.Online.SharePoint.PowerShell')

$StandardPermissionLevels = @(
    @{ Label = 'Owners';   Level = 'Full Control'; Suffix = 'Owners'   }
    @{ Label = 'Members';  Level = 'Edit';         Suffix = 'Members'  }
    @{ Label = 'Visitors'; Level = 'Read';         Suffix = 'Visitors' }
)

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

    Write-Host ""
    return @{ Success = $true }
}

# ============================================================================
# SITE RETRIEVAL
# ============================================================================

function Get-AuditSites {
    param([string]$ScopeChoice)

    switch ($ScopeChoice) {
        '1' {
            Write-Host "   Retrieving all site collections..." -ForegroundColor Gray
            $allSites = Get-SPOSite -Limit All -ErrorAction Stop
            return @($allSites | Where-Object { $_.Url -notlike '*-my.sharepoint.com*' })
        }
        '2' {
            $specificUrl = Read-Host "   Enter site URL (e.g. https://contoso.sharepoint.com/sites/Marketing)"
            if ($specificUrl -notmatch '^https://') {
                Write-Host "   Invalid URL format" -ForegroundColor Red
                return @()
            }
            $site = Get-SPOSite -Identity $specificUrl -ErrorAction SilentlyContinue
            if ($null -eq $site) {
                Write-Host "   Site not found: $specificUrl" -ForegroundColor Red
                return @()
            }
            return @($site)
        }
        default { return @() }
    }
}

# ============================================================================
# AUDIT
# ============================================================================

function Test-SitePermissionGroups {
    param([object]$Site)

    $auditResult = @{
        Url           = $Site.Url
        Title         = $Site.Title
        OwnerGroup    = $null
        MemberGroup   = $null
        VisitorGroup  = $null
        MissingLevels = @()
        Error         = $null
    }

    try {
        $groups = Get-SPOSiteGroup -Site $Site.Url -ErrorAction Stop

        $auditResult.OwnerGroup   = $groups | Where-Object { $_.Roles -contains 'Full Control' } | Select-Object -First 1
        $auditResult.MemberGroup  = $groups | Where-Object { $_.Roles -contains 'Edit' -or $_.Roles -contains 'Contribute' } | Select-Object -First 1
        $auditResult.VisitorGroup = $groups | Where-Object { $_.Roles -contains 'Read' } | Select-Object -First 1

        if ($null -eq $auditResult.OwnerGroup)   { $auditResult.MissingLevels += 'Full Control' }
        if ($null -eq $auditResult.MemberGroup)  { $auditResult.MissingLevels += 'Edit' }
        if ($null -eq $auditResult.VisitorGroup) { $auditResult.MissingLevels += 'Read' }
    }
    catch {
        $auditResult.Error = $_.Exception.Message
    }

    return $auditResult
}

# ============================================================================
# DISPLAY
# ============================================================================

function Show-AuditTable {
    param([array]$AuditResults)

    Write-Host ""
    Write-Host "  # | Site Title                       | Owners | Members | Visitors" -ForegroundColor Yellow
    Write-Host "  --|----------------------------------|--------|---------|----------" -ForegroundColor Gray

    $index = 1
    foreach ($result in $AuditResults) {
        $title = $result.Title
        if ($title.Length -gt 34) { $title = $title.Substring(0, 31) + "..." }

        Write-Host -NoNewline ("  {0,2} | {1,-34}| " -f $index, $title)

        if ($null -ne $result.Error) {
            Write-Host "ERROR: $($result.Error)" -ForegroundColor Yellow
        }
        else {
            $ownerText   = if ($null -ne $result.OwnerGroup)   { "OK    " } else { "MISS  " }
            $memberText  = if ($null -ne $result.MemberGroup)  { "OK     " } else { "MISS   " }
            $visitorText = if ($null -ne $result.VisitorGroup) { "OK       " } else { "MISS     " }
            $ownerColor   = if ($null -ne $result.OwnerGroup)   { "Green" } else { "Red" }
            $memberColor  = if ($null -ne $result.MemberGroup)  { "Green" } else { "Red" }
            $visitorColor = if ($null -ne $result.VisitorGroup) { "Green" } else { "Red" }

            Write-Host -NoNewline $ownerText   -ForegroundColor $ownerColor
            Write-Host -NoNewline "| "
            Write-Host -NoNewline $memberText  -ForegroundColor $memberColor
            Write-Host -NoNewline "| "
            Write-Host            $visitorText -ForegroundColor $visitorColor
        }
        $index++
    }
    Write-Host ""
}

# ============================================================================
# REPAIR
# ============================================================================

function Repair-PermissionGroup {
    param(
        [string]$SiteUrl,
        [string]$SiteTitle,
        [string]$PermissionLevel,
        [string]$GroupSuffix
    )

    $groupName = "$SiteTitle $GroupSuffix"

    try {
        New-SPOSiteGroup -Site $SiteUrl -Group $groupName -PermissionLevels $PermissionLevel -ErrorAction Stop
        Write-Host "     Created: $groupName" -ForegroundColor Green
        return @{ Success = $true; GroupName = $groupName }
    }
    catch {
        Write-Host "     Failed: $groupName - $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; GroupName = $groupName; Error = $_.Exception.Message }
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-PermissionGroups {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  SHAREPOINT PERMISSION GROUPS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Audits site permission groups and repairs missing standard groups" -ForegroundColor Gray
    Write-Host ""

    # Step 1: Prerequisites
    Write-Host "  STEP 1: Prerequisites" -ForegroundColor Yellow
    $prereqResult = Test-Prerequisites

    if (!$prereqResult.Success) {
        Write-Host ""
        Write-Host "  Prerequisites not met. Please resolve issues and try again." -ForegroundColor Red
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    # Step 2: Scope selection
    Write-Host ""
    Write-Host "  STEP 2: Audit Scope" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray
    Write-Host ""
    Write-Host "   Select sites to audit:" -ForegroundColor White
    Write-Host "   1. All site collections" -ForegroundColor Gray
    Write-Host "   2. Specific site URL" -ForegroundColor Gray
    Write-Host "   Q. Cancel" -ForegroundColor Gray
    Write-Host ""
    $scopeChoice = Read-Host "   Selection"

    if ($scopeChoice -like "Q*") {
        Write-Host ""
        Write-Host "  Cancelled by user" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    if ($scopeChoice -notin @('1', '2')) {
        Write-Host ""
        Write-Host "  Invalid selection" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    # Step 3: Retrieve sites
    Write-Host ""
    Write-Host "  STEP 3: Retrieving Sites" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    try {
        $sites = Get-AuditSites -ScopeChoice $scopeChoice
    }
    catch {
        Write-Host "   Failed to retrieve sites: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    if ($sites.Count -eq 0) {
        Write-Host "   No sites found to audit" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    Write-Host "   Found $($sites.Count) site(s)" -ForegroundColor Green

    # Step 4: Audit each site
    Write-Host ""
    Write-Host "  STEP 4: Auditing Permission Groups" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    $auditResults = @()
    $siteIndex = 0
    foreach ($site in $sites) {
        $siteIndex++
        Write-Host "   [$siteIndex/$($sites.Count)] $($site.Title)..." -ForegroundColor Gray
        $auditResults += Test-SitePermissionGroups -Site $site
        if ($siteIndex -lt $sites.Count) {
            Start-Sleep -Milliseconds 300
        }
    }

    # Step 5: Results
    Write-Host ""
    Write-Host "  STEP 5: Audit Results" -ForegroundColor Yellow
    Show-AuditTable -AuditResults $auditResults

    $sitesWithIssues = @($auditResults | Where-Object { $_.MissingLevels.Count -gt 0 })
    $sitesOk         = @($auditResults | Where-Object { $_.MissingLevels.Count -eq 0 -and $null -eq $_.Error })
    $sitesErrored    = @($auditResults | Where-Object { $null -ne $_.Error })

    Write-Host "  Audit Summary:" -ForegroundColor White
    Write-Host "    Sites audited:             $($auditResults.Count)" -ForegroundColor Gray
    Write-Host "    Sites with all groups OK:  $($sitesOk.Count)" -ForegroundColor Green
    Write-Host "    Sites with missing groups: $($sitesWithIssues.Count)" -ForegroundColor $(if ($sitesWithIssues.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "    Sites with errors:         $($sitesErrored.Count)" -ForegroundColor $(if ($sitesErrored.Count -gt 0) { "Yellow" } else { "Gray" })
    Write-Host ""

    if ($sitesWithIssues.Count -eq 0) {
        Write-Host "  All sites have standard permission groups configured." -ForegroundColor Green
        Write-Host ""
        Write-Host "  Next Steps:" -ForegroundColor Yellow
        Write-Host "    1. Manage group membership in SharePoint admin centre" -ForegroundColor Gray
        Write-Host "    2. Run External-Sharing script to configure sharing policies" -ForegroundColor Gray
        Write-Host "    3. Run Site-Creation script to provision additional sites" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    # Step 6: Repair confirmation
    Write-Host "  STEP 6: Repair Missing Groups" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray
    Write-Host ""
    Write-Host "   $($sitesWithIssues.Count) site(s) have missing permission groups." -ForegroundColor Yellow
    Write-Host "   Standard groups will be created using these permission levels:" -ForegroundColor Gray
    Write-Host "     '[Site Title] Owners'   - Full Control" -ForegroundColor Gray
    Write-Host "     '[Site Title] Members'  - Edit" -ForegroundColor Gray
    Write-Host "     '[Site Title] Visitors' - Read" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [Y] Create missing groups  [N] Skip repair" -ForegroundColor Gray
    Write-Host ""
    $confirm = Read-Host "  Create missing permission groups? (Y/N)"

    if ($confirm -notlike "Y*") {
        Write-Host ""
        Write-Host "  Repair skipped" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    # Step 7: Execute repairs
    Write-Host ""
    Write-Host "  STEP 7: Creating Missing Groups" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    $repairResults = @{
        Created = @()
        Failed  = @()
    }

    foreach ($site in $sitesWithIssues) {
        Write-Host "   $($site.Title):" -ForegroundColor White

        foreach ($missingLevel in $site.MissingLevels) {
            $matchedPermission = $StandardPermissionLevels | Where-Object { $_.Level -eq $missingLevel } | Select-Object -First 1
            $suffix = if ($null -ne $matchedPermission) { $matchedPermission.Suffix } else { $missingLevel }

            $repairResult = Repair-PermissionGroup `
                -SiteUrl         $site.Url `
                -SiteTitle       $site.Title `
                -PermissionLevel $missingLevel `
                -GroupSuffix     $suffix

            if ($repairResult.Success) {
                $repairResults.Created += @{ Site = $site.Title; Group = $repairResult.GroupName }
            }
            else {
                $repairResults.Failed += @{ Site = $site.Title; Group = $repairResult.GroupName; Error = $repairResult.Error }
            }
            Start-Sleep -Milliseconds 500
        }
    }

    # Summary
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  Sites audited:   $($auditResults.Count)" -ForegroundColor White
    Write-Host "  Groups created:  $($repairResults.Created.Count)" -ForegroundColor Green
    Write-Host "  Groups failed:   $($repairResults.Failed.Count)" -ForegroundColor $(if ($repairResults.Failed.Count -gt 0) { "Red" } else { "Green" })
    Write-Host ""

    if ($repairResults.Created.Count -gt 0) {
        Write-Host "  Created Groups:" -ForegroundColor Green
        foreach ($item in $repairResults.Created) {
            Write-Host "    - $($item.Group)" -ForegroundColor White
            Write-Host "      Site: $($item.Site)" -ForegroundColor Gray
        }
        Write-Host ""
    }

    if ($repairResults.Failed.Count -gt 0) {
        Write-Host "  Failed:" -ForegroundColor Red
        foreach ($fail in $repairResults.Failed) {
            Write-Host "    - $($fail.Group): $($fail.Error)" -ForegroundColor Red
        }
        Write-Host ""
    }

    Write-Host "  IMPORTANT:" -ForegroundColor Yellow
    Write-Host "    - New groups start empty - add members via SharePoint admin centre" -ForegroundColor Gray
    Write-Host "    - Groups are site-specific and do not sync to Entra ID" -ForegroundColor Gray
    Write-Host "    - Default sites created by SharePoint rarely lose standard groups" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  Next Steps:" -ForegroundColor Yellow
    Write-Host "    1. Add members to permission groups in SharePoint admin centre" -ForegroundColor Gray
    Write-Host "    2. Configure external sharing via the External-Sharing script" -ForegroundColor Gray
    Write-Host "    3. Review site inheritance settings if subsites exist" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
    try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
}

# ============================================================================
# ENTRY POINT
# ============================================================================

try {
    if (!(Initialize-ScriptModules)) {
        Write-Host "Failed to initialize required modules. Exiting." -ForegroundColor Red
        return
    }

    Start-PermissionGroups
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
}
