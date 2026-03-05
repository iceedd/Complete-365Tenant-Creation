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

$RequiredModules = @('Microsoft.Online.SharePoint.PowerShell')

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

    # SPO connection
    Write-Host "   Checking SharePoint Online connection..." -ForegroundColor Gray
    try {
        $null = Get-SPOTenant -ErrorAction Stop
        Write-Host "   SharePoint Online: connected" -ForegroundColor Green
    }
    catch {
        Write-Host "   Not connected to SharePoint Online" -ForegroundColor Red
        Write-Host "   Please connect using the main menu first" -ForegroundColor Yellow
        return @{ Success = $false }
    }

    # Graph connection
    Write-Host "   Checking Microsoft Graph connection..." -ForegroundColor Gray
    $graphCtx = Get-MgContext -ErrorAction SilentlyContinue
    if ($null -eq $graphCtx) {
        Write-Host "   Not connected to Microsoft Graph" -ForegroundColor Red
        Write-Host "   Please connect using the main menu first" -ForegroundColor Yellow
        return @{ Success = $false }
    }
    Write-Host "   Microsoft Graph: connected ($($graphCtx.Account))" -ForegroundColor Green

    # Detect tenant root URL
    Write-Host "   Detecting tenant URL..." -ForegroundColor Gray
    try {
        $sample = Get-SPOSite -Limit 5 -ErrorAction Stop |
                  Where-Object { $_.Url -notlike '*-my.sharepoint.com*' } |
                  Select-Object -First 1

        $tenantRootUrl = if ($null -ne $sample) {
            $sample.Url -replace '(https://[^/]+).*', '$1'
        }
        else {
            $tenantName = Read-Host "   Enter your tenant name (e.g. 'contoso')"
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

function Get-ExistingSiteTargets {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'TenantRootUrl', Justification = 'Parameter kept for consistent API signature; sites retrieved directly via SPO')]
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
        '2' {
            $url = Read-Host "   Site URL (e.g. https://contoso.sharepoint.com/sites/marketing)"
            if ($url -match '^https://') {
                $alias = $url -replace '.*/sites/', ''
                $site  = Get-SPOSite -Identity $url -ErrorAction SilentlyContinue
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
