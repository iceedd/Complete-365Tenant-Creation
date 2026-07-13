#Requires -Version 7.0

<#
.SYNOPSIS
    Configures SharePoint Online external sharing settings
.DESCRIPTION
    Configures tenant-level external sharing policies with multiple
    options: Disabled, Existing Guests Only, New and Existing Guests, Anyone.
    Also configures guest expiration and default link settings.
.AUTHOR
    BITS
.VERSION
    2.1 - Implemented with multiple sharing options and preview mode. Adds
          non-interactive mode (-NonInteractive/-ConfigFile) for unattended
          E2E testing.
.PARAMETER NonInteractive
    Run unattended: skip preset/menu selection, all prompts, and "press any
    key" pauses, applying exactly the settings in -ConfigFile (always
    routed through the "custom" path, bypassing presets). Used by CI E2E
    tests.
.PARAMETER ConfigFile
    Required in non-interactive mode. JSON file with (all optional — omit a
    key, or set it to null, to keep the tenant's current value for that
    setting):
      SharingLevel: one of Disabled, ExistingExternalUserSharingOnly,
        ExternalUserSharingOnly, ExternalUserAndGuestSharing
      GuestExpirationEnabled (bool), GuestExpirationDays (int)
      DefaultLinkType: one of Internal, Direct, AnonymousAccess
      DefaultLinkPermission: one of View, Edit
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

# Run-behaviour config — overridable via -ConfigFile JSON. $null for any
# key means "keep the tenant's current value for that setting".
$script:RunConfig = @{
    SharingLevel           = $null
    GuestExpirationEnabled = $null
    GuestExpirationDays    = $null
    DefaultLinkType        = $null
    DefaultLinkPermission  = $null
}

if ($ConfigFile) {
    if (!(Test-Path $ConfigFile)) {
        Write-Host "Config file not found: $ConfigFile" -ForegroundColor Red
        if ($script:NonInteractive) { exit 2 } else { return }
    }
    try {
        $userConfig = Get-Content $ConfigFile -Raw | ConvertFrom-Json -AsHashtable
        foreach ($key in @($script:RunConfig.Keys)) {
            if ($userConfig.ContainsKey($key)) { $script:RunConfig[$key] = $userConfig[$key] }
        }
        Write-Host "Loaded config from $ConfigFile" -ForegroundColor Gray
    }
    catch {
        Write-Host "Failed to parse config file: $($_.Exception.Message)" -ForegroundColor Red
        if ($script:NonInteractive) { exit 2 } else { return }
    }
}

$RequiredModules = @(
    'Microsoft.Online.SharePoint.PowerShell'
)

# Sharing levels (from most restrictive to most permissive)
$SharingLevels = @{
    "Disabled" = @{
        DisplayName = "Disabled (Internal Only)"
        Description = "No external sharing - only people in your organization"
        SharingCapability = "Disabled"
        Order = 1
    }
    "ExistingExternalUserSharingOnly" = @{
        DisplayName = "Existing Guests Only"
        Description = "Share only with guests already in your directory"
        SharingCapability = "ExistingExternalUserSharingOnly"
        Order = 2
    }
    "ExternalUserSharingOnly" = @{
        DisplayName = "New and Existing Guests"
        Description = "External users must authenticate (sign in)"
        SharingCapability = "ExternalUserSharingOnly"
        Order = 3
    }
    "ExternalUserAndGuestSharing" = @{
        DisplayName = "Anyone (Most Permissive)"
        Description = "Anyone with the link, including anonymous users"
        SharingCapability = "ExternalUserAndGuestSharing"
        Order = 4
    }
}

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

    # Check SharePoint connection
    Write-Host "   Checking SharePoint Online connection..." -ForegroundColor Gray

    try {
        $spoTenant = Get-SPOTenant -ErrorAction Stop
        Write-Host "   Connected to SharePoint Online" -ForegroundColor Green

        $currentSharing = $spoTenant.SharingCapability
        $currentDomainRestriction = $spoTenant.SharingDomainRestrictionMode
        $guestExpiration = $spoTenant.ExternalUserExpirationRequired
        $guestExpirationDays = $spoTenant.ExternalUserExpireInDays
        $defaultLinkType = $spoTenant.DefaultSharingLinkType
        $defaultLinkPermission = $spoTenant.DefaultLinkPermission

        Write-Host "   Current sharing level: $currentSharing" -ForegroundColor Gray

        Write-Host ""
        return @{
            Success = $true
            CurrentSharing = $currentSharing
            DomainRestriction = $currentDomainRestriction
            GuestExpiration = $guestExpiration
            GuestExpirationDays = $guestExpirationDays
            DefaultLinkType = $defaultLinkType
            DefaultLinkPermission = $defaultLinkPermission
            TenantConfig = $spoTenant
        }
    }
    catch {
        Write-Host "   Not connected to SharePoint Online" -ForegroundColor Red
        Write-Host ""
        Write-Host "   Please connect first using:" -ForegroundColor Yellow
        Write-Host "   Connect-SPOService -Url https://[tenant]-admin.sharepoint.com" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "   Replace [tenant] with your tenant name (e.g., contoso-admin.sharepoint.com)" -ForegroundColor Gray

        # Try to get admin URL from Graph context if available
        try {
            $context = Get-MgContext -ErrorAction SilentlyContinue
            if ($context) {
                $tenantDomain = $context.TenantId
                Write-Host ""
                Write-Host "   Detected tenant: $tenantDomain" -ForegroundColor Gray
            }
        }
        catch {}

        return @{ Success = $false }
    }
}

# ============================================================================
# SHARING LEVEL SELECTION
# ============================================================================

function Show-SharingOptions {
    param(
        [string]$CurrentLevel
    )

    Write-Host ""
    Write-Host "  Available Sharing Levels:" -ForegroundColor Yellow
    Write-Host ("  " + "-" * 60) -ForegroundColor Gray
    Write-Host ""

    $sortedLevels = $SharingLevels.GetEnumerator() | Sort-Object { $_.Value.Order }
    $index = 1

    foreach ($level in $sortedLevels) {
        $current = ""
        if ($CurrentLevel -eq $level.Key) {
            $current = " [CURRENT]"
            $color = "Green"
        }
        else {
            $color = "White"
        }

        Write-Host ("  {0}. {1}{2}" -f $index, $level.Value.DisplayName, $current) -ForegroundColor $color
        Write-Host ("     {0}" -f $level.Value.Description) -ForegroundColor Gray
        Write-Host ""
        $index++
    }

    Write-Host "  Security Recommendations:" -ForegroundColor Yellow
    Write-Host "    - 'Existing Guests Only' is recommended for most organizations" -ForegroundColor Gray
    Write-Host "    - 'New and Existing Guests' allows controlled external collaboration" -ForegroundColor Gray
    Write-Host "    - 'Anyone' links should be avoided unless absolutely necessary" -ForegroundColor Gray
    Write-Host "    - 'Disabled' for highly sensitive environments only" -ForegroundColor Gray
    Write-Host ""
}

function Get-UserSharingChoice {
    param([string]$CurrentLevel)

    $sortedLevels = $SharingLevels.GetEnumerator() | Sort-Object { $_.Value.Order }
    $levelList = @($sortedLevels)

    Write-Host "  Enter your choice (1-4) or 'K' to keep current setting:" -ForegroundColor Gray
    $choice = Read-Host "  Selection"

    if ($choice -like "K*" -or [string]::IsNullOrWhiteSpace($choice)) {
        return @{ Keep = $true; Level = $CurrentLevel }
    }

    $choiceNum = 0
    if ([int]::TryParse($choice, [ref]$choiceNum)) {
        if ($choiceNum -ge 1 -and $choiceNum -le 4) {
            $selectedLevel = $levelList[$choiceNum - 1]
            return @{ Keep = $false; Level = $selectedLevel.Key; Config = $selectedLevel.Value }
        }
    }

    Write-Host "  Invalid selection, keeping current setting" -ForegroundColor Yellow
    return @{ Keep = $true; Level = $CurrentLevel }
}

# ============================================================================
# ADDITIONAL OPTIONS
# ============================================================================

function Get-GuestExpirationChoice {
    param(
        [bool]$CurrentEnabled,
        [int]$CurrentDays
    )

    Write-Host ""
    Write-Host "  Guest Expiration Settings:" -ForegroundColor Yellow
    Write-Host ("  " + "-" * 60) -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Current: $(if ($CurrentEnabled) { "Enabled - $CurrentDays days" } else { "Disabled" })" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Options:" -ForegroundColor White
    Write-Host "    1. Enable - 30 days (Recommended for security)" -ForegroundColor Gray
    Write-Host "    2. Enable - 60 days" -ForegroundColor Gray
    Write-Host "    3. Enable - 90 days" -ForegroundColor Gray
    Write-Host "    4. Disable (guests never expire)" -ForegroundColor Gray
    Write-Host "    K. Keep current setting" -ForegroundColor Gray
    Write-Host ""

    $choice = Read-Host "  Selection"

    switch -Wildcard ($choice) {
        "1" { return @{ Enabled = $true; Days = 30 } }
        "2" { return @{ Enabled = $true; Days = 60 } }
        "3" { return @{ Enabled = $true; Days = 90 } }
        "4" { return @{ Enabled = $false; Days = 0 } }
        default { return @{ Keep = $true; Enabled = $CurrentEnabled; Days = $CurrentDays } }
    }
}

function Get-DefaultLinkTypeChoice {
    param([string]$CurrentType)

    Write-Host ""
    Write-Host "  Default Sharing Link Type:" -ForegroundColor Yellow
    Write-Host ("  " + "-" * 60) -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Current: $CurrentType" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Options:" -ForegroundColor White
    Write-Host "    1. Internal - Only people in your organization (Recommended)" -ForegroundColor Gray
    Write-Host "    2. Direct - Specific people only" -ForegroundColor Gray
    Write-Host "    3. AnonymousAccess - Anyone with the link (if enabled)" -ForegroundColor Gray
    Write-Host "    K. Keep current setting" -ForegroundColor Gray
    Write-Host ""

    $choice = Read-Host "  Selection"

    switch -Wildcard ($choice) {
        "1" { return @{ Type = "Internal" } }
        "2" { return @{ Type = "Direct" } }
        "3" { return @{ Type = "AnonymousAccess" } }
        default { return @{ Keep = $true; Type = $CurrentType } }
    }
}

function Get-DefaultLinkPermissionChoice {
    param([string]$CurrentPermission)

    Write-Host ""
    Write-Host "  Default Link Permission:" -ForegroundColor Yellow
    Write-Host ("  " + "-" * 60) -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Current: $CurrentPermission" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Options:" -ForegroundColor White
    Write-Host "    1. View - Read-only access (Recommended)" -ForegroundColor Gray
    Write-Host "    2. Edit - Full edit access" -ForegroundColor Gray
    Write-Host "    K. Keep current setting" -ForegroundColor Gray
    Write-Host ""

    $choice = Read-Host "  Selection"

    switch -Wildcard ($choice) {
        "1" { return @{ Permission = "View" } }
        "2" { return @{ Permission = "Edit" } }
        default { return @{ Keep = $true; Permission = $CurrentPermission } }
    }
}

# ============================================================================
# PREVIEW AND APPLY
# ============================================================================

function Show-ConfigurationPreview {
    param(
        [hashtable]$SharingChoice,
        [hashtable]$ExpirationChoice,
        [hashtable]$LinkTypeChoice,
        [hashtable]$LinkPermissionChoice,
        [hashtable]$CurrentConfig
    )

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  CONFIGURATION PREVIEW" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""

    # Sharing Level
    if ($SharingChoice.Keep) {
        Write-Host "  Sharing Level:      (keeping current)" -ForegroundColor Gray
    }
    else {
        $levelName = $SharingLevels[$SharingChoice.Level].DisplayName
        Write-Host "  Sharing Level:      $levelName" -ForegroundColor White
    }

    # Guest Expiration
    if ($ExpirationChoice.Keep) {
        Write-Host "  Guest Expiration:   (keeping current)" -ForegroundColor Gray
    }
    elseif ($ExpirationChoice.Enabled) {
        Write-Host "  Guest Expiration:   $($ExpirationChoice.Days) days" -ForegroundColor White
    }
    else {
        Write-Host "  Guest Expiration:   Disabled" -ForegroundColor White
    }

    # Default Link Type
    if ($LinkTypeChoice.Keep) {
        Write-Host "  Default Link Type:  (keeping current)" -ForegroundColor Gray
    }
    else {
        Write-Host "  Default Link Type:  $($LinkTypeChoice.Type)" -ForegroundColor White
    }

    # Default Permission
    if ($LinkPermissionChoice.Keep) {
        Write-Host "  Default Permission: (keeping current)" -ForegroundColor Gray
    }
    else {
        Write-Host "  Default Permission: $($LinkPermissionChoice.Permission)" -ForegroundColor White
    }

    Write-Host ""
}

function Set-SharingConfiguration {
    param(
        [hashtable]$SharingChoice,
        [hashtable]$ExpirationChoice,
        [hashtable]$LinkTypeChoice,
        [hashtable]$LinkPermissionChoice
    )

    $results = @{
        SharingLevel = $null
        GuestExpiration = $null
        LinkType = $null
        LinkPermission = $null
    }

    try {
        # Set Sharing Level
        if (!$SharingChoice.Keep) {
            Write-Host "   Setting sharing level..." -ForegroundColor Gray
            Set-SPOTenant -SharingCapability $SharingChoice.Level -ErrorAction Stop
            $levelName = $SharingLevels[$SharingChoice.Level].DisplayName
            Write-Host "     Sharing level: $levelName" -ForegroundColor Green
            $results.SharingLevel = @{ Success = $true; Value = $SharingChoice.Level }
        }
        else {
            Write-Host "   Sharing level: (unchanged)" -ForegroundColor Gray
            $results.SharingLevel = @{ Success = $true; Skipped = $true }
        }

        # Set Guest Expiration
        if (!$ExpirationChoice.Keep) {
            Write-Host "   Setting guest expiration..." -ForegroundColor Gray
            if ($ExpirationChoice.Enabled) {
                Set-SPOTenant -ExternalUserExpirationRequired $true -ExternalUserExpireInDays $ExpirationChoice.Days -ErrorAction Stop
                Write-Host "     Guest expiration: $($ExpirationChoice.Days) days" -ForegroundColor Green
            }
            else {
                Set-SPOTenant -ExternalUserExpirationRequired $false -ErrorAction Stop
                Write-Host "     Guest expiration: Disabled" -ForegroundColor Green
            }
            $results.GuestExpiration = @{ Success = $true; Value = $ExpirationChoice }
        }
        else {
            Write-Host "   Guest expiration: (unchanged)" -ForegroundColor Gray
            $results.GuestExpiration = @{ Success = $true; Skipped = $true }
        }

        # Set Default Link Type
        if (!$LinkTypeChoice.Keep) {
            Write-Host "   Setting default link type..." -ForegroundColor Gray
            Set-SPOTenant -DefaultSharingLinkType $LinkTypeChoice.Type -ErrorAction Stop
            Write-Host "     Default link type: $($LinkTypeChoice.Type)" -ForegroundColor Green
            $results.LinkType = @{ Success = $true; Value = $LinkTypeChoice.Type }
        }
        else {
            Write-Host "   Default link type: (unchanged)" -ForegroundColor Gray
            $results.LinkType = @{ Success = $true; Skipped = $true }
        }

        # Set Default Link Permission
        if (!$LinkPermissionChoice.Keep) {
            Write-Host "   Setting default link permission..." -ForegroundColor Gray
            Set-SPOTenant -DefaultLinkPermission $LinkPermissionChoice.Permission -ErrorAction Stop
            Write-Host "     Default permission: $($LinkPermissionChoice.Permission)" -ForegroundColor Green
            $results.LinkPermission = @{ Success = $true; Value = $LinkPermissionChoice.Permission }
        }
        else {
            Write-Host "   Default link permission: (unchanged)" -ForegroundColor Gray
            $results.LinkPermission = @{ Success = $true; Skipped = $true }
        }

        return @{ Success = $true; Results = $results }
    }
    catch {
        Write-Host "   Failed: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; Error = $_.Exception.Message; Results = $results }
    }
}

# ============================================================================
# QUICK PRESETS
# ============================================================================

function Show-QuickPresets {
    Write-Host ""
    Write-Host "  Quick Configuration Presets:" -ForegroundColor Yellow
    Write-Host ("  " + "-" * 60) -ForegroundColor Gray
    Write-Host ""
    Write-Host "  1. Secure Default (Recommended)" -ForegroundColor Cyan
    Write-Host "     - Sharing: Existing Guests Only" -ForegroundColor Gray
    Write-Host "     - Guest Expiration: 30 days" -ForegroundColor Gray
    Write-Host "     - Default Link: Internal" -ForegroundColor Gray
    Write-Host "     - Default Permission: View" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  2. Collaboration Enabled" -ForegroundColor Cyan
    Write-Host "     - Sharing: New and Existing Guests" -ForegroundColor Gray
    Write-Host "     - Guest Expiration: 60 days" -ForegroundColor Gray
    Write-Host "     - Default Link: Direct" -ForegroundColor Gray
    Write-Host "     - Default Permission: View" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  3. Internal Only (Most Restrictive)" -ForegroundColor Cyan
    Write-Host "     - Sharing: Disabled" -ForegroundColor Gray
    Write-Host "     - Guest Expiration: N/A" -ForegroundColor Gray
    Write-Host "     - Default Link: Internal" -ForegroundColor Gray
    Write-Host "     - Default Permission: View" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  4. Custom Configuration" -ForegroundColor Cyan
    Write-Host "     - Choose each setting individually" -ForegroundColor Gray
    Write-Host ""
}

function Get-PresetConfiguration {
    param([int]$PresetNumber)

    switch ($PresetNumber) {
        1 {
            return @{
                Sharing = @{ Keep = $false; Level = "ExistingExternalUserSharingOnly" }
                Expiration = @{ Keep = $false; Enabled = $true; Days = 30 }
                LinkType = @{ Keep = $false; Type = "Internal" }
                LinkPermission = @{ Keep = $false; Permission = "View" }
            }
        }
        2 {
            return @{
                Sharing = @{ Keep = $false; Level = "ExternalUserSharingOnly" }
                Expiration = @{ Keep = $false; Enabled = $true; Days = 60 }
                LinkType = @{ Keep = $false; Type = "Direct" }
                LinkPermission = @{ Keep = $false; Permission = "View" }
            }
        }
        3 {
            return @{
                Sharing = @{ Keep = $false; Level = "Disabled" }
                Expiration = @{ Keep = $true; Enabled = $false; Days = 0 }
                LinkType = @{ Keep = $false; Type = "Internal" }
                LinkPermission = @{ Keep = $false; Permission = "View" }
            }
        }
        default {
            return $null
        }
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-ExternalSharing {
    # Header
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  SHAREPOINT EXTERNAL SHARING CONFIGURATION" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Configure tenant-level sharing policies and guest access" -ForegroundColor Gray
    Write-Host ""

    # Step 1: Prerequisites
    Write-Host "  STEP 1: Prerequisites" -ForegroundColor Yellow
    $prereqResult = Test-Prerequisites

    if (!$prereqResult.Success) {
        Write-Host ""
        Write-Host "  Prerequisites not met. Please connect and try again." -ForegroundColor Red
        Write-Host ""
        Write-Result-File -Result @{ Success = $false; Error = "Prerequisites not met" }
        if ($script:NonInteractive) { return }
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    # Step 2: Show current config and presets
    Write-Host ""
    Write-Host "  STEP 2: Current Configuration" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Current Settings:" -ForegroundColor White
    Write-Host "    Sharing Level:      $($prereqResult.CurrentSharing)" -ForegroundColor Gray
    Write-Host "    Guest Expiration:   $(if ($prereqResult.GuestExpiration) { "$($prereqResult.GuestExpirationDays) days" } else { "Disabled" })" -ForegroundColor Gray
    Write-Host "    Default Link Type:  $($prereqResult.DefaultLinkType)" -ForegroundColor Gray
    Write-Host "    Default Permission: $($prereqResult.DefaultLinkPermission)" -ForegroundColor Gray

    if ($script:NonInteractive) {
        # Always routed through the "custom" shape, built directly from
        # config — a $null value in any key means "keep the tenant's
        # current value", matching the interactive Get-*Choice functions'
        # own "Keep" convention.
        Write-Host ""
        Write-Host "  STEP 3: Custom Configuration (non-interactive)" -ForegroundColor Yellow

        $sharingChoice = if ($null -ne $script:RunConfig.SharingLevel) {
            @{ Keep = $false; Level = $script:RunConfig.SharingLevel }
        } else {
            @{ Keep = $true; Level = $prereqResult.CurrentSharing }
        }

        $expirationChoice = if ($null -ne $script:RunConfig.GuestExpirationEnabled) {
            @{ Keep = $false; Enabled = $script:RunConfig.GuestExpirationEnabled; Days = $script:RunConfig.GuestExpirationDays }
        } else {
            @{ Keep = $true; Enabled = $prereqResult.GuestExpiration; Days = $prereqResult.GuestExpirationDays }
        }

        $linkTypeChoice = if ($script:RunConfig.DefaultLinkType) {
            @{ Keep = $false; Type = $script:RunConfig.DefaultLinkType }
        } else {
            @{ Keep = $true; Type = $prereqResult.DefaultLinkType }
        }

        $linkPermissionChoice = if ($script:RunConfig.DefaultLinkPermission) {
            @{ Keep = $false; Permission = $script:RunConfig.DefaultLinkPermission }
        } else {
            @{ Keep = $true; Permission = $prereqResult.DefaultLinkPermission }
        }
    }
    else {
        Show-QuickPresets

        Write-Host "  Select a preset (1-4) or 'Q' to quit:" -ForegroundColor Gray
        $presetChoice = Read-Host "  Selection"

        if ($presetChoice -like "Q*") {
            Write-Host ""
            Write-Host "  Cancelled by user" -ForegroundColor Yellow
            Write-Host ""
            Write-Result-File -Result @{ Success = $false; Error = "Cancelled by user" }
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
            return
        }

        $presetNum = 0
        if (![int]::TryParse($presetChoice, [ref]$presetNum) -or $presetNum -lt 1 -or $presetNum -gt 4) {
            Write-Host ""
            Write-Host "  Invalid selection. Exiting." -ForegroundColor Yellow
            Write-Host ""
            Write-Result-File -Result @{ Success = $false; Error = "Invalid preset selection" }
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
            return
        }

        # Get configuration based on preset or custom
        if ($presetNum -eq 4) {
            # Custom configuration
            Write-Host ""
            Write-Host "  STEP 3: Custom Configuration" -ForegroundColor Yellow

            Show-SharingOptions -CurrentLevel $prereqResult.CurrentSharing
            $sharingChoice = Get-UserSharingChoice -CurrentLevel $prereqResult.CurrentSharing

            $expirationChoice = Get-GuestExpirationChoice -CurrentEnabled $prereqResult.GuestExpiration -CurrentDays $prereqResult.GuestExpirationDays

            $linkTypeChoice = Get-DefaultLinkTypeChoice -CurrentType $prereqResult.DefaultLinkType

            $linkPermissionChoice = Get-DefaultLinkPermissionChoice -CurrentPermission $prereqResult.DefaultLinkPermission
        }
        else {
            # Use preset
            $preset = Get-PresetConfiguration -PresetNumber $presetNum
            $sharingChoice = $preset.Sharing
            $expirationChoice = $preset.Expiration
            $linkTypeChoice = $preset.LinkType
            $linkPermissionChoice = $preset.LinkPermission
        }
    }

    # Step 4: Preview
    Write-Host ""
    Write-Host "  STEP 4: Preview Changes" -ForegroundColor Yellow
    Show-ConfigurationPreview -SharingChoice $sharingChoice -ExpirationChoice $expirationChoice -LinkTypeChoice $linkTypeChoice -LinkPermissionChoice $linkPermissionChoice -CurrentConfig $prereqResult

    # Confirmation
    if (!$script:NonInteractive) {
        Write-Host "  [Y] Apply changes  [N] Cancel" -ForegroundColor Gray
        Write-Host ""
        $confirm = Read-Host "  Apply these settings? (Y/N)"

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

    # Step 5: Apply
    Write-Host ""
    Write-Host "  STEP 5: Applying Configuration" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    $result = Set-SharingConfiguration -SharingChoice $sharingChoice -ExpirationChoice $expirationChoice -LinkTypeChoice $linkTypeChoice -LinkPermissionChoice $linkPermissionChoice

    # Step 6: Summary
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""

    if ($result.Success) {
        Write-Host "  Configuration applied successfully!" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Applied Settings:" -ForegroundColor White

        if (!$result.Results.SharingLevel.Skipped) {
            $levelName = $SharingLevels[$sharingChoice.Level].DisplayName
            Write-Host "    Sharing Level: $levelName" -ForegroundColor Gray
        }
        if (!$result.Results.GuestExpiration.Skipped) {
            if ($expirationChoice.Enabled) {
                Write-Host "    Guest Expiration: $($expirationChoice.Days) days" -ForegroundColor Gray
            }
            else {
                Write-Host "    Guest Expiration: Disabled" -ForegroundColor Gray
            }
        }
        if (!$result.Results.LinkType.Skipped) {
            Write-Host "    Default Link Type: $($linkTypeChoice.Type)" -ForegroundColor Gray
        }
        if (!$result.Results.LinkPermission.Skipped) {
            Write-Host "    Default Permission: $($linkPermissionChoice.Permission)" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "  Configuration failed: $($result.Error)" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "  IMPORTANT:" -ForegroundColor Yellow
    Write-Host "    - Changes may take up to 24 hours to fully propagate" -ForegroundColor Gray
    Write-Host "    - Site-level settings cannot exceed tenant-level permissions" -ForegroundColor Gray
    Write-Host "    - Existing shares are not affected by these changes" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  To manage site-specific sharing:" -ForegroundColor Yellow
    Write-Host "    https://admin.microsoft.com/sharepoint?page=sharing" -ForegroundColor Cyan
    Write-Host ""

    Write-Result-File -Result @{
        Success               = $result.Success
        Error                 = $result.Error
        SharingLevel          = if (!$sharingChoice.Keep) { $sharingChoice.Level } else { $null }
        GuestExpirationDays   = if (!$expirationChoice.Keep -and $expirationChoice.Enabled) { $expirationChoice.Days } else { $null }
        DefaultLinkType       = if (!$linkTypeChoice.Keep) { $linkTypeChoice.Type } else { $null }
        DefaultLinkPermission = if (!$linkPermissionChoice.Keep) { $linkPermissionChoice.Permission } else { $null }
    }

    if ($script:NonInteractive) { return }
    Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
    try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
}

function Write-Result-File {
    param([hashtable]$Result)
    if (!$ResultPath) { return }
    $Result | ConvertTo-Json -Depth 10 | Set-Content -Path $ResultPath -Encoding UTF8
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

    Start-ExternalSharing
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Result-File -Result @{ Success = $false; Error = $_.Exception.Message }
    if ($script:NonInteractive) { exit 1 }
}
