#Requires -Version 7.0

<#
.SYNOPSIS
    Shared Helper Functions for Complete-365Tenant-Creation Scripts
.DESCRIPTION
    Provides standardized functions for logging, prerequisites checking,
    preview mode, execution, and summary display across all scripts.
.AUTHOR
    CB & Claude Partnership
.VERSION
    1.0
#>

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

function Write-LogMessage {
    <#
    .SYNOPSIS
        Standardized logging with emoji prefixes and color coding
    .PARAMETER Message
        The message to display
    .PARAMETER Type
        Message type: Info, Success, Warning, Error
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Type = "Info"
    )

    $color = switch ($Type) {
        "Info"    { "White" }
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error"   { "Red" }
    }

    $prefix = switch ($Type) {
        "Info"    { "   " }
        "Success" { "   " }
        "Warning" { "   " }
        "Error"   { "   " }
    }

    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Write-ScriptHeader {
    <#
    .SYNOPSIS
        Display standardized script header
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Title,

        [string]$Description = ""
    )

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan

    if ($Description) {
        Write-Host "  $Description" -ForegroundColor Gray
    }
    Write-Host ""
}

function Write-SectionHeader {
    <#
    .SYNOPSIS
        Display section divider within script
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Title
    )

    Write-Host ""
    Write-Host ("-" * 50) -ForegroundColor Gray
    Write-Host "  $Title" -ForegroundColor Yellow
    Write-Host ("-" * 50) -ForegroundColor Gray
}

# ============================================================================
# MODULE MANAGEMENT
# ============================================================================

function Initialize-RequiredModules {
    <#
    .SYNOPSIS
        Check, install, and import required PowerShell modules
    .PARAMETER Modules
        Array of module names to initialize
    .RETURNS
        $true if all modules ready, $false if any failed
    #>
    param(
        [Parameter(Mandatory)]
        [string[]]$Modules
    )

    Write-Host "   Checking required modules..." -ForegroundColor Yellow

    try {
        foreach ($Module in $Modules) {
            try {
                # Check if module is available
                $installedModule = Get-Module -ListAvailable -Name $Module |
                    Sort-Object Version -Descending |
                    Select-Object -First 1

                if (!$installedModule) {
                    Write-Host "   Installing $Module..." -ForegroundColor Yellow
                    Install-Module $Module -Force -Scope CurrentUser -AllowClobber -SkipPublisherCheck -ErrorAction Stop
                    Write-Host "   Installed $Module" -ForegroundColor Green
                }

                # Check if module is loaded
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
        Write-Host "   Module initialization failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-ModuleAvailable {
    <#
    .SYNOPSIS
        Check if a module is available (installed)
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ModuleName
    )

    return $null -ne (Get-Module -ListAvailable -Name $ModuleName)
}

# ============================================================================
# PREREQUISITES - CONNECTION & AUTHENTICATION
# ============================================================================

function Test-GraphConnection {
    <#
    .SYNOPSIS
        Test Microsoft Graph connection status
    .RETURNS
        Hashtable with Connected, Context, Organization, Error, Solution
    #>

    try {
        $context = Get-MgContext -ErrorAction Stop

        if (!$context) {
            return @{
                Connected = $false
                Error = "No Microsoft Graph connection found"
                Solution = "Please connect using: Connect-MgGraph -Scopes 'User.Read.All'"
            }
        }

        # Test actual connectivity
        $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1

        if (!$org) {
            return @{
                Connected = $false
                Error = "Connected but cannot retrieve organization info"
                Solution = "Check your permissions or reconnect"
            }
        }

        return @{
            Connected = $true
            Context = $context
            Organization = $org
            TenantId = $context.TenantId
            Account = $context.Account
            Scopes = $context.Scopes
        }
    }
    catch {
        return @{
            Connected = $false
            Error = $_.Exception.Message
            Solution = "Connect using: Connect-MgGraph -Scopes 'User.Read.All'"
        }
    }
}

function Test-RequiredScopes {
    <#
    .SYNOPSIS
        Check if current Graph session has required scopes
    .PARAMETER RequiredScopes
        Array of scope names required
    .PARAMETER AutoRequest
        If true, automatically reconnect to request missing scopes
    .RETURNS
        Hashtable with HasAllScopes, MissingScopes, CurrentScopes
    #>
    param(
        [Parameter(Mandatory)]
        [string[]]$RequiredScopes,

        [switch]$AutoRequest
    )

    $context = Get-MgContext

    if (!$context) {
        return @{
            HasAllScopes = $false
            MissingScopes = $RequiredScopes
            CurrentScopes = @()
            Error = "Not connected to Microsoft Graph"
        }
    }

    $currentScopes = $context.Scopes
    $missingScopes = $RequiredScopes | Where-Object { $_ -notin $currentScopes }

    if ($missingScopes.Count -gt 0 -and $AutoRequest) {
        Write-Host "   Requesting additional permissions..." -ForegroundColor Yellow

        try {
            $allScopes = ($currentScopes + $missingScopes) | Select-Object -Unique
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            Connect-MgGraph -Scopes $allScopes -NoWelcome -ErrorAction Stop

            # Re-check after reconnection
            $context = Get-MgContext
            $currentScopes = $context.Scopes
            $missingScopes = $RequiredScopes | Where-Object { $_ -notin $currentScopes }

            Write-Host "   Permissions updated" -ForegroundColor Green
        }
        catch {
            Write-Host "   Failed to request additional scopes: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    return @{
        HasAllScopes = ($missingScopes.Count -eq 0)
        MissingScopes = $missingScopes
        CurrentScopes = $currentScopes
    }
}

function Test-RequiredLicense {
    <#
    .SYNOPSIS
        Check if tenant has required license type
    .PARAMETER LicenseType
        Type of license to check: EntraP2, DefenderP2, BusinessPremium, E5
    .RETURNS
        Hashtable with HasLicense, LicenseName, Details
    #>
    param(
        [Parameter(Mandatory)]
        [ValidateSet("EntraP2", "DefenderP2", "BusinessPremium", "E5")]
        [string]$LicenseType
    )

    try {
        $subscribedSkus = Get-MgSubscribedSku -ErrorAction SilentlyContinue

        if (!$subscribedSkus) {
            return @{
                HasLicense = $false
                Error = "Unable to retrieve license information"
            }
        }

        $licenseSkus = switch ($LicenseType) {
            "EntraP2" {
                @("AAD_PREMIUM_P2", "ENTERPRISEPREMIUM", "SPE_E5", "EMSPREMIUM",
                  "M365EDU_A5_FACULTY", "M365EDU_A5_STUDENT", "SPB")
            }
            "DefenderP2" {
                @("DEFENDER_ENDPOINT_P2", "WIN_DEF_ATP", "ENTERPRISEPREMIUM", "SPE_E5")
            }
            "BusinessPremium" {
                @("SPB", "O365_BUSINESS_PREMIUM", "MICROSOFT_BUSINESS_PREMIUM")
            }
            "E5" {
                @("ENTERPRISEPREMIUM", "SPE_E5", "OFFICE365_E5", "M365EDU_A5_FACULTY")
            }
        }

        $foundLicense = $subscribedSkus | Where-Object { $_.SkuPartNumber -in $licenseSkus } |
            Select-Object -First 1

        return @{
            HasLicense = ($null -ne $foundLicense)
            LicenseName = if ($foundLicense) { $foundLicense.SkuPartNumber } else { $null }
            AvailableUnits = if ($foundLicense) { $foundLicense.PrepaidUnits.Enabled } else { 0 }
            ConsumedUnits = if ($foundLicense) { $foundLicense.ConsumedUnits } else { 0 }
        }
    }
    catch {
        return @{
            HasLicense = $false
            Error = $_.Exception.Message
        }
    }
}

function Test-RequiredRole {
    <#
    .SYNOPSIS
        Check if current user has required Azure AD or Purview role
    .PARAMETER RoleName
        Name of the role to check (e.g., "Global Administrator", "Compliance Administrator")
    .RETURNS
        Hashtable with HasRole, RoleAssignments
    #>
    param(
        [Parameter(Mandatory)]
        [string]$RoleName
    )

    try {
        # Get current user
        $context = Get-MgContext
        if (!$context) {
            return @{ HasRole = $false; Error = "Not connected" }
        }

        # Get role definition
        $role = Get-MgDirectoryRole -Filter "displayName eq '$RoleName'" -ErrorAction SilentlyContinue

        if (!$role) {
            # Role might not be activated, check role template
            $roleTemplate = Get-MgDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq $RoleName }
            if ($roleTemplate) {
                return @{
                    HasRole = $false
                    RoleExists = $true
                    Message = "Role '$RoleName' exists but is not activated"
                }
            }
            return @{ HasRole = $false; Error = "Role '$RoleName' not found" }
        }

        # Check if current user is member
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -ErrorAction SilentlyContinue
        $currentUserId = (Get-MgUser -UserId $context.Account -ErrorAction SilentlyContinue).Id

        $hasRole = $members.Id -contains $currentUserId

        return @{
            HasRole = $hasRole
            RoleId = $role.Id
            RoleName = $RoleName
        }
    }
    catch {
        return @{
            HasRole = $false
            Error = $_.Exception.Message
        }
    }
}

# ============================================================================
# AUTO-FIX HELPERS
# ============================================================================

function Disable-SecurityDefaultsIfEnabled {
    <#
    .SYNOPSIS
        Check and optionally disable Security Defaults (required for CA policies)
    .PARAMETER AutoFix
        If true, automatically disable without prompting
    .RETURNS
        Hashtable with WasEnabled, IsNowDisabled, Error
    #>
    param(
        [switch]$AutoFix
    )

    try {
        $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop

        if (!$securityDefaults.IsEnabled) {
            return @{
                WasEnabled = $false
                IsNowDisabled = $true
                Message = "Security Defaults already disabled"
            }
        }

        # Security Defaults is enabled
        if (!$AutoFix) {
            Write-Host ""
            Write-Host "   Security Defaults is currently ENABLED" -ForegroundColor Yellow
            Write-Host "   This must be disabled to create Conditional Access policies." -ForegroundColor Yellow
            Write-Host ""

            $response = Read-Host "   Disable Security Defaults? (Y/N)"

            if ($response -notlike "Y*") {
                return @{
                    WasEnabled = $true
                    IsNowDisabled = $false
                    Message = "User declined to disable Security Defaults"
                }
            }
        }

        # Disable Security Defaults
        Write-Host "   Disabling Security Defaults..." -ForegroundColor Yellow

        $params = @{
            IsEnabled = $false
        }

        Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -BodyParameter $params -ErrorAction Stop

        # Verify
        Start-Sleep -Seconds 2
        $verification = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop

        if (!$verification.IsEnabled) {
            Write-Host "   Security Defaults disabled successfully" -ForegroundColor Green
            return @{
                WasEnabled = $true
                IsNowDisabled = $true
                Message = "Security Defaults disabled"
            }
        }
        else {
            return @{
                WasEnabled = $true
                IsNowDisabled = $false
                Error = "Failed to verify Security Defaults was disabled"
            }
        }
    }
    catch {
        return @{
            Error = $_.Exception.Message
            WasEnabled = $null
            IsNowDisabled = $false
        }
    }
}

function Request-MissingScopes {
    <#
    .SYNOPSIS
        Reconnect to Graph with additional scopes
    .PARAMETER AdditionalScopes
        Scopes to add to current session
    #>
    param(
        [Parameter(Mandatory)]
        [string[]]$AdditionalScopes
    )

    $context = Get-MgContext
    $currentScopes = if ($context) { $context.Scopes } else { @() }
    $allScopes = ($currentScopes + $AdditionalScopes) | Select-Object -Unique

    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Connect-MgGraph -Scopes $allScopes -NoWelcome -ErrorAction Stop
        Write-Host "   Graph reconnected with expanded permissions" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "   Failed to reconnect: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ============================================================================
# PREVIEW MODE FUNCTIONS
# ============================================================================

function Show-PreviewTable {
    <#
    .SYNOPSIS
        Display a formatted preview table of items to be created
    .PARAMETER Items
        Array of objects to display
    .PARAMETER Columns
        Array of column definitions: @{Name="Display Name"; Property="PropertyName"; Width=20}
    .PARAMETER Title
        Title for the preview section
    #>
    param(
        [Parameter(Mandatory)]
        [array]$Items,

        [Parameter(Mandatory)]
        [array]$Columns,

        [string]$Title = "Items to Create"
    )

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  PREVIEW: $Title" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  The following $($Items.Count) item(s) will be created:" -ForegroundColor White
    Write-Host ""

    # Build header
    $headerLine = "  # |"
    $separatorLine = "----|"

    foreach ($col in $Columns) {
        $width = if ($col.Width) { $col.Width } else { 20 }
        $headerLine += " " + $col.Name.PadRight($width) + " |"
        $separatorLine += ("-" * ($width + 2)) + "|"
    }

    Write-Host $headerLine -ForegroundColor Yellow
    Write-Host $separatorLine -ForegroundColor Gray

    # Build rows
    $index = 1
    foreach ($item in $Items) {
        $rowLine = "  $($index.ToString().PadLeft(2)) |"

        foreach ($col in $Columns) {
            $width = if ($col.Width) { $col.Width } else { 20 }
            $value = $item.($col.Property)
            if ($null -eq $value) { $value = "-" }
            $value = $value.ToString()
            if ($value.Length -gt $width) { $value = $value.Substring(0, $width - 3) + "..." }
            $rowLine += " " + $value.PadRight($width) + " |"
        }

        Write-Host $rowLine -ForegroundColor White
        $index++
    }

    Write-Host ""
}

function Get-UserConfirmation {
    <#
    .SYNOPSIS
        Get Y/N confirmation from user with optional edit capability
    .PARAMETER Message
        Confirmation prompt message
    .PARAMETER AllowEdit
        If true, show E option to edit
    .RETURNS
        "Y", "N", or "E" for edit
    #>
    param(
        [string]$Message = "Proceed with creation?",

        [switch]$AllowEdit
    )

    Write-Host ""

    if ($AllowEdit) {
        Write-Host "  [Y] Proceed  [N] Cancel  [E] Edit list" -ForegroundColor Gray
    }
    else {
        Write-Host "  [Y] Proceed  [N] Cancel" -ForegroundColor Gray
    }

    Write-Host ""
    $response = Read-Host "  $Message (Y/N$(if($AllowEdit){'E'}))"

    if ($response -like "Y*") { return "Y" }
    if ($response -like "N*") { return "N" }
    if ($AllowEdit -and $response -like "E*") { return "E" }

    return "N"
}

function Show-EditPrompt {
    <#
    .SYNOPSIS
        Allow user to remove items from a list before creation
    .PARAMETER Items
        Array of items (must have Name or DisplayName property)
    .RETURNS
        Filtered array with removed items excluded
    #>
    param(
        [Parameter(Mandatory)]
        [array]$Items
    )

    Write-Host ""
    Write-Host "  Enter item numbers to REMOVE (comma-separated), or press Enter to keep all:" -ForegroundColor Yellow

    for ($i = 0; $i -lt $Items.Count; $i++) {
        $name = if ($Items[$i].Name) { $Items[$i].Name } else { $Items[$i].DisplayName }
        Write-Host "    $($i + 1). $name" -ForegroundColor White
    }

    Write-Host ""
    $toRemove = Read-Host "  Remove items"

    if ([string]::IsNullOrWhiteSpace($toRemove)) {
        return $Items
    }

    $removeIndices = $toRemove -split ',' | ForEach-Object {
        $num = $_.Trim() -as [int]
        if ($num -gt 0) { $num - 1 }
    }

    $filteredItems = @()
    for ($i = 0; $i -lt $Items.Count; $i++) {
        if ($i -notin $removeIndices) {
            $filteredItems += $Items[$i]
        }
    }

    Write-Host "  Kept $($filteredItems.Count) of $($Items.Count) items" -ForegroundColor Green
    return $filteredItems
}

# ============================================================================
# EXECUTION HELPERS
# ============================================================================

function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Execute a script block with retry logic and exponential backoff
    .PARAMETER ScriptBlock
        The code to execute
    .PARAMETER MaxRetries
        Maximum number of retry attempts
    .PARAMETER RetryDelaySeconds
        Initial delay between retries (doubles each retry)
    #>
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [int]$MaxRetries = 3,

        [int]$RetryDelaySeconds = 2
    )

    $attempt = 0
    $delay = $RetryDelaySeconds

    while ($attempt -lt $MaxRetries) {
        $attempt++

        try {
            return & $ScriptBlock
        }
        catch {
            if ($attempt -ge $MaxRetries) {
                throw $_
            }

            Write-Host "     Attempt $attempt failed, retrying in ${delay}s..." -ForegroundColor Yellow
            Start-Sleep -Seconds $delay
            $delay = $delay * 2
        }
    }
}

function Start-ThrottledLoop {
    <#
    .SYNOPSIS
        Process items with throttling delay to avoid API rate limits
    .PARAMETER Items
        Array of items to process
    .PARAMETER ScriptBlock
        Code to execute for each item (receives $_ as current item)
    .PARAMETER DelayMs
        Delay between items in milliseconds
    .RETURNS
        Array of results
    #>
    param(
        [Parameter(Mandatory)]
        [array]$Items,

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [int]$DelayMs = 500
    )

    $results = @()
    $index = 0

    foreach ($item in $Items) {
        $index++

        try {
            $result = & $ScriptBlock
            $results += @{
                Success = $true
                Item = $item
                Result = $result
                Index = $index
            }
        }
        catch {
            $results += @{
                Success = $false
                Item = $item
                Error = $_.Exception.Message
                Index = $index
            }
        }

        if ($index -lt $Items.Count) {
            Start-Sleep -Milliseconds $DelayMs
        }
    }

    return $results
}

# ============================================================================
# SUMMARY FUNCTIONS
# ============================================================================

function Show-ExecutionSummary {
    <#
    .SYNOPSIS
        Display standardized execution summary
    .PARAMETER Results
        Array of result hashtables with Success, Item, Result/Error properties
    .PARAMETER ItemType
        Type of items (e.g., "groups", "policies")
    #>
    param(
        [Parameter(Mandatory)]
        [array]$Results,

        [string]$ItemType = "items"
    )

    $successCount = ($Results | Where-Object { $_.Success }).Count
    $failCount = ($Results | Where-Object { -not $_.Success }).Count

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  EXECUTION SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  Total $ItemType processed: $($Results.Count)" -ForegroundColor White
    Write-Host "  Successful: $successCount" -ForegroundColor Green

    if ($failCount -gt 0) {
        Write-Host "  Failed: $failCount" -ForegroundColor Red
    }

    Write-Host ""

    # Show successful items
    if ($successCount -gt 0) {
        Write-Host "  Created:" -ForegroundColor Green
        foreach ($result in ($Results | Where-Object { $_.Success })) {
            $name = if ($result.Item.Name) { $result.Item.Name }
                    elseif ($result.Item.DisplayName) { $result.Item.DisplayName }
                    else { "Item $($result.Index)" }
            $id = if ($result.Result.Id) { " (ID: $($result.Result.Id))" } else { "" }
            Write-Host "    $name$id" -ForegroundColor White
        }
    }

    # Show failed items
    if ($failCount -gt 0) {
        Write-Host ""
        Write-Host "  Failed:" -ForegroundColor Red
        foreach ($result in ($Results | Where-Object { -not $_.Success })) {
            $name = if ($result.Item.Name) { $result.Item.Name }
                    elseif ($result.Item.DisplayName) { $result.Item.DisplayName }
                    else { "Item $($result.Index)" }
            Write-Host "    $name - $($result.Error)" -ForegroundColor Red
        }
    }

    Write-Host ""
}

function Show-NextSteps {
    <#
    .SYNOPSIS
        Display numbered list of next steps
    .PARAMETER Steps
        Array of step descriptions
    .PARAMETER Title
        Section title
    #>
    param(
        [Parameter(Mandatory)]
        [string[]]$Steps,

        [string]$Title = "Next Steps"
    )

    Write-Host "  $Title:" -ForegroundColor Yellow

    $index = 1
    foreach ($step in $Steps) {
        Write-Host "    $index. $step" -ForegroundColor Gray
        $index++
    }

    Write-Host ""
}

function Show-ImportantInfo {
    <#
    .SYNOPSIS
        Display important IDs or information for reference
    .PARAMETER Items
        Hashtable of label -> value pairs
    .PARAMETER Title
        Section title
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Items,

        [string]$Title = "Important Information"
    )

    Write-Host "  $Title:" -ForegroundColor Yellow

    foreach ($key in $Items.Keys) {
        Write-Host "    ${key}: $($Items[$key])" -ForegroundColor Gray
    }

    Write-Host ""
}

function Show-PauseBeforeExit {
    <#
    .SYNOPSIS
        Pause execution and wait for user before returning
    .PARAMETER Message
        Custom message to display
    #>
    param(
        [string]$Message = "Press any key to return to menu..."
    )

    Write-Host ""
    Write-Host "  $Message" -ForegroundColor Gray

    try {
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    catch {
        # Fallback for non-interactive environments
        Start-Sleep -Seconds 2
    }
}

# ============================================================================
# COMING SOON STUB
# ============================================================================

function Show-ComingSoon {
    <#
    .SYNOPSIS
        Display standardized "Coming Soon" message for stub scripts
    .PARAMETER FeatureName
        Name of the feature
    .PARAMETER Description
        Description of what the feature will do
    #>
    param(
        [Parameter(Mandatory)]
        [string]$FeatureName,

        [string]$Description = ""
    )

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Yellow
    Write-Host "  COMING SOON: $FeatureName" -ForegroundColor Yellow
    Write-Host ("=" * 70) -ForegroundColor Yellow
    Write-Host ""

    if ($Description) {
        Write-Host "  $Description" -ForegroundColor White
        Write-Host ""
    }

    Write-Host "  This feature is under development." -ForegroundColor Gray
    Write-Host "  Check back for updates!" -ForegroundColor Gray
    Write-Host ""

    Show-PauseBeforeExit
}

# ============================================================================
# EXPORT
# ============================================================================

# Export all functions when dot-sourced
Export-ModuleMember -Function * -ErrorAction SilentlyContinue
