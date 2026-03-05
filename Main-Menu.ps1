#Requires -Version 7.0

<#
.SYNOPSIS
    M365 Tenant Automation Hub - Universal Main Menu with Prerequisites
.DESCRIPTION
    Universal PowerShell 7 automation hub for Microsoft 365 tenant configuration.
    Downloads latest scripts from GitHub and provides centralized authentication with prerequisite blocking.
.AUTHOR
    CB & Claude Partnership
.VERSION
    1.8
#>

# Force TLS 1.2 for all HTTPS connections (required for GitHub)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Script version — compared against GitHub on startup for self-update
$Script:MenuVersion = "1.8"

# Global Variables
$Global:TenantConnection = $null
$Global:CurrentScopes = @()
$Global:GitHubRepo = "cbro09/Complete-365Tenant-Creation"
$Global:GitHubBranch = "main" # Change to "dev" for testing
$Global:ScriptCache = @{}
$Global:SharedHelpersLoaded = $false

# Load Shared Helper Module
function Initialize-SharedHelpers {
    <#
    .SYNOPSIS
        Load the shared helper module from GitHub or local path
    #>

    if ($Global:SharedHelpersLoaded) {
        return $true
    }

    $helperPath = "Shared/ScriptHelpers.ps1"

    try {
        # Try GitHub first
        $url = "https://raw.githubusercontent.com/$Global:GitHubRepo/$Global:GitHubBranch/$helperPath"
        $helperContent = Invoke-RestMethod -Uri $url -TimeoutSec 10 -ErrorAction Stop

        # Execute the helper script to load functions
        $scriptBlock = [ScriptBlock]::Create($helperContent)
        . $scriptBlock

        $Global:SharedHelpersLoaded = $true
        Write-Host "   Shared helpers loaded from GitHub" -ForegroundColor Green
        return $true
    }
    catch {
        # Try local path as fallback
        $localPaths = @(
            ".\Shared\ScriptHelpers.ps1",
            "$PSScriptRoot\Shared\ScriptHelpers.ps1",
            "Shared\ScriptHelpers.ps1"
        )

        foreach ($localPath in $localPaths) {
            if (Test-Path $localPath -ErrorAction SilentlyContinue) {
                try {
                    . $localPath
                    $Global:SharedHelpersLoaded = $true
                    Write-Host "   Shared helpers loaded from local path" -ForegroundColor Green
                    return $true
                }
                catch {
                    continue
                }
            }
        }

        Write-Host "   Could not load shared helpers (non-critical)" -ForegroundColor Yellow
        return $false
    }
}

# Required Modules for Main Menu
$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Identity.DirectoryManagement'
)

# Auto-install and import required modules
function Initialize-Modules {
    Write-Host "🔧 Checking required modules..." -ForegroundColor Yellow
    
    foreach ($Module in $RequiredModules) {
        if (!(Get-Module -ListAvailable -Name $Module)) {
            Write-Host "Installing $Module..." -ForegroundColor Yellow
            Install-Module $Module -Force -Scope CurrentUser -AllowClobber
        }
        if (!(Get-Module -Name $Module)) {
            Write-Host "Importing $Module..." -ForegroundColor Yellow
            Import-Module $Module -Force
        }
    }
    Write-Host "✅ Modules ready!" -ForegroundColor Green
}

# License checking function
function Test-EntraP2License {
    param(
        [switch]$ShowDetails
    )
    
    try {
        # Check for Entra ID P2 licenses
        $subscribedSkus = Get-MgSubscribedSku -ErrorAction SilentlyContinue
        
        if (-not $subscribedSkus) {
            if ($ShowDetails) {
                Write-Host "❌ Unable to retrieve license information" -ForegroundColor Red
            }
            return $false
        }
        
        # Look for Entra ID P2 SKUs and equivalent licenses
        $p2Licenses = @(
            "AAD_PREMIUM_P2",           # Entra ID P2
            "ENTERPRISEPREMIUM",        # Microsoft 365 E5
            "ENTERPRISEPACKPLUS_GOV",   # Microsoft 365 E5 Government
            "SPE_E5",                   # Microsoft 365 E5 (newer SKU)
            "EMSPREMIUM",              # Enterprise Mobility + Security E5
            "EMS",                      # Enterprise Mobility + Security E5 (alternate SKU)
            "OFFICE365_E5",            # Office 365 E5
            "STANDARDPACK_FACULTY",     # Office 365 A3 for faculty
            "ENTERPRISEPACK_FACULTY",   # Office 365 A3 for faculty
            "DEVELOPERPACK_E5",        # Microsoft 365 E5 Developer
            "M365_E5_SUITE_COMPONENTS", # Microsoft 365 E5 (component)
            "SPE_F1",                  # Microsoft 365 F3 (has some features)
            "MICROSOFT_BUSINESS_PREMIUM", # Microsoft 365 Business Premium (some CA features)
            "O365_BUSINESS_PREMIUM",   # Microsoft 365 Business Premium (legacy)
            "SPB",                     # Microsoft 365 Business Premium (current)
            "M365EDU_A5_FACULTY",      # Microsoft 365 A5 for faculty
            "M365EDU_A5_STUDENT",      # Microsoft 365 A5 for students
            "ENTERPRISEPREMIUM_NOPSTNCONF", # Microsoft 365 E5 without Audio Conferencing
            "SPE_E5_NOPSTNCONF"        # Microsoft 365 E5 without PSTN
        )
        
        $hasP2License = $false
        $availableLicenses = @()
        
        foreach ($sku in $subscribedSkus) {
            $skuPartNumber = $sku.SkuPartNumber
            $availableLicenses += $skuPartNumber
            
            if ($skuPartNumber -in $p2Licenses) {
                $hasP2License = $true
                if ($ShowDetails) {
                    Write-Host "✅ Found P2-compatible license: $skuPartNumber" -ForegroundColor Green
                    Write-Host "   Available: $($sku.PrepaidUnits.Enabled)" -ForegroundColor Gray
                    Write-Host "   Consumed: $($sku.ConsumedUnits)" -ForegroundColor Gray
                }
            }
        }
        
        # Check for partial P2 support (Business Premium has some CA features)
        $partialP2Licenses = @("SPB", "O365_BUSINESS_PREMIUM", "MICROSOFT_BUSINESS_PREMIUM")
        $hasPartialP2 = $subscribedSkus | Where-Object { $_.SkuPartNumber -in $partialP2Licenses }
        
        if ($ShowDetails -and -not $hasP2License) {
            if ($hasPartialP2) {
                Write-Host "⚠️ Partial P2 features detected (Business Premium)" -ForegroundColor Yellow
                Write-Host "   ✅ Basic Conditional Access supported" -ForegroundColor Green
                Write-Host "   ❌ Dynamic groups require full P2" -ForegroundColor Red
                Write-Host "   ❌ PIM requires full P2" -ForegroundColor Red
            } else {
                Write-Host "❌ No Entra ID P2 licenses found" -ForegroundColor Red
            }
            
            Write-Host "Available licenses:" -ForegroundColor Yellow
            $availableLicenses | ForEach-Object { Write-Host "   • $_" -ForegroundColor Gray }
            Write-Host ""
            Write-Host "💡 P2 licenses support:" -ForegroundColor Cyan
            Write-Host "   • Conditional Access policies" -ForegroundColor Gray
            Write-Host "   • Dynamic security groups" -ForegroundColor Gray
            Write-Host "   • Privileged Identity Management (PIM)" -ForegroundColor Gray
            Write-Host "   • Advanced identity protection" -ForegroundColor Gray
        }
        
        return $hasP2License
    }
    catch {
        if ($ShowDetails) {
            Write-Host "❌ Error checking licenses: $($_.Exception.Message)" -ForegroundColor Red
        }
        return $false
    }
}

# Check if a script requires P2 license
function Test-ScriptP2Requirement {
    param([string]$ScriptPath)
    
    $p2RequiredScripts = @(
        "entra/CA-Policies.ps1",
        "entra/Security-Groups.ps1", 
        "Intune/Device-Groups.ps1",
        "entra/Admin-Creation.ps1"
    )
    
    return $ScriptPath -in $p2RequiredScripts
}

# Download script from GitHub
function Get-GitHubScript {
    param(
        [string]$ScriptPath,
        [string]$Branch = $Global:GitHubBranch
    )

    $url = "https://raw.githubusercontent.com/$Global:GitHubRepo/$Branch/$ScriptPath"

    try {
        # Force TLS 1.2 for GitHub connectivity (fixes SSL connection issues)
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # Increase timeout for slow connections
        $response = Invoke-RestMethod -Uri $url -TimeoutSec 30 -ErrorAction Stop
        return $response
    }
    catch {
        Write-Host "❌ Failed to download $ScriptPath from GitHub" -ForegroundColor Red
        Write-Host "   Error: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "   URL: $url" -ForegroundColor Gray
        Write-Host ""
        Write-Host "💡 Troubleshooting:" -ForegroundColor Cyan
        Write-Host "   • Check your internet connection" -ForegroundColor Gray
        Write-Host "   • Verify firewall/proxy settings allow GitHub access" -ForegroundColor Gray
        Write-Host "   • Try: [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12" -ForegroundColor Gray
        return $null
    }
}

# Execute downloaded script
function Invoke-GitHubScript {
    param(
        [string]$ScriptPath,
        [hashtable]$Parameters = @{}
    )
    
    # Check if script requires P2 license
    if (Test-ScriptP2Requirement -ScriptPath $ScriptPath) {
        Write-Host "🔍 Checking Entra ID P2 license requirements..." -ForegroundColor Yellow
        
        if (-not (Test-EntraP2License)) {
            Write-Host ""
            Write-Host "❌ P2 LICENSE REQUIRED" -ForegroundColor Red
            Write-Host "━" * 50 -ForegroundColor Red
            Write-Host "This script requires Entra ID P2 licensing:" -ForegroundColor White
            Write-Host ""
            
            switch ($ScriptPath) {
                "entra/CA-Policies.ps1" {
                    Write-Host "• Conditional Access policies require P2" -ForegroundColor Yellow
                    Write-Host "• Alternative: Use Microsoft 365 Business Premium for basic CA" -ForegroundColor Gray
                }
                "entra/Security-Groups.ps1" {
                    Write-Host "• Dynamic group membership rules require P2" -ForegroundColor Yellow
                    Write-Host "• Alternative: Script can create static groups instead" -ForegroundColor Gray
                }
                "Intune/Device-Groups.ps1" {
                    Write-Host "• Dynamic device groups require P2" -ForegroundColor Yellow
                    Write-Host "• Alternative: Use static device groups" -ForegroundColor Gray
                }
                "entra/Admin-Creation.ps1" {
                    Write-Host "• PIM (Privileged Identity Management) features require P2" -ForegroundColor Yellow
                    Write-Host "• Alternative: Create admin accounts without PIM" -ForegroundColor Gray
                }
            }
            
            Write-Host ""
            Write-Host "Options:" -ForegroundColor Cyan
            Write-Host "1. Purchase Entra ID P2 licenses" -ForegroundColor White
            Write-Host "2. Run script anyway (some features may fail)" -ForegroundColor Yellow
            Write-Host "3. Cancel and return to menu" -ForegroundColor White
            Write-Host ""
            
            $choice = Read-Host "Choose option (1/2/3)"
            
            switch ($choice) {
                "1" {
                    Write-Host "💡 Purchase P2 licenses at: https://admin.microsoft.com/AdminPortal/Home#/catalog" -ForegroundColor Cyan
                    Write-Host "Press any key to return to menu..." -ForegroundColor Gray
                    try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep 2 }
                    return $null
                }
                "2" {
                    Write-Host "⚠️ Proceeding without P2 license - some features may fail" -ForegroundColor Yellow
                    Start-Sleep 2
                }
                "3" {
                    Write-Host "Returning to menu..." -ForegroundColor Gray
                    return $null
                }
                default {
                    Write-Host "Invalid choice. Returning to menu..." -ForegroundColor Red
                    return $null
                }
            }
        } else {
            Write-Host "✅ P2 license detected - proceeding with script" -ForegroundColor Green
        }
    }
    
    if ($Global:ScriptCache.ContainsKey($ScriptPath)) {
        $scriptContent = $Global:ScriptCache[$ScriptPath]
    } else {
        Write-Host "📥 Downloading $ScriptPath..." -ForegroundColor Yellow
        $scriptContent = Get-GitHubScript -ScriptPath $ScriptPath
        if ($scriptContent) {
            $Global:ScriptCache[$ScriptPath] = $scriptContent
        } else {
            return $null
        }
    }
    
    try {
        # Create script block and execute with parameters
        $scriptBlock = [ScriptBlock]::Create($scriptContent)
        $result = & $scriptBlock @Parameters
        
        return $result
    }
    catch {
        Write-Error "Error executing ${ScriptPath}: $($_.Exception.Message)"
        return $null
    }
}

function Test-GroupsExist {
    param([string[]]$GroupNames)
    try {
        $existingGroups = Get-MgGroup | Select-Object -ExpandProperty DisplayName
        $missingGroups = @()
        
        foreach ($groupName in $GroupNames) {
            if ($groupName -notin $existingGroups) {
                $missingGroups += $groupName
            }
        }
        
        $result = $missingGroups.Count -eq 0
        if ($missingGroups.Count -gt 0) {
            Write-Host "  ⚠️ Missing groups: $($missingGroups -join ', ')" -ForegroundColor Yellow
        }
        return $result
    }
    catch {
        Write-Host "  ❌ Error checking groups: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-PoliciesExist {
    param([string[]]$PolicyNames)
    try {
        $existingPolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -Method GET |
            Select-Object -ExpandProperty value | Select-Object -ExpandProperty name
        return ($PolicyNames | ForEach-Object { $_ -in $existingPolicies }) -notcontains $false
    }
    catch {
        return $false
    }
}

function Test-ConfigPoliciesExist {
    try {
        # Get all existing configuration policies
        $existingPolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -Method GET |
            Select-Object -ExpandProperty value | Select-Object -ExpandProperty name
        
        # Core policies that can be automatically created
        $corePolicies = @(
            "Defender Configuration", "Enable Bitlocker", 
            "Office Updates Configuration", "OneDrive Configuration",
            "Outlook Configuration", "Tamper Protection", "Web Sign-in Policy"
        )
        
        # Optional policies that may require manual setup (like EDR)
        $optionalPolicies = @("EDR Policy")
        
        # Check how many core policies exist
        $coreExists = $corePolicies | Where-Object { $_ -in $existingPolicies }
        # Check if optional policies exist (bonus points but not required)
        $optionalExists = $optionalPolicies | Where-Object { $_ -in $existingPolicies }
        
        # Calculate completion including EDR as important but manual
        # Core policies = 80% completion, EDR = 20% completion for accurate tracking
        $coreCompletion = if ($corePolicies.Count -gt 0) { $coreExists.Count / $corePolicies.Count } else { 0 }
        $edrCompletion = if ($optionalExists.Count -gt 0) { 1 } else { 0 }
        
        # Overall completion: 80% for core + 20% for EDR
        $overallCompletion = ($coreCompletion * 0.8) + ($edrCompletion * 0.2)
        
        # Mark as complete only if we have 90%+ completion (allows for rounding)
        $isComplete = $overallCompletion -ge 0.9
        
        if (-not $isComplete) {
            $missingCore = $corePolicies | Where-Object { $_ -notin $existingPolicies }
            $missingOptional = $optionalPolicies | Where-Object { $_ -notin $existingPolicies }
            
            if ($missingCore.Count -gt 0) {
                Write-Host "  ⚠️ Missing core config policies: $($missingCore -join ', ')" -ForegroundColor Yellow
            }
            if ($missingOptional.Count -gt 0) {
                Write-Host "  💡 Optional policies (may require manual setup): $($missingOptional -join ', ')" -ForegroundColor Gray
            }
        }
        
        return $isComplete
    }
    catch {
        Write-Host "  ❌ Error checking config policies: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-EDRPolicyExists {
    try {
        $existingPolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -Method GET |
            Select-Object -ExpandProperty value | Select-Object -ExpandProperty name
        
        $edrExists = "EDR Policy" -in $existingPolicies
        
        if (-not $edrExists) {
            Write-Host "  💡 EDR Policy requires manual setup in Microsoft Defender for Endpoint" -ForegroundColor Gray
        }
        
        return $edrExists
    }
    catch {
        Write-Host "  ❌ Error checking EDR policy: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-ConditionalAccessPoliciesExist {
    try {
        # Look for custom conditional access policies (not just any policies)
        $policies = Get-MgIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue | 
            Where-Object { 
                $_.State -eq "enabled" -and 
                ($_.DisplayName -like "*BITS*" -or 
                 $_.DisplayName -like "*Admin*" -or 
                 $_.DisplayName -like "*MFA*" -or
                 $_.CreatedDateTime -gt (Get-Date).AddDays(-30)) # Recently created policies
            }
        
        return $policies.Count -gt 0
    }
    catch {
        return $false
    }
}

function Test-AdminAccountsExist {
    try {
        # Check for the core admin accounts created by the Admin-Creation script
        $adminAccounts = @(
            "BITS-Admin-Cloud",
            "BITS-Admin-HD", 
            "BITS-Admin-BG01",
            "BITS-Admin-BG02"
        )
        
        $existingUsers = Get-MgUser -Filter "department eq 'BITS Admin'" -ErrorAction SilentlyContinue
        $existingDisplayNames = $existingUsers | Select-Object -ExpandProperty DisplayName
        
        $foundAccounts = 0
        foreach ($adminAccount in $adminAccounts) {
            if ($adminAccount -in $existingDisplayNames) {
                $foundAccounts++
            }
        }
        
        # Return true if at least 2 admin accounts exist (flexible threshold)
        return $foundAccounts -ge 2
    }
    catch {
        return $false
    }
}
function Test-CompliancePoliciesExist {
    try {
        $policies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies" -Method GET -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty value
        
        # Check for our standard compliance policies
        $expectedPolicies = @("Android Basic Compliance", "iOS Basic Compliance", "macOS Basic Compliance", "Windows 10/11 Basic Compliance")
        $existingPolicyNames = $policies | Select-Object -ExpandProperty displayName
        
        $foundPolicies = 0
        foreach ($expectedPolicy in $expectedPolicies) {
            if ($expectedPolicy -in $existingPolicyNames) {
                $foundPolicies++
            }
        }
        
        return $foundPolicies -ge 2  # At least 2 compliance policies exist (flexible threshold)
    }
    catch {
        return $false
    }
}

# === Enhanced Error Handling ===

function Show-FriendlyError {
    param(
        [string]$ErrorMessage,
        [string]$Context = "",
        [string]$SuggestedAction = ""
    )
    
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║                                   ⚠️ ERROR                                    ║" -ForegroundColor Red
    Write-Host "╚═══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    
    if ($Context) {
        Write-Host ""
        Write-Host "📍 Context: $Context" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "❌ Error Details:" -ForegroundColor Red
    Write-Host "   $ErrorMessage" -ForegroundColor White
    
    if ($SuggestedAction) {
        Write-Host ""
        Write-Host "💡 Suggested Solution:" -ForegroundColor Green
        Write-Host "   $SuggestedAction" -ForegroundColor White
    }
    
    Write-Host ""
    Write-Host "🔄 Common Solutions:" -ForegroundColor Cyan
    Write-Host "   • Try refreshing scripts (Option 9)" -ForegroundColor Gray
    Write-Host "   • Check your Microsoft Graph connection" -ForegroundColor Gray
    Write-Host "   • Verify you have appropriate permissions" -ForegroundColor Gray
    Write-Host "   • Ensure prerequisites are met" -ForegroundColor Gray
    
    Write-Host ""
    Write-Host "Press any key to continue..."
    try {
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    catch {
        Start-Sleep 1
    }
}

function Test-TenantConnection {
    try {
        $context = Get-MgContext -ErrorAction Stop
        if (-not $context) {
            return @{
                Connected = $false
                Error = "No Microsoft Graph connection found"
                Solution = "Please connect to your tenant using Option 8"
            }
        }
        
        # Test actual connectivity
        $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
        if (-not $org) {
            return @{
                Connected = $false
                Error = "Unable to retrieve organization information"
                Solution = "Check your connection and permissions, then try reconnecting"
            }
        }
        
        return @{
            Connected = $true
            Context = $context
            Organization = $org
        }
    }
    catch {
        return @{
            Connected = $false
            Error = $_.Exception.Message
            Solution = "Try reconnecting to your tenant (Option 8) or check your permissions"
        }
    }
}

function Invoke-WithErrorHandling {
    param(
        [scriptblock]$ScriptBlock,
        [string]$Context = "Operation",
        [string]$SuggestedAction = "Try the operation again"
    )
    
    try {
        return & $ScriptBlock
    }
    catch {
        Show-FriendlyError -ErrorMessage $_.Exception.Message -Context $Context -SuggestedAction $SuggestedAction
        return $false
    }
}

# === Session Persistence ===

$Global:StateFilePath = "$env:TEMP\\M365AutomationState.json"

function Save-SessionState {
    try {
        $state = @{
            LastUpdated = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            TenantInfo = if ($Global:TenantConnection) { 
                @{
                    TenantId = $Global:TenantConnection.TenantId
                    OrgName = $Global:TenantConnection.OrgName
                    Account = $Global:TenantConnection.Account
                }
            } else { $null }
            CompletedSteps = $Global:CompletedSteps
            LastRunMenus = @{
                Entra = $false
                Intune = $false
                Exchange = $false
                SharePoint = $false
                Security = $false
                Purview = $false
            }
        }
        
        $jsonState = $state | ConvertTo-Json -Depth 3
        $jsonState | Out-File -FilePath $Global:StateFilePath -Encoding UTF8
    }
    catch {
        # Silently fail - session persistence is not critical
    }
}

function Import-SessionState {
    try {
        if (Test-Path $Global:StateFilePath) {
            $jsonState = Get-Content -Path $Global:StateFilePath -Raw
            $state = $jsonState | ConvertFrom-Json
            
            # Only load if state is recent (within last 24 hours)
            $lastUpdated = [DateTime]::Parse($state.LastUpdated)
            if ($lastUpdated.AddHours(24) -gt (Get-Date)) {
                Write-Host "📋 Loading previous session state..." -ForegroundColor Gray
                
                # Convert PSCustomObject back to hashtables
                if ($state.CompletedSteps) {
                    $Global:CompletedSteps = @{}
                    $state.CompletedSteps.PSObject.Properties | ForEach-Object {
                        $Global:CompletedSteps[$_.Name] = $_.Value
                    }
                }
                
                return $true
            }
        }
    }
    catch {
        # Silently fail - session persistence is not critical
    }
    
    return $false
}

function Clear-SessionState {
    try {
        if (Test-Path $Global:StateFilePath) {
            Remove-Item -Path $Global:StateFilePath -Force
        }
    }
    catch {
        # Silently fail
    }
}

function Show-SessionInfo {
    try {
        if (Test-Path $Global:StateFilePath) {
            $jsonState = Get-Content -Path $Global:StateFilePath -Raw
            $state = $jsonState | ConvertFrom-Json
            
            Write-Host "💾 Session Information:" -ForegroundColor Cyan
            Write-Host "   Last Updated: $($state.LastUpdated)" -ForegroundColor Gray
            if ($state.TenantInfo) {
                Write-Host "   Previous Tenant: $($state.TenantInfo.OrgName)" -ForegroundColor Gray
            }
            Write-Host ""
        }
    }
    catch {
        # Silently fail
    }
}

# === Interactive Navigation System ===

function Get-MenuSelection {
    param(
        [array]$MenuItems,
        [string]$Title = "Select Option",
        [int]$InitialSelection = 0,
        [scriptblock]$HeaderCallback = $null
    )
    
    $selectedIndex = $InitialSelection
    $maxIndex = $MenuItems.Count - 1
    $firstRun = $true
    
    do {
        # Clear screen and redraw everything for consistency
        if (-not $firstRun) {
            Clear-Host
            
            # Call header callback if provided (for dashboard)
            if ($HeaderCallback) {
                & $HeaderCallback
            }
        }
        $firstRun = $false
        
        # Show title
        Write-Host $Title -ForegroundColor Cyan
        Write-Host ("─" * $Title.Length) -ForegroundColor Gray
        Write-Host ""
        
        # Display menu items with highlighting
        for ($i = 0; $i -lt $MenuItems.Count; $i++) {
            $item = $MenuItems[$i]
            
            if ($i -eq $selectedIndex) {
                # Highlighted selection
                Write-Host "  ► " -NoNewline -ForegroundColor Yellow
                Write-Host "$($item.Display)" -ForegroundColor Black -BackgroundColor Yellow
            }
            else {
                # Normal menu item
                Write-Host "    $($item.Display)" -ForegroundColor White
            }
        }
        
        Write-Host ""
        Write-Host "Use ↑↓ arrow keys to navigate, Enter to select, or type number + Enter" -ForegroundColor Gray
        
        # Get user input
        try {
            $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        catch {
            # Fallback for non-interactive environments
            $key = @{ VirtualKeyCode = 0; Character = '0' }
        }
        
        switch ($key.VirtualKeyCode) {
            38 { # Up arrow
                $selectedIndex = if ($selectedIndex -eq 0) { $maxIndex } else { $selectedIndex - 1 }
            }
            40 { # Down arrow
                $selectedIndex = if ($selectedIndex -eq $maxIndex) { 0 } else { $selectedIndex + 1 }
            }
            13 { # Enter
                return $MenuItems[$selectedIndex].Value
            }
            27 { # Escape
                return "0" # Exit
            }
            default {
                # Check if it's a number key (fallback to traditional input)
                if ($key.Character -match '\d' -or $key.Character -eq 'd') {
                    $numberInput = $key.Character.ToString()
                    
                    # Find matching menu item
                    $matchingItem = $MenuItems | Where-Object { $_.Value -eq $numberInput }
                    if ($matchingItem) {
                        return $numberInput
                    }
                }
            }
        }
    } while ($true)
}

function Show-InteractiveMainMenu {
    # Clear screen for main menu
    Clear-Host
    
    # Show dashboard if connected
    if ($Global:TenantConnection -and $Global:CompletedSteps) {
        Write-Host "✅ Connected to: $($Global:TenantConnection.OrgName)" -ForegroundColor Green
        Write-Host "   Account: $($Global:TenantConnection.Account)" -ForegroundColor Gray
        Write-Host ""
        
        # Show Enhanced Progress Dashboard
        Show-EnhancedProgressDashboard -CompletedSteps $Global:CompletedSteps
        
        # Show Smart Recommendations
        Show-SmartRecommendations -CompletedSteps $Global:CompletedSteps
        Write-Host ""
    }
    
    # Show main menu title
    Write-Host "🚀 M365 TENANT AUTOMATION HUB" -ForegroundColor Cyan
    Write-Host ("─" * "🚀 M365 TENANT AUTOMATION HUB".Length) -ForegroundColor Gray
    Write-Host ""
    
    # Show menu options
    if ($Global:TenantConnection) {
        Write-Host "1. 🏢 Entra ID (Identity & Access Management)" -ForegroundColor Green
        Write-Host "2. 📱 Intune (Device Management & Compliance)" -ForegroundColor Green
        Write-Host "3. 📧 Exchange Online (Email & Collaboration)" -ForegroundColor Green
        Write-Host "4. 🌐 SharePoint Online (File Sharing & Sites)" -ForegroundColor Green
        Write-Host "5. 🛡️ Security & Defender (Threat Protection)" -ForegroundColor Green
        Write-Host "6. 🔒 Purview (Data Governance & Compliance)" -ForegroundColor Green
        Write-Host ""
        Write-Host "7. 🚀 Quick Start Wizard (Guided Setup)" -ForegroundColor Yellow
        Write-Host "9. 🔄 Refresh Scripts & Status" -ForegroundColor White
        Write-Host "d. 🛠️ Debug: Manual Status Override" -ForegroundColor Gray
        Write-Host "r. 🧠 Test Smart Recommendations" -ForegroundColor Gray
        Write-Host "a. 🔐 Check Authentication Status" -ForegroundColor Gray
    }
    else {
        Write-Host "8. 🔐 Connect to Tenant (Required First Step)" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "0. ❌ Exit Application" -ForegroundColor Red
    Write-Host ""
    
    return Read-Host "Select option"
}

function Show-CompactProgressDashboard {
    param([hashtable]$CompletedSteps)
    
    $serviceProgress = Get-ServiceProgress -CompletedSteps $CompletedSteps
    $overallCompleted = ($serviceProgress.Values | Measure-Object -Property Completed -Sum).Sum
    $overallTotal = ($serviceProgress.Values | Measure-Object -Property Total -Sum).Sum
    
    Write-Host "┌─────────────────────────── TENANT PROGRESS ───────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "│ Overall: $(Get-ProgressBar -Current $overallCompleted -Total $overallTotal -Width 12)" -NoNewline -ForegroundColor Cyan
    
    # Show key service status in compact format
    $entraid = if ($CompletedSteps.SecurityGroups -and $CompletedSteps.AdminAccounts) { "✅" } else { "⏳" }
    $intune = if ($CompletedSteps.DeviceGroups -and $CompletedSteps.CompliancePolicies -and $CompletedSteps.ConfigPolicies) { 
        if ($CompletedSteps.EDRPolicy) { "✅" } else { "⚠️" }  # Warning if EDR missing
    } else { "⏳" }
    $ca = if ($CompletedSteps.ConditionalAccess) { "✅" } else { "⏳" }
    
    Write-Host "   EntraID:$entraid Intune:$intune CA:$ca" -NoNewline -ForegroundColor Gray
    Write-Host " │" -ForegroundColor Cyan
    Write-Host "└────────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
}

function Show-CompactRecommendations {
    param([hashtable]$CompletedSteps)
    
    $recommendations = Get-SmartRecommendations -CompletedSteps $CompletedSteps
    
    if ($recommendations.Count -gt 0) {
        $topRec = $recommendations[0]
        $priorityColor = switch ($topRec.Priority) {
            "High" { "Red" }
            "Medium" { "Yellow" }  
            "Low" { "Green" }
            default { "White" }
        }
        
        Write-Host "💡 Next: " -NoNewline -ForegroundColor Yellow
        Write-Host "$($topRec.Icon) $($topRec.Title)" -ForegroundColor $priorityColor
    }
}

function Show-InteractiveSubMenu {
    param(
        [array]$MenuItems,
        [string]$Title,
        [string]$ServiceIcon = "🔧"
    )
    
    # Show compact progress at the top initially
    if ($Global:CompletedSteps) {
        Clear-Host
        Show-CompactProgressDashboard -CompletedSteps $Global:CompletedSteps
        Show-CompactRecommendations -CompletedSteps $Global:CompletedSteps
        Write-Host ""
    }
    
    # Create header callback for consistent dashboard display
    $headerCallback = if ($Global:CompletedSteps) {
        {
            Show-CompactProgressDashboard -CompletedSteps $Global:CompletedSteps
            Show-CompactRecommendations -CompletedSteps $Global:CompletedSteps
            Write-Host ""
        }
    } else { $null }
    
    $fullTitle = "$ServiceIcon $Title"
    return Get-MenuSelection -MenuItems $MenuItems -Title $fullTitle -HeaderCallback $headerCallback
}

# === Enhanced UI Functions ===

function Get-ProgressBar {
    param(
        [int]$Current,
        [int]$Total,
        [int]$Width = 20,
        [string]$CompletedChar = "█",
        [string]$RemainingChar = "░"
    )
    
    if ($Total -eq 0) { return "[$($RemainingChar * $Width)]   0%" }
    
    $percentage = [math]::Round(($Current / $Total) * 100)
    $completedWidth = [math]::Round(($Current / $Total) * $Width)
    $remainingWidth = $Width - $completedWidth
    
    $completedSection = $CompletedChar * $completedWidth
    $remainingSection = $RemainingChar * $remainingWidth
    
    return "[$completedSection$remainingSection] $percentage%"
}

function Get-ServiceProgress {
    param([hashtable]$CompletedSteps)
    
    return @{
        "Entra ID" = @{
            Completed = ($CompletedSteps.SecurityGroups + $CompletedSteps.AdminAccounts + $CompletedSteps.ConditionalAccess)
            Total = 3
            Items = @("Security Groups", "Admin Accounts", "Conditional Access")
            NextStep = if (-not $CompletedSteps.SecurityGroups) { "Create Security Groups" } 
                      elseif (-not $CompletedSteps.AdminAccounts) { "Create Admin Accounts" }
                      elseif (-not $CompletedSteps.ConditionalAccess) { "Configure Conditional Access" }
                      else { "Complete ✓" }
        }
        "Intune" = @{
            Completed = ($CompletedSteps.DeviceGroups + $CompletedSteps.ConfigPolicies + $CompletedSteps.CompliancePolicies)
            Total = 3
            Items = @("Device Groups", "Configuration Policies", "Compliance Policies")
            NextStep = if (-not $CompletedSteps.DeviceGroups) { "Create Device Groups" }
                      elseif (-not $CompletedSteps.ConfigPolicies) { 
                          if (-not $CompletedSteps.EDRPolicy) { "Config Policies (EDR manual setup needed)" }
                          else { "Configure Device Policies" }
                      }
                      elseif (-not $CompletedSteps.CompliancePolicies) { "Setup Compliance Policies" }
                      else { 
                          if (-not $CompletedSteps.EDRPolicy) { "EDR Policy manual setup required" }
                          else { "Complete ✓" }
                      }
        }
        "Exchange" = @{
            Completed = 0  # Placeholder - will be enhanced later
            Total = 3
            Items = @("Shared Mailboxes", "Archive Policies", "Mail Flow Rules")
            NextStep = "Configure Exchange Online"
        }
        "SharePoint" = @{
            Completed = 0  # Placeholder - will be enhanced later
            Total = 3
            Items = @("Site Collections", "Permissions", "External Sharing")
            NextStep = "Setup SharePoint Online"
        }
        "Security" = @{
            Completed = 0  # Placeholder - will be enhanced later
            Total = 3
            Items = @("Safe Attachments", "Anti-Phishing", "Web Filtering")
            NextStep = "Configure Security Policies"
        }
        "Purview" = @{
            Completed = 0  # Placeholder - will be enhanced later
            Total = 3
            Items = @("Retention Policies", "DLP Policies", "Sensitivity Labels")
            NextStep = "Setup Compliance Features"
        }
    }
}

function Show-EnhancedProgressDashboard {
    param([hashtable]$CompletedSteps)
    
    $serviceProgress = Get-ServiceProgress -CompletedSteps $CompletedSteps
    $overallCompleted = ($serviceProgress.Values | Measure-Object -Property Completed -Sum).Sum
    $overallTotal = ($serviceProgress.Values | Measure-Object -Property Total -Sum).Sum

    Write-Host "╔═══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                          🚀 TENANT SETUP PROGRESS                             ║" -ForegroundColor Cyan
    Write-Host "╠═══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Overall Progress: $(Get-ProgressBar -Current $overallCompleted -Total $overallTotal)" -NoNewline -ForegroundColor Cyan
    Write-Host (" " * (45 - (Get-ProgressBar -Current $overallCompleted -Total $overallTotal).Length)) -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    Write-Host "╠═══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    foreach ($service in $serviceProgress.Keys) {
        $progress = $serviceProgress[$service]
        $progressBar = Get-ProgressBar -Current $progress.Completed -Total $progress.Total -Width 15
        $serviceIcon = switch ($service) {
            "Entra ID" { "🏢" }
            "Intune" { "📱" }
            "Exchange" { "📧" }
            "SharePoint" { "🌐" }
            "Security" { "🛡️" }
            "Purview" { "🔒" }
        }
        
        $statusColor = if ($progress.Completed -eq $progress.Total) { "Green" } 
                      elseif ($progress.Completed -gt 0) { "Yellow" } 
                      else { "White" }
        
        $serviceName = "$serviceIcon $service".PadRight(12)
        $nextStep = $progress.NextStep.PadRight(30)
        
        Write-Host "║ " -NoNewline -ForegroundColor Cyan
        Write-Host "$serviceName" -NoNewline -ForegroundColor $statusColor
        Write-Host " $progressBar " -NoNewline -ForegroundColor $statusColor
        Write-Host "$nextStep" -NoNewline -ForegroundColor Gray
        Write-Host " ║" -ForegroundColor Cyan
    }
    
    Write-Host "╚═══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
}

function Get-SmartRecommendations {
    param([hashtable]$CompletedSteps)
    
    $recommendations = @()
    
    # Step 1: Foundation - Security Groups (ALWAYS FIRST)
    if (-not $CompletedSteps.SecurityGroups) {
        $recommendations += @{
            Priority = "High"
            Title = "Start with Security Groups"
            Description = "Create foundation security groups for user management and licensing"
            Action = "Go to Entra ID → Security Groups"
            Icon = "🏗️"
        }
        return $recommendations  # Only show this until completed
    }
    
    # Step 2: Admin Accounts (SECOND PRIORITY)
    if (-not $CompletedSteps.AdminAccounts) {
        $recommendations += @{
            Priority = "High"
            Title = "Create Admin Accounts"
            Description = "Set up administrative accounts with proper break-glass access"
            Action = "Go to Entra ID → Admin Account Creation"
            Icon = "👑"
        }
        return $recommendations  # Only show this until completed
    }
    
    # Step 3: Conditional Access (HIGH PRIORITY after admin accounts)
    if (-not $CompletedSteps.ConditionalAccess) {
        $recommendations += @{
            Priority = "High"
            Title = "Setup Conditional Access"
            Description = "Implement conditional access policies for enhanced security"
            Action = "Go to Entra ID → Conditional Access Policies"
            Icon = "🔐"
        }
    }
    
    # Step 4: Device Management
    if (-not $CompletedSteps.DeviceGroups) {
        $recommendations += @{
            Priority = "Medium"
            Title = "Setup Device Management"
            Description = "Create device groups for Intune policy assignments"
            Action = "Go to Intune → Device Groups"
            Icon = "📱"
        }
    }
    
    # Step 5: Device Configuration
    if ($CompletedSteps.DeviceGroups -and -not $CompletedSteps.ConfigPolicies) {
        $recommendations += @{
            Priority = "Medium"
            Title = "Configure Device Policies"
            Description = "Set up device configuration policies for security settings"
            Action = "Go to Intune → Configuration Policies"
            Icon = "⚙️"
        }
    }
    
    # Step 6: Compliance Policies
    if ($CompletedSteps.DeviceGroups -and -not $CompletedSteps.CompliancePolicies) {
        $recommendations += @{
            Priority = "Medium"
            Title = "Configure Compliance Policies"
            Description = "Set up device compliance policies for security"
            Action = "Go to Intune → Compliance Policies"
            Icon = "✅"
        }
    }
    
    # Step 7: EDR Policy (Manual Setup Required)
    if ($CompletedSteps.ConfigPolicies -and -not $CompletedSteps.EDRPolicy) {
        $recommendations += @{
            Priority = "Medium"
            Title = "Setup EDR Policy (Manual)"
            Description = "Configure Endpoint Detection & Response in Microsoft Defender for Endpoint portal"
            Action = "Manual setup required in Microsoft Defender for Endpoint"
            Icon = "🛡️"
        }
    }
    
    # Advanced features (only show if core is complete)
    if ($CompletedSteps.SecurityGroups -and $CompletedSteps.AdminAccounts -and $CompletedSteps.ConditionalAccess) {
        $recommendations += @{
            Priority = "Low"
            Title = "Setup Exchange Online"
            Description = "Configure email and collaboration features"
            Action = "Go to Exchange Online → Shared Mailboxes"
            Icon = "📧"
        }
        
        $recommendations += @{
            Priority = "Low"
            Title = "Configure Security Policies"
            Description = "Set up threat protection and security features"
            Action = "Go to Security & Defender → Safe Attachments"
            Icon = "🛡️"
        }
    }
    
    return $recommendations
}

function Show-SmartRecommendations {
    param([hashtable]$CompletedSteps)
    
    $recommendations = Get-SmartRecommendations -CompletedSteps $CompletedSteps
    
    if ($recommendations.Count -eq 0) {
        Write-Host "🎉 Great work! No immediate recommendations. All core components are configured!" -ForegroundColor Green
        return
    }
    
    Write-Host ""
    Write-Host "💡 Smart Recommendations:" -ForegroundColor Yellow
    Write-Host "─" * 80 -ForegroundColor Gray
    
    $i = 1
    foreach ($rec in $recommendations) {
        $priorityColor = switch ($rec.Priority) {
            "High" { "Red" }
            "Medium" { "Yellow" }
            "Low" { "Green" }
        }
        
        Write-Host "$i. " -NoNewline -ForegroundColor White
        Write-Host "$($rec.Icon) $($rec.Title)" -ForegroundColor $priorityColor
        Write-Host "   $($rec.Description)" -ForegroundColor Gray
        Write-Host "   → $($rec.Action)" -ForegroundColor Cyan
        
        if ($i -lt $recommendations.Count) {
            Write-Host ""
        }
        $i++
    }
}

function Show-QuickStartWizard {
    Write-Host "╔═══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                            🚀 QUICK START WIZARD                             ║" -ForegroundColor Green
    Write-Host "╚═══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "Welcome to your M365 tenant setup! This wizard will guide you through" -ForegroundColor White
    Write-Host "the essential configuration steps in the optimal order." -ForegroundColor White
    Write-Host ""
    
    Write-Host "📋 Setup Flow:" -ForegroundColor Yellow
    Write-Host "  Step 1: 👥 Security Groups        (Foundation for user management)" -ForegroundColor White
    Write-Host "  Step 2: 👑 Admin Accounts         (Privileged access setup)" -ForegroundColor White
    Write-Host "  Step 3: 📱 Device Groups          (Intune device management)" -ForegroundColor White
    Write-Host "  Step 4: ⚙️  Configuration Policies (Device security settings)" -ForegroundColor White
    Write-Host "  Step 5: ✅ Compliance Policies    (Device compliance rules)" -ForegroundColor White
    Write-Host "  Step 6: 🔐 Conditional Access     (Identity security policies)" -ForegroundColor White
    Write-Host ""
    
    Write-Host "🕒 Estimated Time: 30-45 minutes" -ForegroundColor Gray
    Write-Host ""
    
    $choice = Read-Host "Ready to start? (y/n)"
    if ($choice -eq "y" -or $choice -eq "Y") {
        return $true
    }
    return $false
}

function Start-QuickStartFlow {
    Write-Host ""
    Write-Host "🚀 Starting Quick Start Flow..." -ForegroundColor Green
    Write-Host ""
    
    $steps = @(
        @{ Name = "Security Groups"; Menu = "1"; SubMenu = "1"; Check = "SecurityGroups" },
        @{ Name = "Admin Accounts"; Menu = "1"; SubMenu = "3"; Check = "AdminAccounts" },
        @{ Name = "Device Groups"; Menu = "2"; SubMenu = "1"; Check = "DeviceGroups" },
        @{ Name = "Configuration Policies"; Menu = "2"; SubMenu = "2"; Check = "ConfigPolicies" },
        @{ Name = "Compliance Policies"; Menu = "2"; SubMenu = "3"; Check = "CompliancePolicies" },
        @{ Name = "Conditional Access"; Menu = "1"; SubMenu = "2"; Check = "ConditionalAccess" }
    )
    
    $currentStep = 1
    foreach ($step in $steps) {
        Write-Host "Step $currentStep of $($steps.Count): " -NoNewline -ForegroundColor White
        Write-Host "$($step.Name)" -ForegroundColor Yellow
        
        # Check if already completed
        if ($Global:CompletedSteps[$step.Check]) {
            Write-Host "   ✅ Already completed - Skipping" -ForegroundColor Green
        }
        else {
            Write-Host "   🔄 Starting configuration..." -ForegroundColor Yellow
            Write-Host "   This will take you to the appropriate menu section." -ForegroundColor Gray
            Write-Host ""
            Write-Host "   Press any key to continue or 'q' to quit Quick Start..."
            
            try {
                $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            catch {
                $key = @{ Character = 'q' }
            }
            if ($key.Character -eq 'q') {
                Write-Host ""
                Write-Host "Quick Start cancelled. Returning to main menu..." -ForegroundColor Yellow
                Start-Sleep 2
                return
            }
            
            # Navigate to appropriate menu
            switch ($step.Menu) {
                "1" { 
                    Write-Host "   → Opening Entra ID menu..." -ForegroundColor Cyan
                    Show-EntraMenu 
                }
                "2" { 
                    Write-Host "   → Opening Intune menu..." -ForegroundColor Cyan
                    Show-IntuneMenu 
                }
            }
            
            # Refresh status after returning from menu
            Initialize-CompletedSteps
            
            # Check if completed
            if ($Global:CompletedSteps[$step.Check]) {
                Write-Host "   ✅ Step completed successfully!" -ForegroundColor Green
            }
            else {
                Write-Host "   ⚠️ Step not completed. You can continue or return later." -ForegroundColor Yellow
                $continueChoice = Read-Host "Continue with Quick Start? (y/n)"
                if ($continueChoice -ne "y" -and $continueChoice -ne "Y") {
                    Write-Host "Quick Start paused. Returning to main menu..." -ForegroundColor Yellow
                    Start-Sleep 2
                    return
                }
            }
        }
        
        $currentStep++
        Write-Host ""
    }
    
    Write-Host "🎉 Quick Start Flow Complete!" -ForegroundColor Green
    Write-Host "Your M365 tenant foundation is now configured." -ForegroundColor White
    Write-Host ""
    Write-Host "Next steps you might consider:" -ForegroundColor Yellow
    Write-Host "• Configure Exchange Online (Option 3)" -ForegroundColor Gray
    Write-Host "• Setup SharePoint Online (Option 4)" -ForegroundColor Gray
    Write-Host "• Configure Security Policies (Option 5)" -ForegroundColor Gray
    Write-Host "• Setup Purview Compliance (Option 6)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Press any key to return to main menu..."
    try {
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    catch {
        Start-Sleep 1
    }
}

function Initialize-CompletedSteps {    
    $Global:CompletedSteps = @{
        SecurityGroups = Test-GroupsExist -GroupNames @(
            "NoMFA Exclusion Group", "BITS Admin Users", "SSPR Eligible Users",
            "Helpdesk Operator Group"
        )
        DeviceGroups = Test-GroupsExist -GroupNames @(
            "Windows Devices (Autopilot)", "macOS Devices", "iOS Devices",
            "Android Devices", "Corporate Owned Devices", "Personal Devices",
            "Pilot Device Group"
        )
        ConfigPolicies = Test-ConfigPoliciesExist
        EDRPolicy = Test-EDRPolicyExists
        CompliancePolicies = Test-CompliancePoliciesExist
        ConditionalAccess = Test-ConditionalAccessPoliciesExist
        AdminAccounts = Test-AdminAccountsExist
    }
}

function Test-Prerequisites {
    param([string]$RequiredStep)
    
    switch ($RequiredStep) {
        "ConditionalAccess" { return $Global:CompletedSteps.SecurityGroups }
        "AdminCreation" { return $Global:CompletedSteps.SecurityGroups }
        "UserCreation" { return $Global:CompletedSteps.SecurityGroups }
        "PasswordPolicies" { return $Global:CompletedSteps.AdminAccounts }
        "ConfigPolicies" { return $Global:CompletedSteps.DeviceGroups }
        "CompliancePolicies" { return $Global:CompletedSteps.DeviceGroups }
        "AppDeployment" { return ($Global:CompletedSteps.DeviceGroups -and $Global:CompletedSteps.CompliancePolicies) }
        "AutopilotConfig" { return $Global:CompletedSteps.DeviceGroups }
        "ArchivePolicies" { return $Global:CompletedSteps.SecurityGroups }
        "DistributionLists" { return $Global:CompletedSteps.SecurityGroups }
        default { return $true }
    }
}



# Simplified Microsoft 365 Tenant Connection
function Connect-M365Tenant {
    Write-Host "`n🔐 Connecting to Microsoft 365 Tenant..." -ForegroundColor Cyan
    
    try {
        # Disconnect any existing connection to force fresh authentication
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        
        # Use a practical set of scopes that cover most common scenarios
        $practicalScopes = @(
            "Directory.Read.All", 
            "Directory.ReadWrite.All",
            "User.ReadWrite.All",
            "Group.ReadWrite.All",
            "Group.Read.All",
            "Policy.ReadWrite.ConditionalAccess",
            "Policy.Read.All",
            "RoleManagement.ReadWrite.Directory",
            "Policy.ReadWrite.SecurityDefaults",
            "DeviceManagementConfiguration.ReadWrite.All",
            "DeviceManagementManagedDevices.ReadWrite.All",
            "DeviceManagementApps.ReadWrite.All"
        )
        
        Write-Host "🚀 Authenticating with essential permissions..." -ForegroundColor Yellow
        
        # Connect with practical scopes
        Connect-MgGraph -Scopes $practicalScopes -NoWelcome
        
        $context = Get-MgContext
        if (!$context) {
            throw "No authentication context returned"
        }
        
        $org = Get-MgOrganization | Select-Object -First 1
        if (!$org) {
            throw "Unable to retrieve organization information"
        }
        
        # Store connection details
        $Global:TenantConnection = @{
            TenantId = $context.TenantId
            Account = $context.Account
            OrgName = $org.DisplayName
            ConnectedTime = Get-Date
        }
        
        Write-Host "✅ Connected to: $($org.DisplayName)" -ForegroundColor Green
        Write-Host "   Tenant ID: $($context.TenantId)" -ForegroundColor Gray
        Write-Host "   Account: $($context.Account)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "🎉 Ready to configure your Microsoft 365 tenant!" -ForegroundColor Green
        
        return $true
    }
    catch {
        Write-Host "⚠️ Primary authentication failed. Trying minimal connection..." -ForegroundColor Yellow
        
        try {
            # Fallback to very basic connection
            Connect-MgGraph -Scopes "Organization.Read.All" -NoWelcome
            
            $context = Get-MgContext
            $org = Get-MgOrganization | Select-Object -First 1
            
            $Global:TenantConnection = @{
                TenantId = $context.TenantId
                Account = $context.Account
                OrgName = $org.DisplayName
                ConnectedTime = Get-Date
            }
            
            Write-Host "✅ Connected with basic permissions: $($org.DisplayName)" -ForegroundColor Green
            Write-Host "   ⚠️ Some features may require additional permissions" -ForegroundColor Yellow
            
            return $true
        }
        catch {
            Write-Host "❌ Connection failed completely: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "" 
            Write-Host "Troubleshooting tips:" -ForegroundColor Yellow
            Write-Host "• Ensure you have Microsoft Graph PowerShell installed" -ForegroundColor Gray
            Write-Host "• Check your internet connection" -ForegroundColor Gray
            Write-Host "• Verify you have appropriate tenant permissions" -ForegroundColor Gray
            Write-Host "• Try running: Install-Module Microsoft.Graph -Force" -ForegroundColor Gray
            
            return $false
        }
    }
}

# Unified Authentication Helper for Scripts
function Test-ServiceAuthentication {
    param(
        [string]$Service,
        [switch]$ShowStatus
    )
    
    $authStatus = @{
        GraphConnected = $false
        ServiceConnected = $false
        RequiredAuth = $null
    }
    
    # Check Microsoft Graph connection
    $graphContext = Get-MgContext
    if ($graphContext) {
        $authStatus.GraphConnected = $true
        if ($ShowStatus) {
            Write-Host "✅ Microsoft Graph: Connected" -ForegroundColor Green
        }
    }
    
    # Check service-specific connections based on service type
    switch ($Service) {
        "Exchange" {
            $authStatus.RequiredAuth = "ExchangeOnline"
            try {
                # Use modern Get-ConnectionInformation (EXO v3+)
                $exoConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue
                if ($exoConnection -and $exoConnection.State -eq "Connected") {
                    $authStatus.ServiceConnected = $true
                    if ($ShowStatus) { Write-Host "✅ Exchange Online: Connected as $($exoConnection.UserPrincipalName)" -ForegroundColor Green }
                } else {
                    if ($ShowStatus) { Write-Host "⚠️ Exchange Online: Not Connected" -ForegroundColor Yellow }
                }
            }
            catch {
                if ($ShowStatus) { Write-Host "⚠️ Exchange Online: Not Available" -ForegroundColor Yellow }
            }
        }
        "SharePoint" {
            $authStatus.RequiredAuth = "SharePointPnP"
            try {
                Get-SPOTenant -ErrorAction Stop | Out-Null
                $authStatus.ServiceConnected = $true
                if ($ShowStatus) { Write-Host "   SharePoint: Connected" -ForegroundColor Green }
            }
            catch {
                $authStatus.ServiceConnected = $false
                if ($ShowStatus) { Write-Host "   SharePoint: Not connected (SPO service)" -ForegroundColor Yellow }
            }
        }
        default {
            # Most services can use Graph
            $authStatus.ServiceConnected = $authStatus.GraphConnected
        }
    }
    
    return $authStatus
}

function Connect-SharePointOnline {
    # Derives SPO admin URL from the connected tenant, imports the SPO module,
    # and calls Connect-SPOService.
    try {
        $org = Get-MgOrganization | Select-Object -First 1
        $initialDomain = $org.VerifiedDomains | Where-Object { $_.IsInitial } | Select-Object -ExpandProperty Name
        $tenantName = $initialDomain -replace '\.onmicrosoft\.com$', ''
        $spoAdminUrl = "https://$tenantName-admin.sharepoint.com"

        # Install/update SPO module and import it
        Write-Host "   Checking Microsoft.Online.SharePoint.PowerShell..." -ForegroundColor Gray
        Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Import-Module Microsoft.Online.SharePoint.PowerShell -Force -ErrorAction Stop

        # Check if already connected
        try {
            Get-SPOTenant -ErrorAction Stop | Out-Null
            Write-Host "   SharePoint Online: already connected" -ForegroundColor Green
            return $true
        }
        catch {}

        # Clear any stale cached auth before connecting (ignore if nothing to disconnect)
        try { Disconnect-SPOService -ErrorAction Stop } catch {}

        Write-Host "   Connecting to SharePoint Online ($spoAdminUrl)..." -ForegroundColor Yellow
        Connect-SPOService -Url $spoAdminUrl -ErrorAction Stop
        Write-Host "   SharePoint Online: connected" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "   Failed to connect to SharePoint Online: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "   Connect manually: Connect-SPOService -Url https://[tenant]-admin.sharepoint.com" -ForegroundColor Gray
        return $false
    }
}

# Simplified and Robust Authentication System with Auto-Scope Expansion
function Set-ServiceScopes {
    param([string]$Service)

    # Check if we have any active Graph connection
    $currentContext = Get-MgContext

    if (!$currentContext) {
        Write-Host "❌ Not connected to tenant. Please connect first." -ForegroundColor Red
        return $false
    }

    # Define comprehensive scopes for each service
    $serviceScopes = @{
        "Entra" = @(
            "User.ReadWrite.All",
            "Group.ReadWrite.All",
            "Directory.ReadWrite.All",
            "Policy.ReadWrite.ConditionalAccess",
            "RoleManagement.ReadWrite.Directory",
            "Policy.ReadWrite.SecurityDefaults",
            "Directory.AccessAsUser.All"
        )
        "Intune" = @(
            "DeviceManagementConfiguration.ReadWrite.All",
            "DeviceManagementManagedDevices.ReadWrite.All",
            "DeviceManagementApps.ReadWrite.All",
            "Group.ReadWrite.All",
            "Directory.ReadWrite.All"
        )
        "Exchange" = @(
            "Mail.ReadWrite",
            "MailboxSettings.ReadWrite",
            "Group.ReadWrite.All",
            "Directory.ReadWrite.All"
        )
        "Security" = @(
            "SecurityEvents.ReadWrite.All",
            "ThreatIndicators.ReadWrite.OwnedBy"
        )
        "Purview" = @(
            "InformationProtectionPolicy.Read",
            "RecordsManagement.ReadWrite.All"
        )
        "SharePoint" = @(
            "Sites.ReadWrite.All",
            "Sites.FullControl.All",
            "Group.ReadWrite.All"
        )
    }

    # Get required scopes for this service
    $requiredScopes = $serviceScopes[$Service]

    if (!$requiredScopes) {
        # Unknown service - use existing context
        Write-Host "✅ Using existing authentication context for $Service" -ForegroundColor Green
        return $true
    }

    # Check if we have all required scopes
    $currentScopes = $currentContext.Scopes
    $missingScopes = $requiredScopes | Where-Object { $_ -notin $currentScopes }

    if ($missingScopes.Count -gt 0) {
        Write-Host "⚠️ Additional permissions needed for $Service" -ForegroundColor Yellow
        Write-Host "Missing scopes: $($missingScopes.Count)" -ForegroundColor Gray
        Write-Host "🔄 Requesting additional permissions..." -ForegroundColor Cyan

        try {
            # Combine existing and new scopes
            $allScopes = @($currentScopes) + @($missingScopes) | Sort-Object -Unique

            # Reconnect with expanded scopes
            Connect-MgGraph -Scopes $allScopes -NoWelcome -ErrorAction Stop

            Write-Host "✅ Successfully obtained additional permissions" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "❌ Failed to obtain additional permissions: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "💡 You may need to consent to additional permissions in your browser" -ForegroundColor Yellow
            Write-Host "Press any key to return to menu..." -ForegroundColor Gray
            try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep 3 }
            return $false
        }
    }

    Write-Host "   Graph permissions ready for $Service" -ForegroundColor Green

    return $true
}

function Show-AuthenticationStatus {
    Write-Host "🔍 Authentication Status:" -ForegroundColor Cyan
    Write-Host "─" * 50 -ForegroundColor Gray
    
    $context = Get-MgContext
    if ($context) {
        Write-Host "✅ Connected to Microsoft Graph" -ForegroundColor Green
        Write-Host "   Account: $($context.Account)" -ForegroundColor White
        Write-Host "   Tenant ID: $($context.TenantId)" -ForegroundColor Gray
        Write-Host "   Active Scopes: $($context.Scopes.Count)" -ForegroundColor White
        
        if ($context.Scopes.Count -gt 0) {
            Write-Host ""
            Write-Host "🔐 Available Permissions:" -ForegroundColor Yellow
            $context.Scopes | Sort-Object | ForEach-Object {
                Write-Host "   • $_" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "❌ Not connected to Microsoft Graph" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "Press any key to continue..."
    try {
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    catch {
        Start-Sleep 1
    }
}

# Service menus with prerequisite blocking
function Show-EntraMenu {
    if (!(Set-ServiceScopes -Service "Entra")) { return }
    
    # Auto-refresh prerequisites when entering Entra menu
    Write-Host "🔄 Checking current prerequisites..." -ForegroundColor Gray
    Initialize-CompletedSteps
    Start-Sleep 1
    
    do {
        Clear-Host
        
        # Show compact progress dashboard
        if ($Global:CompletedSteps) {
            Show-CompactProgressDashboard -CompletedSteps $Global:CompletedSteps
            Show-CompactRecommendations -CompletedSteps $Global:CompletedSteps
            Write-Host ""
        }
        
        Write-Host "=" * 60 -ForegroundColor Cyan
        Write-Host "🏢 ENTRA ID AUTOMATION" -ForegroundColor Cyan
        Write-Host "=" * 60 -ForegroundColor Cyan
        
        # Check P2 license status
        $hasP2 = Test-EntraP2License
        if (-not $hasP2) {
            Write-Host "⚠️ LIMITED FUNCTIONALITY: Some features require Entra ID P2 licenses" -ForegroundColor Yellow
            Write-Host ""
        }
        
        # Security Groups - Always available (foundational) but dynamic groups need P2
        if ($hasP2) {
            Write-Host "1. 👥 Security Groups (Dynamic)" -ForegroundColor Green
        } else {
            Write-Host "1. 👥 Security Groups (Static - P2 required for dynamic)" -ForegroundColor Yellow
        }
        
        # Conditional Access - Requires Security Groups and P2
        if (Test-Prerequisites -RequiredStep "ConditionalAccess") {
            if ($hasP2) {
                Write-Host "2. 🛡️ Conditional Access Policies" -ForegroundColor Green
            } else {
                Write-Host "2. 🛡️ Conditional Access Policies [REQUIRES: P2 License]" -ForegroundColor Red
            }
        } else {
            Write-Host "2. 🛡️ Conditional Access Policies [REQUIRES: Security Groups]" -ForegroundColor Red
        }
        
        # Admin Creation - Requires Security Groups, P2 for PIM
        if (Test-Prerequisites -RequiredStep "AdminCreation") {
            if ($hasP2) {
                Write-Host "3. 👑 Admin Account Creation (with PIM)" -ForegroundColor Green
            } else {
                Write-Host "3. 👑 Admin Account Creation (Basic - P2 required for PIM)" -ForegroundColor Yellow
            }
        } else {
            Write-Host "3. 👑 Admin Account Creation [REQUIRES: Security Groups]" -ForegroundColor Red
        }
        
        # User Creation - Requires Security Groups
        if (Test-Prerequisites -RequiredStep "UserCreation") {
            Write-Host "4. 👤 User Creation & Management" -ForegroundColor Green
        } else {
            Write-Host "4. 👤 User Creation & Management [REQUIRES: Security Groups]" -ForegroundColor Red
        }
        
        # Password Policies - Requires Admin Accounts
        if (Test-Prerequisites -RequiredStep "PasswordPolicies") {
            Write-Host "5. 🔐 Password Policies" -ForegroundColor Green
        } else {
            Write-Host "5. 🔐 Password Policies [REQUIRES: Admin Accounts]" -ForegroundColor Red
        }
        
        Write-Host "0. ⬅️ Back to Main Menu"
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { 
                Invoke-GitHubScript -ScriptPath "entra/Security-Groups.ps1"
                Write-Host "🔄 Refreshing menu options..." -ForegroundColor Gray
                Initialize-CompletedSteps
            }
            "2" { 
                if (Test-Prerequisites -RequiredStep "ConditionalAccess") {
                    Invoke-GitHubScript -ScriptPath "entra/CA-Policies.ps1"
                    Write-Host "🔄 Refreshing menu options..." -ForegroundColor Gray
                    Initialize-CompletedSteps
                } else {
                    Write-Host "❌ Create Security Groups first!" -ForegroundColor Red
                    Start-Sleep 2
                }
            }
            "3" { 
                if (Test-Prerequisites -RequiredStep "AdminCreation") {
                    Invoke-GitHubScript -ScriptPath "entra/Admin-Creation.ps1"
                    Write-Host "🔄 Refreshing menu options..." -ForegroundColor Gray
                    Initialize-CompletedSteps
                } else {
                    Write-Host "❌ Create Security Groups first!" -ForegroundColor Red
                    Start-Sleep 2
                }
            }
            "4" {
                if (Test-Prerequisites -RequiredStep "UserCreation") {
                    $provKey = "external:M365-UserProvisioning-Enterprise"
                    if (!$Global:ScriptCache.ContainsKey($provKey)) {
                        Write-Host "📥 Downloading User Provisioning Tool..." -ForegroundColor Yellow
                        try {
                            $provUrl = "https://raw.githubusercontent.com/iceedd/M365-UserProvisioning-Tool/main/M365-UserProvisioning-Enterprise.ps1"
                            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                            $Global:ScriptCache[$provKey] = Invoke-RestMethod -Uri $provUrl -TimeoutSec 30 -ErrorAction Stop
                        }
                        catch {
                            Write-Host "❌ Failed to download provisioning tool: $($_.Exception.Message)" -ForegroundColor Red
                            Start-Sleep 3
                            break
                        }
                    }
                    # Write to a temp file and run in a separate pwsh process.
                    # This avoids scope/function collisions and module-removal side-effects
                    # in the parent menu session.
                    $tempScript = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.ps1'
                    try {
                        $Global:ScriptCache[$provKey] | Set-Content -Path $tempScript -Encoding UTF8
                        Write-Host "🚀 Launching User Provisioning Tool..." -ForegroundColor Cyan
                        Write-Host "   (The tool will open in a new window — return here when done)" -ForegroundColor Gray
                        # Extract Bearer token from current Graph session and pass via env var
                        # so the child process can connect silently without a login prompt.
                        $tenantId = (Get-MgContext).TenantId
                        try {
                            $resp = Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/v1.0/me' -Method GET -OutputType HttpResponseMessage -ErrorAction Stop
                            $bearerToken = $resp.RequestMessage.Headers.Authorization.Parameter
                            if ($bearerToken) { $env:M365_BEARER_TOKEN = $bearerToken }
                        } catch { }
                        $psArgs = "-NoProfile -File `"$tempScript`""
                        if ($tenantId) { $psArgs += " -TenantId `"$tenantId`"" }
                        Start-Process pwsh -ArgumentList $psArgs -Wait
                    }
                    catch {
                        Write-Host "❌ Provisioning tool error: $($_.Exception.Message)" -ForegroundColor Red
                        Start-Sleep 3
                    }
                    finally {
                        $env:M365_BEARER_TOKEN = $null
                        Remove-Item $tempScript -ErrorAction SilentlyContinue
                    }
                } else {
                    Write-Host "❌ Create Security Groups first!" -ForegroundColor Red
                    Start-Sleep 2
                }
            }
            "5" { 
                if (Test-Prerequisites -RequiredStep "PasswordPolicies") {
                    Invoke-GitHubScript -ScriptPath "entra/Password-Policies.ps1"
                    Write-Host "🔄 Refreshing menu options..." -ForegroundColor Gray
                    Initialize-CompletedSteps
                } else {
                    Write-Host "❌ Create Admin Accounts first!" -ForegroundColor Red
                    Start-Sleep 2
                }
            }
            "0" { break }
            default { Write-Host "❌ Invalid option!" -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($choice -ne "0")
}

function Show-IntuneMenu {
    if (!(Set-ServiceScopes -Service "Intune")) { return }
    
    # Auto-refresh prerequisites when entering Intune menu
    Write-Host "🔄 Checking current prerequisites..." -ForegroundColor Gray
    Initialize-CompletedSteps
    
    do {
        Clear-Host
        
        # Show compact progress dashboard
        if ($Global:CompletedSteps) {
            Show-CompactProgressDashboard -CompletedSteps $Global:CompletedSteps
            Show-CompactRecommendations -CompletedSteps $Global:CompletedSteps
            Write-Host ""
        }
        
        Write-Host "=" * 60 -ForegroundColor Magenta
        Write-Host "📱 INTUNE AUTOMATION" -ForegroundColor Magenta
        Write-Host "=" * 60 -ForegroundColor Magenta
        
        # Check P2 license status
        $hasP2 = Test-EntraP2License
        if (-not $hasP2) {
            Write-Host "⚠️ LIMITED FUNCTIONALITY: Dynamic device groups require Entra ID P2" -ForegroundColor Yellow
            Write-Host ""
        }
        
        # Device Groups - Always available (foundational for Intune) but dynamic groups need P2
        if ($hasP2) {
            Write-Host "1. 📱 Device Groups (Dynamic)" -ForegroundColor Green
        } else {
            Write-Host "1. 📱 Device Groups (Static - P2 required for dynamic)" -ForegroundColor Yellow
        }
        
        # Configuration Policies - Requires Device Groups
        if (Test-Prerequisites -RequiredStep "ConfigPolicies") {
            Write-Host "2. ⚙️ Configuration Policies" -ForegroundColor Green
        } else {
            Write-Host "2. ⚙️ Configuration Policies [REQUIRES: Device Groups]" -ForegroundColor Red
        }
        
        # Compliance Policies - Requires Device Groups
        if (Test-Prerequisites -RequiredStep "CompliancePolicies") {
            Write-Host "3. ✅ Compliance Policies" -ForegroundColor Green
        } else {
            Write-Host "3. ✅ Compliance Policies [REQUIRES: Device Groups]" -ForegroundColor Red
        }
        
        # App Deployment - Requires Device Groups AND Compliance Policies
        if (Test-Prerequisites -RequiredStep "AppDeployment") {
            Write-Host "4. 📦 Application Deployment" -ForegroundColor Green
        } else {
            Write-Host "4. 📦 Application Deployment [REQUIRES: Device Groups + Compliance Policies]" -ForegroundColor Red
        }
        
        # Autopilot - Requires Device Groups
        if (Test-Prerequisites -RequiredStep "AutopilotConfig") {
            Write-Host "5. 🚀 Autopilot Configuration" -ForegroundColor Green
        } else {
            Write-Host "5. 🚀 Autopilot Configuration [REQUIRES: Device Groups]" -ForegroundColor Red
        }
        
        Write-Host "0. ⬅️ Back to Main Menu"
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { 
                Invoke-GitHubScript -ScriptPath "Intune/Device-Groups.ps1"
                Write-Host "🔄 Refreshing menu options..." -ForegroundColor Gray
                Initialize-CompletedSteps
            }
            "2" { 
                if (Test-Prerequisites -RequiredStep "ConfigPolicies") {
                    Invoke-GitHubScript -ScriptPath "Intune/Configuration-Policies.ps1"
                    Write-Host "🔄 Refreshing menu options..." -ForegroundColor Gray
                    Initialize-CompletedSteps
                } else {
                    Write-Host "❌ Create Device Groups first!" -ForegroundColor Red
                    Start-Sleep 2
                }
            }
            "3" { 
                if (Test-Prerequisites -RequiredStep "CompliancePolicies") {
                    Invoke-GitHubScript -ScriptPath "Intune/Compliance-Policies.ps1"
                    Write-Host "🔄 Refreshing menu options..." -ForegroundColor Gray
                    Initialize-CompletedSteps
                } else {
                    Write-Host "❌ Create Device Groups first!" -ForegroundColor Red
                    Start-Sleep 2
                }
            }
            "4" { 
                if (Test-Prerequisites -RequiredStep "AppDeployment") {
                    Invoke-GitHubScript -ScriptPath "Intune/App-Deployment.ps1"
                    Write-Host "🔄 Refreshing menu options..." -ForegroundColor Gray
                    Initialize-CompletedSteps
                } else {
                    Write-Host "❌ Create Device Groups and Compliance Policies first!" -ForegroundColor Red
                    Start-Sleep 2
                }
            }
            "5" { 
                if (Test-Prerequisites -RequiredStep "AutopilotConfig") {
                    Invoke-GitHubScript -ScriptPath "Intune/Autopilot-Config.ps1"
                    Write-Host "🔄 Refreshing menu options..." -ForegroundColor Gray
                    Initialize-CompletedSteps
                } else {
                    Write-Host "❌ Create Device Groups first!" -ForegroundColor Red
                    Start-Sleep 2
                }
            }
            "0" { break }
            default { Write-Host "❌ Invalid option!" -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($choice -ne "0")
}

function Show-ExchangeMenu {
    if (!(Set-ServiceScopes -Service "Exchange")) { return }

    # Ensure Exchange Online connection
    Write-Host "🔄 Checking Exchange Online connection..." -ForegroundColor Gray

    try {
        # Check if ExchangeOnlineManagement module is available
        if (!(Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
            Write-Host "📦 Installing ExchangeOnlineManagement module..." -ForegroundColor Yellow
            Install-Module ExchangeOnlineManagement -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
        }

        if (!(Get-Module -Name ExchangeOnlineManagement)) {
            Import-Module ExchangeOnlineManagement -Force -ErrorAction Stop
        }

        # Check if already connected using modern method
        $exoConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue
        if (!$exoConnection -or $exoConnection.State -ne "Connected") {
            Write-Host "🔐 Connecting to Exchange Online..." -ForegroundColor Yellow
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
            Write-Host "✅ Connected to Exchange Online" -ForegroundColor Green
        } else {
            Write-Host "✅ Exchange Online: Connected as $($exoConnection.UserPrincipalName)" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "❌ Failed to connect to Exchange Online: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "   Press any key to return to main menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep 2 }
        return
    }

    # Auto-refresh prerequisites when entering Exchange menu
    Write-Host "🔄 Checking current prerequisites..." -ForegroundColor Gray
    Initialize-CompletedSteps
    
    do {
        Clear-Host
        
        # Show compact progress dashboard
        if ($Global:CompletedSteps) {
            Show-CompactProgressDashboard -CompletedSteps $Global:CompletedSteps
            Show-CompactRecommendations -CompletedSteps $Global:CompletedSteps
            Write-Host ""
        }
        
        Write-Host "=" * 60 -ForegroundColor Blue
        Write-Host "📧 EXCHANGE ONLINE AUTOMATION" -ForegroundColor Blue
        Write-Host "=" * 60 -ForegroundColor Blue
        
        # Shared Mailboxes - Always available
        Write-Host "1. 📫 Shared Mailbox Creation" -ForegroundColor Green
        
        # Archive Policies - Requires basic setup
        if (Test-Prerequisites -RequiredStep "ArchivePolicies") {
            Write-Host "2. 📦 Archive Policies" -ForegroundColor Green
        } else {
            Write-Host "2. 📦 Archive Policies [REQUIRES: Security Groups]" -ForegroundColor Red
        }
        
        # Distribution Lists - Requires Security Groups
        if (Test-Prerequisites -RequiredStep "DistributionLists") {
            Write-Host "3. 📋 Distribution Lists" -ForegroundColor Green
        } else {
            Write-Host "3. 📋 Distribution Lists [REQUIRES: Security Groups]" -ForegroundColor Red
        }
        
        # Mail Flow Rules - Always available
        Write-Host "4. 📨 Mail Flow Rules" -ForegroundColor Green
        
        Write-Host "0. ⬅️ Back to Main Menu"
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { 
                Invoke-GitHubScript -ScriptPath "Exchange/Shared-MB-Creation.ps1"
                Write-Host "🔄 Refreshing menu options..." -ForegroundColor Gray
                Initialize-CompletedSteps
            }
            "2" { 
                if (Test-Prerequisites -RequiredStep "ArchivePolicies") {
                    Invoke-GitHubScript -ScriptPath "Exchange/Archive-Policies.ps1"
                    Write-Host "🔄 Refreshing menu options..." -ForegroundColor Gray
                    Initialize-CompletedSteps
                } else {
                    Write-Host "❌ Create Security Groups first!" -ForegroundColor Red
                    Start-Sleep 2
                }
            }
            "3" { 
                if (Test-Prerequisites -RequiredStep "DistributionLists") {
                    Invoke-GitHubScript -ScriptPath "Exchange/Distribution-Lists.ps1"
                    Write-Host "🔄 Refreshing menu options..." -ForegroundColor Gray
                    Initialize-CompletedSteps
                } else {
                    Write-Host "❌ Create Security Groups first!" -ForegroundColor Red
                    Start-Sleep 2
                }
            }
            "4" { 
                Invoke-GitHubScript -ScriptPath "Exchange/Mail-Flow-Rules.ps1"
                Write-Host "🔄 Refreshing menu options..." -ForegroundColor Gray
                Initialize-CompletedSteps
            }
            "0" { break }
            default { Write-Host "❌ Invalid option!" -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($choice -ne "0")
}

function Show-SharePointMenu {
    if (!(Set-ServiceScopes -Service "SharePoint")) { return }

    # Establish SPO service connection (separate from Graph)
    Write-Host ""
    if (!(Connect-SharePointOnline)) {
        Write-Host "   ❌ Could not connect to SharePoint Online." -ForegroundColor Red
        Write-Host "   Press any key to return to main menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep 3 }
        return
    }

    do {
        Clear-Host
        
        # Show compact progress dashboard
        if ($Global:CompletedSteps) {
            Show-CompactProgressDashboard -CompletedSteps $Global:CompletedSteps
            Show-CompactRecommendations -CompletedSteps $Global:CompletedSteps
            Write-Host ""
        }
        
        Write-Host "=" * 60 -ForegroundColor Green
        Write-Host "🌐 SHAREPOINT ONLINE AUTOMATION" -ForegroundColor Green
        Write-Host "=" * 60 -ForegroundColor Green
        Write-Host "1. 🏢 Site Collection Creation" -ForegroundColor Green
        Write-Host "2. 👥 Permission Groups (audit/repair)" -ForegroundColor Green
        Write-Host "3. 🔗 External Sharing Policies" -ForegroundColor Green
        Write-Host "4. 🔐 Site Groups (Entra security groups)" -ForegroundColor Green
        Write-Host "0. ⬅️ Back to Main Menu"
        Write-Host ""

        $choice = Read-Host "Select option"

        switch ($choice) {
            "1" { Invoke-GitHubScript -ScriptPath "SharePoint/Site-Creation.ps1" }
            "2" { Invoke-GitHubScript -ScriptPath "SharePoint/Permission-Groups.ps1" }
            "3" { Invoke-GitHubScript -ScriptPath "SharePoint/External-Sharing.ps1" }
            "4" { Invoke-GitHubScript -ScriptPath "SharePoint/Site-Groups.ps1" }
            "0" { break }
            default { Write-Host "❌ Invalid option!" -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($choice -ne "0")
}

function Show-SecurityMenu {
    if (!(Set-ServiceScopes -Service "Security")) { return }
    
    do {
        Clear-Host
        
        # Show compact progress dashboard
        if ($Global:CompletedSteps) {
            Show-CompactProgressDashboard -CompletedSteps $Global:CompletedSteps
            Show-CompactRecommendations -CompletedSteps $Global:CompletedSteps
            Write-Host ""
        }
        
        Write-Host "=" * 60 -ForegroundColor Red
        Write-Host "🛡️ SECURITY & DEFENDER AUTOMATION" -ForegroundColor Red
        Write-Host "=" * 60 -ForegroundColor Red
        Write-Host "1. 🌐 Web Content Filtering" -ForegroundColor Green
        Write-Host "2. 📎 Safe Attachments/Links" -ForegroundColor Green
        Write-Host "3. 🎣 Anti-phishing Policies" -ForegroundColor Green
        Write-Host "0. ⬅️ Back to Main Menu"
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Invoke-GitHubScript -ScriptPath "Security/Web-Filtering.ps1" }
            "2" { Invoke-GitHubScript -ScriptPath "Security/Safe-Attachments.ps1" }
            "3" { Invoke-GitHubScript -ScriptPath "Security/Anti-Phishing.ps1" }
            "0" { break }
            default { Write-Host "❌ Invalid option!" -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($choice -ne "0")
}

function Show-PurviewMenu {
    if (!(Set-ServiceScopes -Service "Purview")) { return }
    
    do {
        Clear-Host
        
        # Show compact progress dashboard
        if ($Global:CompletedSteps) {
            Show-CompactProgressDashboard -CompletedSteps $Global:CompletedSteps
            Show-CompactRecommendations -CompletedSteps $Global:CompletedSteps
            Write-Host ""
        }
        
        Write-Host "=" * 60 -ForegroundColor DarkCyan
        Write-Host "🔒 PURVIEW COMPLIANCE AUTOMATION" -ForegroundColor DarkCyan
        Write-Host "=" * 60 -ForegroundColor DarkCyan
        Write-Host "1. 📋 Retention Policies" -ForegroundColor Green
        Write-Host "2. 🛡️ Data Loss Prevention" -ForegroundColor Green
        Write-Host "3. 🏷️ Sensitivity Labels" -ForegroundColor Green
        Write-Host "0. ⬅️ Back to Main Menu"
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Invoke-GitHubScript -ScriptPath "Purview/Retention-Policies.ps1" }
            "2" { Invoke-GitHubScript -ScriptPath "Purview/DLP-Policies.ps1" }
            "3" { Invoke-GitHubScript -ScriptPath "Purview/Sensitivity-Labels.ps1" }
            "0" { break }
            default { Write-Host "❌ Invalid option!" -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($choice -ne "0")
}

# Refresh script cache
function Clear-ScriptCache {
    $Global:ScriptCache.Clear()
    Write-Host "🔄 Script cache cleared!" -ForegroundColor Green
}

# Enhanced Main Menu with Progress Dashboard and Interactive Navigation
function Show-MainMenu {
    # First show the progress dashboard
    Clear-Host
    
    if ($Global:TenantConnection) {
        Write-Host ""
        Write-Host "✅ Connected to: $($Global:TenantConnection.OrgName)" -ForegroundColor Green
        Write-Host "   Account: $($Global:TenantConnection.Account)" -ForegroundColor Gray
        Write-Host ""
        
        # Show Enhanced Progress Dashboard
        Show-EnhancedProgressDashboard -CompletedSteps $Global:CompletedSteps
        
        # Show Smart Recommendations
        Show-SmartRecommendations -CompletedSteps $Global:CompletedSteps
    } else {
        Write-Host "╔═══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "║                          🚀 M365 TENANT AUTOMATION HUB                       ║" -ForegroundColor Red
        Write-Host "║                                                                               ║" -ForegroundColor Red
        Write-Host "║                          ❌ NOT CONNECTED TO TENANT                           ║" -ForegroundColor Red
        Write-Host "║                     Please connect to get started (Option 8)                  ║" -ForegroundColor Red
        Write-Host "╚═══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
        Write-Host ""
    }
    
    Write-Host ""
    Write-Host "💡 TIP: Use arrow keys for navigation or type numbers!" -ForegroundColor Yellow
    Write-Host "Press any key to continue to menu..." -ForegroundColor Gray
    try {
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    catch {
        # Fallback for non-interactive environments - just continue
        Start-Sleep 1
    }
    
    # Then switch to interactive menu
    return Show-InteractiveMainMenu
}

function Show-DebugStatusOverride {
    Write-Host "🛠️ Debug Tools" -ForegroundColor Yellow
    Write-Host "─" * 80 -ForegroundColor Gray
    Write-Host ""
    Write-Host "1. 📊 Manual Status Override" -ForegroundColor White
    Write-Host "2. 🔍 Authentication Status" -ForegroundColor White
    Write-Host "3. 📋 License Information" -ForegroundColor White
    Write-Host "0. ⬅️ Back to Main Menu" -ForegroundColor White
    Write-Host ""
    
    $debugChoice = Read-Host "Select debug option"
    
    if ($debugChoice -eq "2") {
        Show-AuthenticationStatus
        return
    }
    elseif ($debugChoice -eq "3") {
        Write-Host "📋 License Information:" -ForegroundColor Cyan
        Write-Host "─" * 50 -ForegroundColor Gray
        Test-EntraP2License -ShowDetails
        return
    }
    elseif ($debugChoice -ne "1") {
        return
    }
    
    Write-Host ""
    Write-Host "📊 Manual Status Override:" -ForegroundColor Cyan
    
    $steps = @{
        "1" = @{ Name = "Security Groups"; Key = "SecurityGroups" }
        "2" = @{ Name = "Admin Accounts"; Key = "AdminAccounts" }
        "3" = @{ Name = "Device Groups"; Key = "DeviceGroups" }
        "4" = @{ Name = "Configuration Policies"; Key = "ConfigPolicies" }
        "5" = @{ Name = "Compliance Policies"; Key = "CompliancePolicies" }
        "6" = @{ Name = "Conditional Access"; Key = "ConditionalAccess" }
    }
    
    foreach ($num in $steps.Keys | Sort-Object) {
        $step = $steps[$num]
        $status = if ($Global:CompletedSteps[$step.Key]) { "✅ Complete" } else { "⏳ Pending" }
        $color = if ($Global:CompletedSteps[$step.Key]) { "Green" } else { "Yellow" }
        Write-Host "$num. $($step.Name): " -NoNewline -ForegroundColor White
        Write-Host "$status" -ForegroundColor $color
    }
    
    Write-Host ""
    Write-Host "Enter number to toggle status (or 'q' to quit):"
    $choice = Read-Host "Selection"
    
    if ($choice -eq 'q') { return }
    
    if ($steps.ContainsKey($choice)) {
        $step = $steps[$choice]
        $Global:CompletedSteps[$step.Key] = -not $Global:CompletedSteps[$step.Key]
        $newStatus = if ($Global:CompletedSteps[$step.Key]) { "Complete" } else { "Pending" }
        Write-Host "✅ $($step.Name) marked as: $newStatus" -ForegroundColor Green
        Save-SessionState
        Start-Sleep 1
    }
    else {
        Write-Host "Invalid selection!" -ForegroundColor Red
        Start-Sleep 1
    }
}

# Main execution loop
function Invoke-SelfUpdate {
    try {
        Write-Host "   Checking for menu updates..." -ForegroundColor Gray
        $url     = "https://raw.githubusercontent.com/$Global:GitHubRepo/$Global:GitHubBranch/Main-Menu.ps1"
        $content = Invoke-RestMethod -Uri $url -TimeoutSec 10 -ErrorAction Stop

        $match = [regex]::Match($content, '\.VERSION\s+(\S+)')
        if (!$match.Success) { return }

        $remoteVersion = [version]$match.Groups[1].Value
        $localVersion  = [version]$Script:MenuVersion

        if ($remoteVersion -le $localVersion) {
            Write-Host "   Menu is up to date (v$localVersion)" -ForegroundColor Green
            return
        }

        Write-Host ""
        Write-Host "   UPDATE AVAILABLE  v$localVersion  ->  v$remoteVersion" -ForegroundColor Yellow
        Write-Host "   A newer Main-Menu.ps1 is available on GitHub." -ForegroundColor White
        Write-Host ""

        # If we know where the script lives, offer to auto-update
        if ($PSCommandPath) {
            $answer = Read-Host "   Update and restart now? (Y/N)"
            if ($answer -notlike "Y*") {
                Write-Host "   Skipping — you will be prompted again next run" -ForegroundColor Gray
                return
            }
            $content | Set-Content -Path $PSCommandPath -Encoding UTF8 -Force
            Write-Host "   Updated to v$remoteVersion. Please re-run the script." -ForegroundColor Green
            Write-Host ""
            Write-Host "   Press any key to exit..." -ForegroundColor Gray
            try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep 2 }
            exit
        }
        else {
            # Running via IEX/launcher — can't auto-overwrite, show manual instructions
            Write-Host "   ACTION REQUIRED: Re-download Main-Menu.ps1 to get the latest version." -ForegroundColor Yellow
            Write-Host "   Run in PowerShell:" -ForegroundColor White
            Write-Host "   Invoke-RestMethod 'https://raw.githubusercontent.com/cbro09/Complete-365Tenant-Creation/main/Main-Menu.ps1' | Out-File Main-Menu.ps1 -Encoding UTF8" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "   Press any key to continue with current version..." -ForegroundColor Gray
            try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep 3 }
        }
    }
    catch {
        Write-Host "   Could not check for updates (no network?)" -ForegroundColor Gray
    }
}

function Start-AutomationHub {
    Invoke-SelfUpdate
    Initialize-Modules
    Initialize-SharedHelpers

    # Try to load previous session state
    if (Import-SessionState) {
        Show-SessionInfo
    }

    do {
        $choice = Show-InteractiveMainMenu
        
        switch ($choice) {
            "1" { 
                if ($Global:TenantConnection) { Show-EntraMenu } 
                else { Write-Host "Please connect to tenant first!" -ForegroundColor Red; Start-Sleep 2 }
            }
            "2" { 
                if ($Global:TenantConnection) { Show-IntuneMenu } 
                else { Write-Host "Please connect to tenant first!" -ForegroundColor Red; Start-Sleep 2 }
            }
            "3" { 
                if ($Global:TenantConnection) { Show-ExchangeMenu } 
                else { Write-Host "Please connect to tenant first!" -ForegroundColor Red; Start-Sleep 2 }
            }
            "4" { 
                if ($Global:TenantConnection) { Show-SharePointMenu } 
                else { Write-Host "Please connect to tenant first!" -ForegroundColor Red; Start-Sleep 2 }
            }
            "5" { 
                if ($Global:TenantConnection) { Show-SecurityMenu } 
                else { Write-Host "Please connect to tenant first!" -ForegroundColor Red; Start-Sleep 2 }
            }
            "6" { 
                if ($Global:TenantConnection) { Show-PurviewMenu } 
                else { Write-Host "Please connect to tenant first!" -ForegroundColor Red; Start-Sleep 2 }
            }
            "7" {
                if ($Global:TenantConnection) { 
                    if (Show-QuickStartWizard) {
                        Start-QuickStartFlow
                    }
                } 
                else { Write-Host "Please connect to tenant first!" -ForegroundColor Red; Start-Sleep 2 }
            }
            "8" {
                Write-Host "🔄 Starting connection process..." -ForegroundColor Cyan
                $connectionResult = Connect-M365Tenant
                
                if ($connectionResult) {
                    Write-Host "🔍 Checking tenant prerequisites..." -ForegroundColor Yellow
                    Initialize-CompletedSteps
                    Write-Host "✅ Prerequisites checked! Service menus will auto-refresh status." -ForegroundColor Green
                    Save-SessionState
                } else {
                    Write-Host "❌ Connection failed. Please try again." -ForegroundColor Red
                    Write-Host "Press any key to continue..." -ForegroundColor Gray
                    try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep 2 }
                }
            }
            "9" { 
                Clear-ScriptCache
                Write-Host "🧹 Session state cleared!" -ForegroundColor Green
                Clear-SessionState
            }
            "d" { Show-DebugStatusOverride }
            "r" { 
                Write-Host "🧠 Testing Smart Recommendations..." -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Current Completion Status:" -ForegroundColor Yellow
                Write-Host "• Security Groups: $(if ($Global:CompletedSteps.SecurityGroups) { '✅ Complete' } else { '❌ Not Complete' })" -ForegroundColor $(if ($Global:CompletedSteps.SecurityGroups) { 'Green' } else { 'Red' })
                Write-Host "• Admin Accounts: $(if ($Global:CompletedSteps.AdminAccounts) { '✅ Complete' } else { '❌ Not Complete' })" -ForegroundColor $(if ($Global:CompletedSteps.AdminAccounts) { 'Green' } else { 'Red' })
                Write-Host "• Conditional Access: $(if ($Global:CompletedSteps.ConditionalAccess) { '✅ Complete' } else { '❌ Not Complete' })" -ForegroundColor $(if ($Global:CompletedSteps.ConditionalAccess) { 'Green' } else { 'Red' })
                Write-Host "• Device Groups: $(if ($Global:CompletedSteps.DeviceGroups) { '✅ Complete' } else { '❌ Not Complete' })" -ForegroundColor $(if ($Global:CompletedSteps.DeviceGroups) { 'Green' } else { 'Red' })
                Write-Host "• Config Policies: $(if ($Global:CompletedSteps.ConfigPolicies) { '✅ Complete' } else { '❌ Not Complete' })" -ForegroundColor $(if ($Global:CompletedSteps.ConfigPolicies) { 'Green' } else { 'Red' })
                Write-Host "• EDR Policy: $(if ($Global:CompletedSteps.EDRPolicy) { '✅ Complete' } else { '❌ Not Complete (Manual Setup)' })" -ForegroundColor $(if ($Global:CompletedSteps.EDRPolicy) { 'Green' } else { 'Yellow' })
                Write-Host "• Compliance Policies: $(if ($Global:CompletedSteps.CompliancePolicies) { '✅ Complete' } else { '❌ Not Complete' })" -ForegroundColor $(if ($Global:CompletedSteps.CompliancePolicies) { 'Green' } else { 'Red' })
                Write-Host ""
                Show-SmartRecommendations -CompletedSteps $Global:CompletedSteps
                Write-Host ""
                Write-Host "Press any key to continue..." -ForegroundColor Gray
                try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep 2 }
            }
            "a" {
                Write-Host "🔐 Checking Authentication Status..." -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Service Authentication Status:" -ForegroundColor Yellow
                Write-Host "─" * 50 -ForegroundColor Gray
                
                $services = @("Entra", "Intune", "Exchange", "SharePoint", "Security", "Purview")
                foreach ($service in $services) {
                    Write-Host "$service Service:" -ForegroundColor White
                    Test-ServiceAuthentication -Service $service -ShowStatus | Out-Null
                }
                
                Write-Host ""
                Write-Host "Authentication Recommendations:" -ForegroundColor Yellow
                if (!(Get-MgContext)) {
                    Write-Host "• Connect to Microsoft Graph first (option 8)" -ForegroundColor Red
                } else {
                    Write-Host "• Microsoft Graph connected ✅" -ForegroundColor Green
                    Write-Host "• Most services will work with Graph authentication" -ForegroundColor Green
                    Write-Host "• Exchange scripts will auto-connect to Exchange Online when needed" -ForegroundColor Yellow
                }
                
                Write-Host ""
                Write-Host "Press any key to continue..." -ForegroundColor Gray
                try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep 2 }
            }
            "0" { 
                Write-Host "💾 Saving session state..." -ForegroundColor Gray
                Save-SessionState
                Write-Host "Goodbye! 👋" -ForegroundColor Cyan
                if ($Global:TenantConnection) { Disconnect-MgGraph -ErrorAction SilentlyContinue }
                break 
            }
            default { Write-Host "❌ Invalid option!" -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($choice -ne "0")
}

# Start the automation hub
Start-AutomationHub

# ▼ CB & Claude | BITS 365 Automation | v1.0 | "Smarter not Harder"