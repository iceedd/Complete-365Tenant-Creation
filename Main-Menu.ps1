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
    1.0
#>

# Global Variables
$Global:TenantConnection = $null
$Global:CurrentScopes = @()
$Global:GitHubRepo = "cbro09/Complete-365Tenant-Creation"
$Global:GitHubBranch = "main" # Change to "dev" for testing
$Global:ScriptCache = @{}

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

# Download script from GitHub
function Get-GitHubScript {
    param(
        [string]$ScriptPath,
        [string]$Branch = $Global:GitHubBranch
    )
    
    $url = "https://raw.githubusercontent.com/$Global:GitHubRepo/$Branch/$ScriptPath"
    
    try {
        $response = Invoke-RestMethod -Uri $url -ErrorAction Stop
        return $response
    }
    catch {
        Write-Error "Failed to download $ScriptPath from GitHub: $($_.Exception.Message)"
        return $null
    }
}

# Execute downloaded script
function Invoke-GitHubScript {
    param(
        [string]$ScriptPath,
        [hashtable]$Parameters = @{}
    )
    
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

function Load-SessionState {
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
        [int]$InitialSelection = 0
    )
    
    $selectedIndex = $InitialSelection
    $maxIndex = $MenuItems.Count - 1
    
    do {
        # Clear screen and show title
        Clear-Host
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
    # Build menu items array
    $menuItems = @()
    
    if ($Global:TenantConnection) {
        $menuItems += @{ Display = "🏢 Entra ID (Identity & Access Management)"; Value = "1" }
        $menuItems += @{ Display = "📱 Intune (Device Management & Compliance)"; Value = "2" }
        $menuItems += @{ Display = "📧 Exchange Online (Email & Collaboration)"; Value = "3" }
        $menuItems += @{ Display = "🌐 SharePoint Online (File Sharing & Sites)"; Value = "4" }
        $menuItems += @{ Display = "🛡️ Security & Defender (Threat Protection)"; Value = "5" }
        $menuItems += @{ Display = "🔒 Purview (Data Governance & Compliance)"; Value = "6" }
        $menuItems += @{ Display = "─" * 50; Value = "separator1" }
        $menuItems += @{ Display = "🚀 Quick Start Wizard (Guided Setup)"; Value = "7" }
        $menuItems += @{ Display = "🔄 Refresh Scripts & Status"; Value = "9" }
        $menuItems += @{ Display = "🛠️ Debug: Manual Status Override"; Value = "d" }
    }
    else {
        $menuItems += @{ Display = "🔐 Connect to Tenant (Required First Step)"; Value = "8" }
    }
    
    $menuItems += @{ Display = "─" * 50; Value = "separator2" }
    $menuItems += @{ Display = "❌ Exit Application"; Value = "0" }
    
    # Filter out separators for navigation
    $navigableItems = $menuItems | Where-Object { $_.Value -notlike "separator*" }
    
    return Get-MenuSelection -MenuItems $navigableItems -Title "🚀 M365 TENANT AUTOMATION HUB"
}

function Show-InteractiveSubMenu {
    param(
        [array]$MenuItems,
        [string]$Title,
        [string]$ServiceIcon = "🔧"
    )
    
    $fullTitle = "$ServiceIcon $Title"
    return Get-MenuSelection -MenuItems $MenuItems -Title $fullTitle
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
                      elseif (-not $CompletedSteps.ConfigPolicies) { "Configure Device Policies" }
                      elseif (-not $CompletedSteps.CompliancePolicies) { "Setup Compliance Policies" }
                      else { "Complete ✓" }
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
    $overallPercentage = if ($overallTotal -gt 0) { [math]::Round(($overallCompleted / $overallTotal) * 100) } else { 0 }
    
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
    
    # Priority 1: Foundation setup
    if (-not $CompletedSteps.SecurityGroups) {
        $recommendations += @{
            Priority = "High"
            Title = "🏗️ Start with Security Groups"
            Description = "Create foundation security groups for user management and licensing"
            Action = "Go to Entra ID → Security Groups"
            Icon = "🚨"
        }
    }
    elseif (-not $CompletedSteps.AdminAccounts) {
        $recommendations += @{
            Priority = "High"
            Title = "👑 Create Admin Accounts"
            Description = "Set up administrative accounts with proper break-glass access"
            Action = "Go to Entra ID → Admin Account Creation"
            Icon = "⚡"
        }
    }
    
    # Priority 2: Device management
    if ($CompletedSteps.SecurityGroups -and -not $CompletedSteps.DeviceGroups) {
        $recommendations += @{
            Priority = "Medium"
            Title = "📱 Setup Device Management"
            Description = "Create device groups for Intune policy assignments"
            Action = "Go to Intune → Device Groups"
            Icon = "🎯"
        }
    }
    
    # Priority 3: Security policies
    if ($CompletedSteps.DeviceGroups -and -not $CompletedSteps.CompliancePolicies) {
        $recommendations += @{
            Priority = "Medium"
            Title = "✅ Configure Compliance"
            Description = "Set up device compliance policies for security"
            Action = "Go to Intune → Compliance Policies"
            Icon = "🛡️"
        }
    }
    
    # Conditional Access - only if prerequisites met but not completed
    if ($CompletedSteps.SecurityGroups -and $CompletedSteps.AdminAccounts -and -not $CompletedSteps.ConditionalAccess) {
        $recommendations += @{
            Priority = "Medium"
            Title = "🔐 Setup Conditional Access"
            Description = "Implement conditional access policies for enhanced security"
            Action = "Go to Entra ID → Conditional Access Policies"
            Icon = "🔒"
        }
    }
    
    # Configuration Policies - if device groups exist but config policies don't
    if ($CompletedSteps.DeviceGroups -and -not $CompletedSteps.ConfigPolicies) {
        $recommendations += @{
            Priority = "Medium"
            Title = "⚙️ Configure Device Policies"
            Description = "Set up device configuration policies for security settings"
            Action = "Go to Intune → Configuration Policies"
            Icon = "🛠️"
        }
    }
    
    # Next service areas
    if ($CompletedSteps.SecurityGroups -and $CompletedSteps.AdminAccounts -and $CompletedSteps.DeviceGroups) {
        $recommendations += @{
            Priority = "Low"
            Title = "📧 Setup Exchange Online"
            Description = "Configure email and collaboration features"
            Action = "Go to Exchange Online → Shared Mailboxes"
            Icon = "📬"
        }
        
        $recommendations += @{
            Priority = "Low"
            Title = "🛡️ Configure Security Policies"
            Description = "Set up threat protection and security features"
            Action = "Go to Security & Defender → Safe Attachments"
            Icon = "🔐"
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
            "License - Business Basic", "License - Business Standard",
            "License - Business Premium", "License - Exchange Online Plan 1",
            "License - Exchange Online Plan 2"
        )
        DeviceGroups = Test-GroupsExist -GroupNames @(
            "Windows Devices (Autopilot)", "macOS Devices", "iOS Devices",
            "Android Devices", "Corporate Owned Devices", "Personal Devices",
            "Pilot Device Group"
        )
        ConfigPolicies = Test-PoliciesExist -PolicyNames @(
            "Defender Configuration", "Enable Bitlocker", "EDR Policy",
            "Office Updates Configuration", "OneDrive Configuration",
            "Outlook Configuration", "Tamper Protection", "Web Sign-in Policy"
        )
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
        # Disconnect any existing connection
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        
        # Use a practical set of scopes that cover most common scenarios
        $practicalScopes = @(
            "Organization.Read.All",
            "Directory.Read.All", 
            "Directory.ReadWrite.All",
            "User.ReadWrite.All",
            "Group.ReadWrite.All",
            "Policy.ReadWrite.ConditionalAccess"
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

# Simplified and Robust Authentication System
function Set-ServiceScopes {
    param([string]$Service)
    
    # Check if we have any active Graph connection
    $currentContext = Get-MgContext
    
    if (!$currentContext) {
        Write-Host "❌ Not connected to tenant. Please connect first." -ForegroundColor Red
        return $false
    }
    
    # Simple approach: If we're already connected, we assume permissions are sufficient
    # This avoids complex scope management that can cause issues
    Write-Host "✅ Using existing $Service authentication context" -ForegroundColor Green
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
        # Build dynamic menu items based on prerequisites
        $menuItems = @()
        
        # Security Groups - Always available (foundational)
        $menuItems += @{ 
            Display = "👥 Security Groups (Dynamic)"; 
            Value = "1"
        }
        
        # Conditional Access - Requires Security Groups
        if (Test-Prerequisites -RequiredStep "ConditionalAccess") {
            $menuItems += @{ 
                Display = "🛡️ Conditional Access Policies"; 
                Value = "2" 
            }
        } else {
            $menuItems += @{ 
                Display = "🛡️ Conditional Access Policies [REQUIRES: Security Groups]"; 
                Value = "2-disabled" 
            }
        }
        
        # Admin Creation - Requires Security Groups
        if (Test-Prerequisites -RequiredStep "AdminCreation") {
            $menuItems += @{ 
                Display = "👑 Admin Account Creation"; 
                Value = "3" 
            }
        } else {
            $menuItems += @{ 
                Display = "👑 Admin Account Creation [REQUIRES: Security Groups]"; 
                Value = "3-disabled" 
            }
        }
        
        # User Creation - Requires Security Groups
        if (Test-Prerequisites -RequiredStep "UserCreation") {
            $menuItems += @{ 
                Display = "👤 User Creation & Management"; 
                Value = "4" 
            }
        } else {
            $menuItems += @{ 
                Display = "👤 User Creation & Management [REQUIRES: Security Groups]"; 
                Value = "4-disabled" 
            }
        }
        
        # Password Policies - Requires Admin Accounts
        if (Test-Prerequisites -RequiredStep "PasswordPolicies") {
            $menuItems += @{ 
                Display = "🔐 Password Policies"; 
                Value = "5" 
            }
        } else {
            $menuItems += @{ 
                Display = "🔐 Password Policies [REQUIRES: Admin Accounts]"; 
                Value = "5-disabled" 
            }
        }
        
        $menuItems += @{ Display = "⬅️ Back to Main Menu"; Value = "0" }
        
        # Filter out disabled items for navigation
        $navigableItems = $menuItems | Where-Object { $_.Value -notlike "*-disabled" }
        
        $choice = Show-InteractiveSubMenu -MenuItems $navigableItems -Title "ENTRA ID AUTOMATION" -ServiceIcon "🏢"
        
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
                    Invoke-GitHubScript -ScriptPath "entra/User-Creation.ps1"
                    Write-Host "🔄 Refreshing menu options..." -ForegroundColor Gray
                    Initialize-CompletedSteps
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
        Write-Host "`n" + "=" * 60 -ForegroundColor Magenta
        Write-Host "📱 INTUNE AUTOMATION" -ForegroundColor Magenta
        Write-Host "=" * 60 -ForegroundColor Magenta
        
        # Device Groups - Always available (foundational for Intune)
        Write-Host "1. 📱 Device Groups (OS-based)" -ForegroundColor Green
        
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
    
    # Auto-refresh prerequisites when entering Exchange menu
    Write-Host "🔄 Checking current prerequisites..." -ForegroundColor Gray
    Initialize-CompletedSteps
    
    do {
        Write-Host "`n" + "=" * 60 -ForegroundColor Blue
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
    
    do {
        Write-Host "`n" + "=" * 60 -ForegroundColor Green
        Write-Host "🌐 SHAREPOINT ONLINE AUTOMATION" -ForegroundColor Green
        Write-Host "=" * 60 -ForegroundColor Green
        Write-Host "1. 🏢 Site Collection Creation" -ForegroundColor Green
        Write-Host "2. 👥 Permission Groups" -ForegroundColor Green
        Write-Host "3. 🔗 External Sharing Policies" -ForegroundColor Green
        Write-Host "0. ⬅️ Back to Main Menu"
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Invoke-GitHubScript -ScriptPath "SharePoint/Site-Creation.ps1" }
            "2" { Invoke-GitHubScript -ScriptPath "SharePoint/Permission-Groups.ps1" }
            "3" { Invoke-GitHubScript -ScriptPath "SharePoint/External-Sharing.ps1" }
            "0" { break }
            default { Write-Host "❌ Invalid option!" -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($choice -ne "0")
}

function Show-SecurityMenu {
    if (!(Set-ServiceScopes -Service "Security")) { return }
    
    do {
        Write-Host "`n" + "=" * 60 -ForegroundColor Red
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
        Write-Host "`n" + "=" * 60 -ForegroundColor DarkCyan
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
    Write-Host "0. ⬅️ Back to Main Menu" -ForegroundColor White
    Write-Host ""
    
    $debugChoice = Read-Host "Select debug option"
    
    if ($debugChoice -eq "2") {
        Show-AuthenticationStatus
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
function Start-AutomationHub {
    Initialize-Modules
    
    # Try to load previous session state
    if (Load-SessionState) {
        Show-SessionInfo
    }

    do {
        $choice = Show-MainMenu
        
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
                if (Connect-M365Tenant) {
                    Write-Host "🔍 Checking tenant prerequisites..." -ForegroundColor Yellow
                    Initialize-CompletedSteps
                    Write-Host "✅ Prerequisites checked! Service menus will auto-refresh status." -ForegroundColor Green
                    Save-SessionState
                }
            }
            "9" { 
                Clear-ScriptCache
                Write-Host "🧹 Session state cleared!" -ForegroundColor Green
                Clear-SessionState
            }
            "d" { Show-DebugStatusOverride }
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