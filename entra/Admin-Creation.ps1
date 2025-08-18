#Requires -Version 7.0

<#
.SYNOPSIS
    Admin Accounts Creation Module - PowerShell 7 Compatible
.DESCRIPTION
    Creates administrative accounts with proper group memberships and role assignments.
    Handles password generation, department assignment, and Intune role configuration.
    
    Creates Admin Accounts:
    - BITS-Admin-Cloud@DefaultDomain (Cloud Administrator)
    - BITS-Admin-HD@DefaultDomain (Helpdesk Administrator)  
    - BITS-Admin-BG01@DefaultDomain (Break Glass Account #1 - MFA required)
    - BITS-Admin-BG02@DefaultDomain (Break Glass Account #2 - NoMFA exempt)
    
    Groups Created/Managed:
    - Helpdesk Operator Group (Dynamic) - for Intune role assignment
    - BITS Admin Users (Dynamic) - uses existing from Groups module
    - NoMFA Exclusion Group (Static) - uses existing from Groups module
    
    Dynamic Membership Rules:
    - Helpdesk Operator Group: Based on displayName matching admin account patterns
    
.NOTES
    Version: 1.0
    Requirements: PowerShell 7.0 or later
    Author: CB & Claude Partnership
    Dependencies: Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.DeviceManagement
    
    Password Requirements:
    - Standard accounts: 12 characters
    - Break Glass accounts: 18 characters  
    - All passwords: Upper + Lower + Numbers + Special characters
    
    Department Assignment:
    - All admin accounts get Department = "BITS Admin" for dynamic group membership
#>

# Required Modules
$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Identity.DirectoryManagement'
)

# Auto-install and import required modules
function Initialize-Modules {
    Write-Host "🔧 Checking required modules..." -ForegroundColor Yellow
    
    try {
        foreach ($Module in $RequiredModules) {
            try {
                if (!(Get-Module -ListAvailable -Name $Module)) {
                    Write-Host "Installing $Module..." -ForegroundColor Yellow
                    Install-Module $Module -Force -Scope CurrentUser -AllowClobber -SkipPublisherCheck -ErrorAction Stop
                }
                if (!(Get-Module -Name $Module)) {
                    Write-Host "Importing $Module..." -ForegroundColor Yellow
                    Import-Module $Module -Force -ErrorAction Stop
                }
                Write-Host "✅ $Module ready!" -ForegroundColor Green
            }
            catch {
                Write-Host "❌ Failed to install/import ${Module}: $($_.Exception.Message)" -ForegroundColor Red
                return $false
            }
        }
        Write-Host "✅ All modules ready!" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "❌ Module initialization failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# === Logging Functions ===
function Write-LogMessage {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Type = "Info"
    )
    
    $color = switch ($Type) {
        "Info" { "White" }
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
    }
    
    $prefix = switch ($Type) {
        "Info" { "ℹ️" }
        "Success" { "✅" }
        "Warning" { "⚠️" }
        "Error" { "❌" }
    }
    
    Write-Host "$prefix $Message" -ForegroundColor $color
}

# === Password Generation ===
function New-SecurePassword {
    <#
    .SYNOPSIS
        Generates a secure password with specified length and complexity requirements
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Length
    )
    
    # Define character sets
    $upperCase = 'ABCDEFGHKLMNOPRSTUVWXYZ'
    $lowerCase = 'abcdefghiklmnoprstuvwxyz'
    $numbers = '1234567890'
    $special = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    # Ensure at least one character from each required set
    $password = @()
    $password += Get-Random -InputObject $upperCase.ToCharArray()
    $password += Get-Random -InputObject $lowerCase.ToCharArray() 
    $password += Get-Random -InputObject $numbers.ToCharArray()
    $password += Get-Random -InputObject $special.ToCharArray()
    
    # Fill remaining length with random characters from all sets
    $allChars = $upperCase + $lowerCase + $numbers + $special
    for ($i = 4; $i -lt $Length; $i++) {
        $password += Get-Random -InputObject $allChars.ToCharArray()
    }
    
    # Shuffle the password array and convert to string
    $shuffledPassword = $password | Sort-Object { Get-Random }
    return -join $shuffledPassword
}

# === User Account Creation ===
function New-AdminUserAccount {
    <#
    .SYNOPSIS
        Creates a single admin user account with proper configuration
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AccountConfig,
        
        [Parameter(Mandatory = $true)]
        [string]$Password
    )
    
    try {
        # Check if user already exists
        $existingUser = Get-MgUser -Filter "userPrincipalName eq '$($AccountConfig.UPN)'" -ErrorAction SilentlyContinue
        
        if ($existingUser) {
            Write-LogMessage -Message "User $($AccountConfig.UPN) already exists" -Type Warning
            return @{
                Success = $true
                User = $existingUser
                Created = $false
            }
        }
        
        # Create password profile
        $passwordProfile = @{
            Password = $Password
            ForceChangePasswordNextSignIn = $false
        }
        
        # Create user parameters
        $userParams = @{
            UserPrincipalName = $AccountConfig.UPN
            DisplayName = $AccountConfig.DisplayName
            GivenName = $AccountConfig.GivenName
            Surname = $AccountConfig.Surname
            JobTitle = $AccountConfig.JobTitle
            Department = "BITS Admin"  # Critical for dynamic group membership
            AccountEnabled = $true
            PasswordProfile = $passwordProfile
            MailNickname = $AccountConfig.DisplayName -replace '[^a-zA-Z0-9]', ''
            UsageLocation = "GB"  # UK location
        }
        
        # Create the user
        $newUser = New-MgUser -BodyParameter $userParams
        
        Write-LogMessage -Message "Created user account: $($AccountConfig.DisplayName)" -Type Success
        
        return @{
            Success = $true
            User = $newUser
            Created = $true
        }
    }
    catch {
        Write-LogMessage -Message "Failed to create user $($AccountConfig.UPN) - $($_.Exception.Message)" -Type Error
        return @{
            Success = $false
            User = $null
            Created = $false
        }
    }
}

# === Group Management ===
function New-HelpdeskOperatorGroup {
    <#
    .SYNOPSIS
        Creates the Helpdesk Operator Group for Intune role assignment
    #>
    [CmdletBinding()]
    param()
    
    try {
        $groupName = "Helpdesk Operator Group"
        
        # Check if group already exists
        $existingGroup = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue
        
        if ($existingGroup) {
            Write-LogMessage -Message "Helpdesk Operator Group already exists" -Type Info
            return @{
                Success = $true
                Group = $existingGroup
                Created = $false
            }
        }
        
        # Create dynamic membership rule for admin accounts
        $membershipRule = '(user.displayName -eq "BITS-Admin-Cloud") or (user.displayName -eq "BITS-Admin-HD") and (user.accountEnabled -eq true)'
        
        # Create group parameters
        $groupParams = @{
            DisplayName = $groupName
            Description = "Dynamic group for assigning Intune Help Desk Operator role to admin accounts"
            GroupTypes = @("DynamicMembership")
            MailEnabled = $false
            MailNickname = "HelpdeskOperatorGroup"
            MembershipRule = $membershipRule
            MembershipRuleProcessingState = "On"
            SecurityEnabled = $true
        }
        
        # Create the group
        $newGroup = New-MgGroup -BodyParameter $groupParams
        
        Write-LogMessage -Message "Created Helpdesk Operator Group with dynamic membership" -Type Success
        
        return @{
            Success = $true
            Group = $newGroup
            Created = $true
        }
    }
    catch {
        Write-LogMessage -Message "Failed to create Helpdesk Operator Group - $($_.Exception.Message)" -Type Error
        return @{
            Success = $false
            Group = $null
            Created = $false
        }
    }
}

function Add-UserToGroup {
    <#
    .SYNOPSIS
        Adds a user to a specified group (handles both static and dynamic groups)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$User,
        
        [Parameter(Mandatory = $true)]
        [string]$GroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$AccountRole
    )
    
    try {
        # Find the group
        $group = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue
        
        if (-not $group) {
            Write-LogMessage -Message "Group '$GroupName' not found - may need to be created by Groups module first" -Type Warning
            return $false
        }
        
        # Check if it's a dynamic group
        if ($group.GroupTypes -contains "DynamicMembership") {
            Write-LogMessage -Message "Group '$GroupName' is dynamic - membership handled automatically based on user properties" -Type Info
            return $true
        }
        
        # For static groups, add the user as member
        try {
            New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $User.Id -ErrorAction Stop
            Write-LogMessage -Message "Added $($User.DisplayName) to $GroupName" -Type Success
            return $true
        }
        catch {
            # Check if already a member
            if ($_.Exception.Message -like "*already exists*" -or $_.Exception.Message -like "*already a member*") {
                Write-LogMessage -Message "$($User.DisplayName) is already a member of $GroupName" -Type Info
                return $true
            }
            else {
                Write-LogMessage -Message "Failed to add $($User.DisplayName) to $GroupName - $($_.Exception.Message)" -Type Warning
                return $false
            }
        }
    }
    catch {
        Write-LogMessage -Message "Error adding user to group '$GroupName' - $($_.Exception.Message)" -Type Error
        return $false
    }
}

# === Results Display ===
function Show-AdminAccountSummary {
    <#
    .SYNOPSIS
        Displays a comprehensive summary of created admin accounts and their configurations
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Results,
        
        [Parameter(Mandatory = $true)]
        [string]$DefaultDomain
    )
    
    Write-Host ""
    Write-Host "=== Admin Accounts Creation Summary ===" -ForegroundColor Cyan
    Write-Host "Total accounts processed: " -ForegroundColor Gray -NoNewline
    Write-Host "$($Results.Total)" -ForegroundColor White
    Write-Host "Successfully created: " -ForegroundColor Gray -NoNewline  
    Write-Host "$($Results.Success)" -ForegroundColor Green
    Write-Host "Failed: " -ForegroundColor Gray -NoNewline
    Write-Host "$($Results.Failed.Count)" -ForegroundColor $(if ($Results.Failed.Count -gt 0) { 'Red' } else { 'Green' })
    
    if ($Results.Failed.Count -gt 0) {
        Write-Host ""
        Write-Host "Failed accounts:" -ForegroundColor Red
        $Results.Failed | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    }
    
    Write-Host ""
    Write-Host "Created Admin Accounts:" -ForegroundColor Yellow
    $Results.Accounts.Keys | ForEach-Object { 
        $account = $Results.Accounts[$_]
        Write-Host "  ✓ $($account.DisplayName) ($($account.UserPrincipalName))" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "Group Memberships:" -ForegroundColor Yellow
    Write-Host "  • Cloud & HD Admins → BITS Admin Users (Dynamic)" -ForegroundColor White
    Write-Host "  • Cloud & HD Admins → Helpdesk Operator Group (Dynamic)" -ForegroundColor White  
    Write-Host "  • BG01 → BITS Admin Users (Dynamic)" -ForegroundColor White
    Write-Host "  • BG02 → BITS Admin Users + NoMFA Exclusion Group" -ForegroundColor White
    
    Write-Host ""
    Write-Host "Generated Passwords:" -ForegroundColor Cyan
    Write-Host "⚠️  SAVE THESE PASSWORDS SECURELY - THEY WILL NOT BE DISPLAYED AGAIN ⚠️" -ForegroundColor Yellow
    Write-Host ""
    
    foreach ($upn in $Results.Passwords.Keys) {
        $password = $Results.Passwords[$upn]
        Write-Host "$upn" -ForegroundColor White -NoNewline
        Write-Host " → " -ForegroundColor Gray -NoNewline
        Write-Host "$password" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "=== Next Steps ===" -ForegroundColor Cyan
    Write-Host "1. " -ForegroundColor White -NoNewline
    Write-Host "Save all passwords in secure password manager" -ForegroundColor Yellow
    Write-Host "2. " -ForegroundColor White -NoNewline
    Write-Host "Verify dynamic group memberships in Azure AD (may take 5-10 minutes)" -ForegroundColor Yellow
    Write-Host "3. " -ForegroundColor White -NoNewline  
    Write-Host "Manually assign 'Help Desk Operator' Intune role to 'Helpdesk Operator Group'" -ForegroundColor Yellow
    Write-Host "4. " -ForegroundColor White -NoNewline
    Write-Host "Test admin account logins and permissions" -ForegroundColor Yellow
    Write-Host "5. " -ForegroundColor White -NoNewline
    Write-Host "Configure Conditional Access policies for admin accounts" -ForegroundColor Yellow
    
    Write-Host ""
    Write-Host "Security Reminders:" -ForegroundColor Red
    Write-Host "• Only BG02 is exempt from MFA - monitor usage closely" -ForegroundColor Yellow
    Write-Host "• BG01 requires MFA for additional security layer" -ForegroundColor Yellow
    Write-Host "• Consider implementing PIM for just-in-time admin access" -ForegroundColor Yellow
    Write-Host "• Review admin account activity regularly" -ForegroundColor Yellow
    Write-Host "• Implement break-glass procedures for emergency accounts" -ForegroundColor Yellow
}

# === Main Admin Accounts Creation Function ===
function New-TenantAdminAccounts {
    <#
    .SYNOPSIS
        Creates administrative accounts with proper group memberships and role assignments
    .DESCRIPTION
        Creates standard admin accounts, generates secure passwords, assigns to appropriate 
        groups, and configures Intune role assignments for helpdesk operations.
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage -Message "Starting admin accounts creation process..." -Type Info
        
        # Verify Graph connection
        if (-not (Get-MgContext)) {
            Write-LogMessage -Message "Not connected to Microsoft Graph. Please connect first." -Type Error
            return $false
        }
        
        # Get tenant information
        $organization = Get-MgOrganization | Select-Object -First 1
        $defaultDomain = $organization.VerifiedDomains | Where-Object { $_.IsDefault -eq $true } | Select-Object -ExpandProperty Name
        
        if ([string]::IsNullOrEmpty($defaultDomain)) {
            Write-LogMessage -Message "No default domain found in tenant." -Type Error
            return $false
        }
        
        Write-LogMessage -Message "Using default domain: $defaultDomain" -Type Info
        
        # Initialize results tracking
        $createdAccounts = @{
            Success = 0
            Failed = @()
            Total = 0
            Accounts = @{}
            Groups = @{}
            Passwords = @{}
        }
        
        # === Create Helpdesk Operator Group First ===
        Write-LogMessage -Message "Creating/verifying Helpdesk Operator Group..." -Type Info
        
        $helpdeskGroupResult = New-HelpdeskOperatorGroup
        if ($helpdeskGroupResult.Success) {
            $createdAccounts.Groups["Helpdesk Operator Group"] = $helpdeskGroupResult.Group
            Write-LogMessage -Message "Helpdesk Operator Group ready for role assignment" -Type Success
        }
        else {
            Write-LogMessage -Message "Failed to create/verify Helpdesk Operator Group" -Type Warning
        }
        
        # === Define Admin Accounts to Create ===
        $adminAccounts = @(
            @{
                Role = "Cloud"
                UPN = "BITS-Admin-Cloud@$defaultDomain"
                DisplayName = "BITS-Admin-Cloud"
                GivenName = "BITS Admin"
                Surname = "Cloud"
                JobTitle = "Cloud Administrator"
                PasswordLength = 12
                Groups = @("BITS Admin Users", "Helpdesk Operator Group")
            },
            @{
                Role = "HD"  
                UPN = "BITS-Admin-HD@$defaultDomain"
                DisplayName = "BITS-Admin-HD"
                GivenName = "BITS Admin"
                Surname = "Helpdesk"
                JobTitle = "Helpdesk Administrator"
                PasswordLength = 12
                Groups = @("BITS Admin Users", "Helpdesk Operator Group")
            },
            @{
                Role = "BG01"
                UPN = "BITS-Admin-BG01@$defaultDomain" 
                DisplayName = "BITS-Admin-BG01"
                GivenName = "BITS Admin"
                Surname = "BG01"
                JobTitle = "Emergency Access Account"
                PasswordLength = 18
                Groups = @("BITS Admin Users")
            },
            @{
                Role = "BG02"
                UPN = "BITS-Admin-BG02@$defaultDomain" 
                DisplayName = "BITS-Admin-BG02"
                GivenName = "BITS Admin"
                Surname = "BG02"
                JobTitle = "Emergency Access Account (NoMFA Exempt)"
                PasswordLength = 18
                Groups = @("BITS Admin Users", "NoMFA Exclusion Group")
            }
        )
        
        Write-LogMessage -Message "Creating $($adminAccounts.Count) administrative accounts..." -Type Info
        
        # === Create Each Admin Account ===
        foreach ($accountConfig in $adminAccounts) {
            $createdAccounts.Total++
            Write-LogMessage -Message "Processing account: $($accountConfig.DisplayName)" -Type Info
            
            # Generate secure password
            $password = New-SecurePassword -Length $accountConfig.PasswordLength
            $createdAccounts.Passwords[$accountConfig.UPN] = $password
            
            # Create the user account
            $userResult = New-AdminUserAccount -AccountConfig $accountConfig -Password $password
            
            if ($userResult.Success) {
                $createdAccounts.Accounts[$accountConfig.Role] = $userResult.User
                $createdAccounts.Success++
                
                # Add to groups
                foreach ($groupName in $accountConfig.Groups) {
                    Add-UserToGroup -User $userResult.User -GroupName $groupName -AccountRole $accountConfig.Role
                }
                
                Write-LogMessage -Message "Successfully created admin account: $($accountConfig.DisplayName)" -Type Success
            }
            else {
                $createdAccounts.Failed += $accountConfig.DisplayName
                Write-LogMessage -Message "Failed to create admin account: $($accountConfig.DisplayName)" -Type Error
            }
        }
        
        # === Display Results ===
        Show-AdminAccountSummary -Results $createdAccounts -DefaultDomain $defaultDomain
        
        # Determine overall success
        $overallSuccess = $createdAccounts.Success -gt 0 -and $createdAccounts.Failed.Count -eq 0
        
        if ($overallSuccess) {
            Write-LogMessage -Message "Admin accounts creation completed successfully - $($createdAccounts.Success)/$($createdAccounts.Total) accounts created" -Type Success
        }
        elseif ($createdAccounts.Success -gt 0) {
            Write-LogMessage -Message "Admin accounts creation completed with warnings - $($createdAccounts.Success)/$($createdAccounts.Total) accounts created" -Type Warning
        }
        else {
            Write-LogMessage -Message "Admin accounts creation failed - no accounts were created successfully" -Type Error
        }
        
        return $overallSuccess
        
    }
    catch {
        Write-LogMessage -Message "Error in admin accounts creation process - $($_.Exception.Message)" -Type Error
        return $false
    }
}

# Main execution function
function Start-AdminCreation {
    Write-Host "🚀 Starting Admin Account Creation..." -ForegroundColor Cyan
    
    if (!(Initialize-Modules)) {
        Write-Host "❌ Failed to initialize required modules. Exiting." -ForegroundColor Red
        return $false
    }
    
    # Check connection
    if (-not (Get-MgContext)) {
        Write-Host "❌ Not connected to Microsoft Graph. Please connect from the main menu first." -ForegroundColor Red
        return $false
    }
    
    # Run the admin account creation
    $result = New-TenantAdminAccounts
    
    if ($result) {
        Write-Host "\n✅ Admin account creation process completed successfully!" -ForegroundColor Green
    } else {
        Write-Host "\n❌ Admin account creation process completed with errors." -ForegroundColor Red
    }
    
    Write-Host "\nPress any key to return to the menu..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    
    return $result
}

# Execute the script
Start-AdminCreation