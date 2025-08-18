#Requires -Version 7.0

<#
.SYNOPSIS
    Microsoft Graph API Distribution List Creation Script
.DESCRIPTION
    Interactive script for creating distribution lists using Microsoft Graph REST API.
    Leverages existing Graph connection from the Complete-365Tenant-Creation main menu.
.AUTHOR
    CB & Claude Partnership
.VERSION
    2.0 - REST API Edition
.NOTES
    - Uses Microsoft Graph REST API (no Exchange PowerShell needed)
    - Leverages existing Graph connection from main menu
    - Modern REST API approach with better reliability
.EXAMPLE
    Invoke-GitHubScript -ScriptPath "Exchange/Distribution-Lists.ps1"
#>

# Required Modules (Microsoft.Graph for REST API calls)
$RequiredModules = @(
    'Microsoft.Graph.Authentication'
)

$RequiredRoles = @(
    "Exchange Administrator",
    "Global Administrator",
    "Groups Administrator"
)

# Initialize modules function
function Initialize-Modules {
    <#
    .SYNOPSIS
        Checks and imports required PowerShell modules for Graph API
    .DESCRIPTION
        Verifies Microsoft.Graph.Authentication module for getting access tokens
    #>
    
    Write-Host "🔧 Checking Microsoft Graph modules..." -ForegroundColor Cyan
    
    foreach ($Module in $RequiredModules) {
        try {
            # Check if module is installed
            $installedModule = Get-Module -ListAvailable -Name $Module | Sort-Object Version -Descending | Select-Object -First 1
            
            if (!$installedModule) {
                Write-Host "❌ Module $Module not found. Installing..." -ForegroundColor Yellow
                Install-Module $Module -Force -Scope CurrentUser -AllowClobber
                Write-Host "✅ Module $Module installed successfully" -ForegroundColor Green
                $installedModule = Get-Module -ListAvailable -Name $Module | Sort-Object Version -Descending | Select-Object -First 1
            } else {
                Write-Host "✅ Module $Module found (Version: $($installedModule.Version))" -ForegroundColor Green
            }
            
            # Import module if not already loaded
            if (!(Get-Module -Name $Module)) {
                Import-Module $Module -Force -Scope Global
                Write-Host "📦 Module $Module imported successfully" -ForegroundColor Green
            }
        }
        catch {
            Write-Error "❌ Failed to initialize module ${Module}: $($_.Exception.Message)"
            return $false
        }
    }
    return $true
}

# Get Graph API access token
function Get-GraphAccessToken {
    <#
    .SYNOPSIS
        Gets Microsoft Graph access token from current session
    .DESCRIPTION
        Retrieves access token to make direct REST API calls to Microsoft Graph
    #>
    
    try {
        # Try to get the current Graph context (from main menu connection)
        $context = Get-MgContext -ErrorAction Stop
        
        if ($context -and $context.Account) {
            Write-Host "✅ Using existing Microsoft Graph connection" -ForegroundColor Green
            Write-Host "   Account: $($context.Account)" -ForegroundColor Cyan
            
            # Get access token using a more reliable method
            try {
                $token = Get-MgAccessToken -ErrorAction Stop
                return $token
            }
            catch {
                # Fallback method for older Graph module versions
                try {
                    $authProvider = Get-MgContext | Select-Object -ExpandProperty AuthType
                    if ($authProvider) {
                        # For scripts that need REST API calls, we can use Invoke-MgGraphRequest instead
                        Write-Host "✅ Graph context available - using Invoke-MgGraphRequest for API calls" -ForegroundColor Green
                        return "USE_INVOKE_MGGRAPHREQUEST"
                    }
                }
                catch {
                    throw "Could not obtain Graph access token or context"
                }
            }
        } else {
            throw "No active Microsoft Graph context found"
        }
    }
    catch {
        Write-Host "⚠️  Could not retrieve Graph access token: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "💡 The main menu should have established Graph connection already" -ForegroundColor Yellow
        return $null
    }
}

# Make Graph API REST call
function Invoke-GraphAPI {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        
        [Parameter(Mandatory)]
        [string]$Method,
        
        [Parameter(Mandatory)]
        [string]$AccessToken,
        
        [Parameter()]
        [hashtable]$Body = @{}
    )
    
    try {
        # Check if we should use Invoke-MgGraphRequest instead of direct REST calls
        if ($AccessToken -eq "USE_INVOKE_MGGRAPHREQUEST") {
            # Use the built-in Graph cmdlet
            $params = @{
                Uri = $Uri
                Method = $Method
            }
            
            if ($Method -in @('POST', 'PATCH', 'PUT') -and $Body.Count -gt 0) {
                $params.Body = $Body
            }
            
            return Invoke-MgGraphRequest @params
        }
        else {
            # Use direct REST API calls with access token
            $headers = @{
                'Authorization' = "Bearer $AccessToken"
                'Content-Type' = 'application/json'
            }
            
            $params = @{
                Uri = $Uri
                Method = $Method
                Headers = $headers
            }
            
            if ($Method -in @('POST', 'PATCH', 'PUT') -and $Body.Count -gt 0) {
                $params.Body = $Body | ConvertTo-Json -Depth 10
            }
            
            $response = Invoke-RestMethod @params
            return $response
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        if ($_.Exception.Response) {
            $errorDetails = $_.Exception.Response.Content.ReadAsStringAsync().Result
            $errorMessage += " - $errorDetails"
        }
        throw $errorMessage
    }
}

# Test Graph API connection
function Test-GraphConnection {
    <#
    .SYNOPSIS
        Tests Microsoft Graph API connection and permissions
    .DESCRIPTION
        Verifies Graph connection and required permissions for group management
    #>
    
    Write-Host "🔗 Testing Microsoft Graph API connection..." -ForegroundColor Cyan
    
    # Get access token
    $accessToken = Get-GraphAccessToken
    if (!$accessToken) {
        return $false
    }
    
    try {
        # Test basic Graph connectivity by getting organization info
        Write-Host "🧪 Testing Graph API connectivity..." -ForegroundColor Cyan
        $orgInfo = Invoke-GraphAPI -Uri "https://graph.microsoft.com/v1.0/organization" -Method "GET" -AccessToken $accessToken
        Write-Host "✅ Connected to tenant: $($orgInfo.value[0].displayName)" -ForegroundColor Green
        
        # Test groups permission by listing groups (limited)
        Write-Host "🔐 Testing group permissions..." -ForegroundColor Cyan
        $testGroups = Invoke-GraphAPI -Uri "https://graph.microsoft.com/v1.0/groups?`$top=1" -Method "GET" -AccessToken $accessToken
        Write-Host "✅ Group permissions verified" -ForegroundColor Green
        
        return $true
    }
    catch {
        Write-Host "❌ Graph API connection test failed" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Host "💡 Possible issues:" -ForegroundColor Yellow
        Write-Host "   1. Insufficient Graph permissions for groups" -ForegroundColor White
        Write-Host "   2. Required roles: $($RequiredRoles -join ', ')" -ForegroundColor White
        Write-Host "   3. Main menu Graph connection may have expired" -ForegroundColor White
        return $false
    }
}

# Get accepted domains via Graph API
function Get-AcceptedDomains {
    <#
    .SYNOPSIS
        Gets accepted domains using Microsoft Graph API
    .DESCRIPTION
        Retrieves organization accepted domains for email validation
    #>
    
    $accessToken = Get-GraphAccessToken
    if (!$accessToken) {
        return @()
    }
    
    try {
        Write-Host "🔍 Retrieving accepted domains via Graph API..." -ForegroundColor Cyan
        $domains = Invoke-GraphAPI -Uri "https://graph.microsoft.com/v1.0/organization?`$expand=verifiedDomains" -Method "GET" -AccessToken $accessToken
        
        $acceptedDomains = $domains.value[0].verifiedDomains | Where-Object { $_.capabilities -contains "Email" } | Select-Object -ExpandProperty name
        
        Write-Host "✅ Retrieved $($acceptedDomains.Count) accepted domain(s)" -ForegroundColor Green
        return $acceptedDomains
    }
    catch {
        Write-Host "⚠️  Could not retrieve accepted domains: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "   Email validation will be limited to format checking only" -ForegroundColor Yellow
        return @()
    }
}

# Check if distribution group already exists
function Test-DistributionGroupExists {
    param(
        [Parameter(Mandatory)]
        [string]$MailNickname,
        
        [Parameter(Mandatory)]
        [string]$AccessToken
    )
    
    try {
        # Search for existing group by mailNickname
        $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=mailNickname eq '$MailNickname'"
        $existingGroups = Invoke-GraphAPI -Uri $uri -Method "GET" -AccessToken $AccessToken
        
        return ($existingGroups.value.Count -gt 0)
    }
    catch {
        # If we can't check, assume it doesn't exist (will be caught during creation)
        return $false
    }
}

# Validate email address format
function Test-EmailFormat {
    param(
        [Parameter(Mandatory)]
        [string]$EmailAddress
    )
    
    $emailRegex = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return $EmailAddress -match $emailRegex
}

# Validate email domain against tenant domains
function Test-EmailDomain {
    param(
        [Parameter(Mandatory)]
        [string]$EmailAddress,
        
        [Parameter(Mandatory)]
        [string[]]$AcceptedDomains
    )
    
    $domain = ($EmailAddress -split '@')[1]
    return $domain -in $AcceptedDomains
}

# Get user input with validation
function Get-ValidatedInput {
    param(
        [Parameter(Mandatory)]
        [string]$Prompt,
        
        [Parameter(Mandatory)]
        [string]$ValidationScript,
        
        [string]$ErrorMessage = "Invalid input. Please try again.",
        
        [string]$Example = "",
        
        [switch]$AllowCancel
    )
    
    do {
        if ($Example -and $AllowCancel) {
            $userInput = Read-Host "$Prompt (Example: $Example) [Enter 'exit' to cancel]"
        } elseif ($Example) {
            $userInput = Read-Host "$Prompt (Example: $Example)"
        } elseif ($AllowCancel) {
            $userInput = Read-Host "$Prompt [Enter 'exit' to cancel]"
        } else {
            $userInput = Read-Host $Prompt
        }
        
        # Check for exit command
        if ($AllowCancel -and ($userInput -eq 'exit' -or $userInput -eq 'quit' -or $userInput -eq 'cancel')) {
            return $null
        }
        
        # Replace $input with $userInput in validation script to avoid PowerShell reserved variable conflict
        $validationScriptFixed = $ValidationScript -replace '\$input', '$userInput'
        $isValid = Invoke-Expression $validationScriptFixed
        
        if (!$isValid) {
            Write-Host $ErrorMessage -ForegroundColor Red
        }
    } while (!$isValid)
    
    return $userInput
}

# Convert email addresses to user IDs for member assignment
function Get-UserIdsFromEmails {
    param(
        [Parameter(Mandatory)]
        [string[]]$EmailAddresses,
        
        [Parameter(Mandatory)]
        [string]$AccessToken
    )
    
    $userIds = @()
    
    foreach ($email in $EmailAddresses) {
        try {
            $uri = "https://graph.microsoft.com/v1.0/users?`$filter=mail eq '$email' or userPrincipalName eq '$email'"
            $user = Invoke-GraphAPI -Uri $uri -Method "GET" -AccessToken $AccessToken
            
            if ($user.value.Count -gt 0) {
                $userIds += "https://graph.microsoft.com/v1.0/users/$($user.value[0].id)"
                Write-Host "✅ Found user: $email" -ForegroundColor Green
            } else {
                Write-Host "⚠️  User not found: $email (skipped)" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "⚠️  Error looking up user $email (skipped)" -ForegroundColor Yellow
        }
    }
    
    return $userIds
}

# Interactive distribution group creation using Graph API
function New-InteractiveDistributionGroup {
    <#
    .SYNOPSIS
        Interactive function to create a new distribution group via Graph API
    .DESCRIPTION
        Collects user input and creates a distribution group using Microsoft Graph REST API
    #>
    
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Blue
    Write-Host "📧 DISTRIBUTION GROUP CREATION WIZARD" -ForegroundColor Blue
    Write-Host "=" * 60 -ForegroundColor Blue
    Write-Host ""
    
    # Early exit option
    Write-Host "🚀 Ready to create a new distribution group using Microsoft Graph API!" -ForegroundColor Green
    $proceed = Read-Host "Continue with distribution group creation? (Y/n)"
    if ($proceed -like "n*") {
        Write-Host "❌ Distribution group creation cancelled" -ForegroundColor Yellow
        return
    }
    Write-Host ""
    
    # Get Graph access token
    $accessToken = Get-GraphAccessToken
    if (!$accessToken) {
        Write-Host "❌ Could not get Graph access token" -ForegroundColor Red
        return
    }
    
    # Get accepted domains for validation
    $acceptedDomains = Get-AcceptedDomains
    if ($acceptedDomains.Count -eq 0) {
        Write-Host "⚠️  Could not retrieve accepted domains - email validation will be basic format only" -ForegroundColor Yellow
        $acceptedDomains = @()
    } else {
        Write-Host "📋 Available domains: $($acceptedDomains -join ', ')" -ForegroundColor Cyan
    }
    Write-Host ""
    
    # Collect Distribution Group Information
    Write-Host "📝 Please provide the following information:" -ForegroundColor Yellow
    Write-Host "💡 Type 'exit' at any prompt to cancel and return to menu" -ForegroundColor Cyan
    Write-Host ""
    
    # Group Name
    $groupName = Get-ValidatedInput -Prompt "Distribution Group Display Name" -ValidationScript "`$userInput.Length -gt 0 -and `$userInput.Length -le 256" -ErrorMessage "Group name cannot be empty and must be 256 characters or less" -Example "Marketing Team" -AllowCancel
    if ($null -eq $groupName) {
        Write-Host "❌ Distribution group creation cancelled" -ForegroundColor Yellow
        return
    }
    
    # Email Address
    if ($acceptedDomains.Count -gt 0) {
        $primaryEmail = Get-ValidatedInput -Prompt "Primary Email Address" -ValidationScript "(Test-EmailFormat `$userInput) -and (Test-EmailDomain `$userInput @('$($acceptedDomains -join "','")')) -and -not (Test-DistributionGroupExists (`$userInput -split '@')[0] '$accessToken')" -ErrorMessage "Invalid email format, domain not accepted by tenant, or email already exists" -Example "marketing@$($acceptedDomains[0])" -AllowCancel
    } else {
        $primaryEmail = Get-ValidatedInput -Prompt "Primary Email Address" -ValidationScript "(Test-EmailFormat `$userInput) -and -not (Test-DistributionGroupExists (`$userInput -split '@')[0] '$accessToken')" -ErrorMessage "Invalid email format or email already exists" -Example "marketing@yourdomain.com" -AllowCancel
    }
    if ($null -eq $primaryEmail) {
        Write-Host "❌ Distribution group creation cancelled" -ForegroundColor Yellow
        return
    }
    
    # Alias (derived from email)
    $suggestedAlias = ($primaryEmail -split '@')[0] -replace '[^a-zA-Z0-9]', ''
    $alias = Read-Host "Alias (press Enter to use '$suggestedAlias')"
    if ([string]::IsNullOrWhiteSpace($alias)) {
        $alias = $suggestedAlias
    }
    
    # Description
    $description = Read-Host "Description (optional)"
    if ([string]::IsNullOrWhiteSpace($description)) {
        $description = "Distribution group: $groupName"
    }
    
    # Initial Members
    Write-Host ""
    Write-Host "👥 Initial Members (optional):" -ForegroundColor Yellow
    Write-Host "Enter email addresses separated by commas, or press Enter to skip"
    $membersInput = Read-Host "Initial members"
    $memberUserIds = @()
    
    if (![string]::IsNullOrWhiteSpace($membersInput)) {
        Write-Host "🔍 Looking up users..." -ForegroundColor Cyan
        $memberEmails = $membersInput -split ',' | ForEach-Object { $_.Trim() }
        $validEmails = @()
        
        foreach ($email in $memberEmails) {
            if (Test-EmailFormat $email) {
                $validEmails += $email
            } else {
                Write-Host "⚠️  Invalid email format: $email (skipped)" -ForegroundColor Yellow
            }
        }
        
        if ($validEmails.Count -gt 0) {
            $memberUserIds = Get-UserIdsFromEmails -EmailAddresses $validEmails -AccessToken $accessToken
        }
    }
    
    # Summary
    Write-Host ""
    Write-Host "📋 DISTRIBUTION GROUP SUMMARY:" -ForegroundColor Green
    Write-Host "=" * 40 -ForegroundColor Green
    Write-Host "Name: $groupName" -ForegroundColor White
    Write-Host "Email: $primaryEmail" -ForegroundColor White  
    Write-Host "Alias: $alias" -ForegroundColor White
    Write-Host "Description: $description" -ForegroundColor White
    Write-Host "Initial Members: $(if($memberUserIds.Count -gt 0) { $memberUserIds.Count } else { 'None' })" -ForegroundColor White
    Write-Host ""
    
    $confirm = Read-Host "Create this distribution group? (Y/n)"
    if ($confirm -like "n*") {
        Write-Host "❌ Distribution group creation cancelled" -ForegroundColor Yellow
        return
    }
    
    # Create Distribution Group via Graph API
    Write-Host ""
    Write-Host "🚀 Creating distribution group via Microsoft Graph API..." -ForegroundColor Cyan
    
    try {
        # Prepare the group object for Graph API
        $groupBody = @{
            displayName = $groupName
            mailNickname = $alias
            description = $description
            mailEnabled = $true
            securityEnabled = $false
            groupTypes = @()  # Empty array for distribution groups
        }
        
        # Add members if specified
        if ($memberUserIds.Count -gt 0) {
            $groupBody["members@odata.bind"] = $memberUserIds
        }
        
        # Create the group
        $newGroup = Invoke-GraphAPI -Uri "https://graph.microsoft.com/v1.0/groups" -Method "POST" -AccessToken $accessToken -Body $groupBody
        
        Write-Host "✅ Distribution group '$groupName' created successfully!" -ForegroundColor Green
        Write-Host "📧 Email address: $($newGroup.mail)" -ForegroundColor Green
        Write-Host "🆔 Group ID: $($newGroup.id)" -ForegroundColor Green
        
        # Show member status
        if ($memberUserIds.Count -gt 0) {
            Write-Host "👥 Members added: $($memberUserIds.Count)" -ForegroundColor Green
        } else {
            Write-Host ""
            Write-Host "💡 Next Steps:" -ForegroundColor Yellow
            Write-Host "   • Add members via Microsoft 365 Admin Center" -ForegroundColor White
            Write-Host "   • Or use Graph API to add members programmatically" -ForegroundColor White
        }
        
        Write-Host ""
        Write-Host "🔗 Manage this group at:" -ForegroundColor Cyan
        Write-Host "   https://admin.microsoft.com/AdminPortal/Home#/groups" -ForegroundColor Blue
        
    }
    catch {
        Write-Host "❌ Failed to create distribution group" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        
        # Specific error guidance
        if ($_.Exception.Message -like "*already exists*" -or $_.Exception.Message -like "*duplicate*") {
            Write-Host "💡 A group with this name or email address already exists" -ForegroundColor Yellow
        } elseif ($_.Exception.Message -like "*permission*" -or $_.Exception.Message -like "*forbidden*") {
            Write-Host "💡 Insufficient permissions. Required roles: $($RequiredRoles -join ', ')" -ForegroundColor Yellow
        } elseif ($_.Exception.Message -like "*domain*") {
            Write-Host "💡 Email domain not accepted by your tenant" -ForegroundColor Yellow
        }
    }
}

# Main execution function
function Start-DistributionListCreation {
    <#
    .SYNOPSIS
        Main execution function for distribution list creation using Graph API
    .DESCRIPTION
        Orchestrates the entire distribution list creation process using REST API
    #>
    
    Write-Host "🔧 Loading Distribution List Creation Script (REST API Edition)..." -ForegroundColor Cyan
    
    # Step 1: Initialize modules
    Write-Host "📦 Step 1: Initialize Graph Modules" -ForegroundColor Cyan
    if (!(Initialize-Modules)) {
        Write-Host "❌ Module initialization failed. Cannot continue." -ForegroundColor Red
        return
    }
    
    # Step 2: Test Graph API connection
    Write-Host "🔗 Step 2: Test Microsoft Graph API Connection" -ForegroundColor Cyan
    if (!(Test-GraphConnection)) {
        Write-Host "❌ Graph API connection test failed. Cannot continue." -ForegroundColor Red
        Write-Host ""
        Write-Host "💡 This script uses the existing Graph connection from the main menu." -ForegroundColor Yellow
        Write-Host "   If connection issues persist, try refreshing the main menu connection." -ForegroundColor Yellow
        Write-Host ""
        Read-Host "Press Enter to return to Exchange menu"
        return
    }
    
    # Step 3: Start interactive creation
    Write-Host "🎯 Step 3: Start Distribution Group Creation" -ForegroundColor Cyan
    
    do {
        New-InteractiveDistributionGroup
        
        Write-Host ""
        $another = Read-Host "Create another distribution group? (y/N)"
        
    } while ($another -like "y*")
    
    Write-Host ""
    Write-Host "✅ Distribution list creation completed!" -ForegroundColor Green
    Write-Host "🔙 Returning to Exchange menu..." -ForegroundColor Cyan
    
    # Clean return to menu
    Start-Sleep -Seconds 2
}

# Execute main function
Start-DistributionListCreation