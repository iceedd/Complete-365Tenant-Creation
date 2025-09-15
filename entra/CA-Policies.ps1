#Requires -Version 7.0

<#
.SYNOPSIS
    Creates Conditional Access policies for fresh tenant security
.DESCRIPTION
    Disables Security Defaults and creates comprehensive CA policies with proper exclusions
.AUTHOR
    CB & Claude Partnership
.VERSION
    1.0
#>

# Required Modules
$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Identity.SignIns'
)

# Required scopes for this script
$RequiredScopes = @(
    "User.ReadWrite.All",
            "Group.ReadWrite.All", 
            "Group.Read.All",
            "Policy.ReadWrite.ConditionalAccess",
            "Directory.ReadWrite.All",
            "RoleManagement.ReadWrite.Directory",
            "Policy.ReadWrite.SecurityDefaults",
            "Directory.AccessAsUser.All"
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

# Get tenant domain for company initials
function Get-TenantInfo {
    try {
        $org = Get-MgOrganization | Select-Object -First 1
        $domain = $org.VerifiedDomains | Where-Object { $_.IsDefault -eq $true } | Select-Object -ExpandProperty Name
        $companyInitials = ($domain -split '\.')[0].ToUpper()
        
        return @{
            Domain = $domain
            CompanyInitials = $companyInitials
            TenantId = $org.Id
        }
    }
    catch {
        Write-Error "Failed to get tenant info: $($_.Exception.Message)"
        return $null
    }
}

# Resolve group name to ID
function Get-GroupId {
    param([string]$GroupName)
    
    try {
        $group = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction Stop
        if ($group) {
            return $group.Id
        } else {
            Write-Warning "Group '$GroupName' not found"
            return $null
        }
    }
    catch {
        Write-Error "Failed to resolve group '$GroupName': $($_.Exception.Message)"
        return $null
    }
}

# Verify required scopes
function Test-RequiredScopes {
    $context = Get-MgContext
    if (!$context) {
        Write-Error "❌ Not connected to Microsoft Graph"
        return $false
    }
    
    $currentScopes = $context.Scopes
    $missingScopes = $RequiredScopes | Where-Object { $_ -notin $currentScopes }
    
    if ($missingScopes) {
        Write-Host "❌ Missing required scopes:" -ForegroundColor Red
        foreach ($scope in $missingScopes) {
            Write-Host "   - $scope" -ForegroundColor Red
        }
        Write-Host "`n💡 Reconnect with: Connect-MgGraph -Scopes '$($RequiredScopes -join "', '")'" -ForegroundColor Yellow
        return $false
    }
    
    Write-Host "✅ All required scopes present" -ForegroundColor Green
    return $true
}

# Disable Security Defaults
function Disable-SecurityDefaults {
    try {
        Write-Host "Checking Security Defaults..."
        
        $policy = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
        
        if ($policy.IsEnabled -eq $true) {
            Write-Host "Security Defaults are enabled. Disabling them now..."
            Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -IsEnabled $false
            Write-Host "Security Defaults have been disabled."
        } else {
            Write-Host "Security Defaults are already disabled."
        }
    }
    catch {
        Write-Error "Failed to disable Security Defaults: $($_.Exception.Message)"
        Write-Host "Try manual disable: Entra admin center → Identity → Override → Properties → Manage security defaults"
        throw
    }
}

# Create CA policy function
function New-ConditionalAccessPolicy {
    param(
        [hashtable]$PolicyConfig,
        [string]$NoMfaGroupId
    )
    
    try {
        # Check if policy already exists
        $existingPolicy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$($PolicyConfig.DisplayName)'" -ErrorAction SilentlyContinue
        
        if ($existingPolicy) {
            Write-Host "⚠️  Policy '$($PolicyConfig.DisplayName)' already exists" -ForegroundColor Yellow
            return $existingPolicy
        }
        
        # Add NoMFA group to exclusions for all policies
        if ($NoMfaGroupId -and $PolicyConfig.Conditions.Users.ExcludeGroups -notcontains $NoMfaGroupId) {
            $PolicyConfig.Conditions.Users.ExcludeGroups += $NoMfaGroupId
        }
        
        # Create the policy
        $newPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicyConfig
        
        Write-Host "✅ Created: $($PolicyConfig.DisplayName)" -ForegroundColor Green
        Write-Host "   Policy ID: $($newPolicy.Id)" -ForegroundColor Gray
        
        return $newPolicy
    }
    catch {
        Write-Error "❌ Failed to create policy '$($PolicyConfig.DisplayName)': $($_.Exception.Message)"
        return $null
    }
}

# Policy definitions based on export
function Get-PolicyDefinitions {
    param([string]$NoMfaGroupId)
    
    return @(
        @{
            DisplayName = "C001 - Block High Risk Users"
            State = "enabled"
            Conditions = @{
                Applications = @{
                    IncludeApplications = @("All")
                    ExcludeApplications = @()
                }
                ClientAppTypes = @("all")
                UserRiskLevels = @("high")
                SignInRiskLevels = @()
                Users = @{
                    IncludeUsers = @("All")
                    ExcludeUsers = @()
                    ExcludeGroups = @($NoMfaGroupId)
                    ExcludeRoles = @()
                }
            }
            GrantControls = @{
                BuiltInControls = @("block")
                Operator = "OR"
            }
        },
        @{
            DisplayName = "C002 - MFA Required for All Users"
            State = "enabled"
            Conditions = @{
                Applications = @{
                    IncludeApplications = @("All")
                    ExcludeApplications = @()
                }
                ClientAppTypes = @("browser", "mobileAppsAndDesktopClients")
                UserRiskLevels = @()
                SignInRiskLevels = @()
                Users = @{
                    IncludeUsers = @("All")
                    ExcludeUsers = @()
                    ExcludeGroups = @($NoMfaGroupId)
                    ExcludeRoles = @()
                }
            }
            GrantControls = @{
                BuiltInControls = @("mfa")
                Operator = "OR"
            }
        },
        @{
            DisplayName = "C003 - Block Non Corporate Devices"
            State = "enabled"
            Conditions = @{
                Applications = @{
                    IncludeApplications = @("All")
                    ExcludeApplications = @()
                }
                ClientAppTypes = @("all")
                UserRiskLevels = @()
                SignInRiskLevels = @()
                Users = @{
                    IncludeUsers = @("All")
                    ExcludeUsers = @()
                    ExcludeGroups = @($NoMfaGroupId)
                    ExcludeRoles = @("d29b2b05-8046-44ba-8758-1e26182fcf32") # Directory Synchronization Accounts
                }
            }
            GrantControls = @{
                BuiltInControls = @("mfa", "compliantDevice", "domainJoinedDevice")
                Operator = "OR"
            }
        },
        @{
            DisplayName = "C004 - Require Password Change and MFA for High Risk Users"
            State = "enabled"
            Conditions = @{
                Applications = @{
                    IncludeApplications = @("All")
                    ExcludeApplications = @()
                }
                ClientAppTypes = @("all")
                UserRiskLevels = @("high")
                SignInRiskLevels = @()
                Users = @{
                    IncludeUsers = @("All")
                    ExcludeUsers = @()
                    ExcludeGroups = @($NoMfaGroupId)
                    ExcludeRoles = @()
                }
            }
            GrantControls = @{
                BuiltInControls = @("mfa", "passwordChange")
                Operator = "AND"
            }
        },
        @{
            DisplayName = "C005 - Require MFA for Risky Sign-Ins"
            State = "enabled"
            Conditions = @{
                Applications = @{
                    IncludeApplications = @("All")
                    ExcludeApplications = @()
                }
                ClientAppTypes = @("all")
                UserRiskLevels = @()
                SignInRiskLevels = @("high", "medium")
                Users = @{
                    IncludeUsers = @("All")
                    ExcludeUsers = @()
                    ExcludeGroups = @($NoMfaGroupId)
                    ExcludeRoles = @()
                }
            }
            GrantControls = @{
                BuiltInControls = @("mfa")
                Operator = "OR"
            }
        }
    )
}

# Main execution function
function Start-CAPolicyCreation {
    Write-Host "`n🚀 Creating Conditional Access Policies..." -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    
    # Verify scopes first
    if (!(Test-RequiredScopes)) {
        return
    }
    
    # Get tenant info
    $tenantInfo = Get-TenantInfo
    if (!$tenantInfo) {
        Write-Error "❌ Failed to get tenant information"
        return
    }
    
    Write-Host "✅ Connected to: $($tenantInfo.Domain)" -ForegroundColor Green
    Write-Host "   Company: $($tenantInfo.CompanyInitials)" -ForegroundColor Gray
    
    # Resolve NoMFA group
    Write-Host "`n🔍 Resolving security groups..." -ForegroundColor Yellow
    $noMfaGroupId = Get-GroupId -GroupName "NoMFA Exclusion Group"
    
    if (!$noMfaGroupId) {
        Write-Error "❌ NoMFA Exclusion Group not found. Please create security groups first."
        return
    }
    
    Write-Host "✅ NoMFA Group ID: $noMfaGroupId" -ForegroundColor Green
    
    # Disable Security Defaults
    Disable-SecurityDefaults
    
    # Create policies
    Write-Host "`n🛡️ Creating CA policies..." -ForegroundColor Yellow
    $policies = Get-PolicyDefinitions -NoMfaGroupId $noMfaGroupId
    
    $createdPolicies = @()
    $failedPolicies = @()
    
    foreach ($policy in $policies) {
        Write-Host "`n📋 Creating: $($policy.DisplayName)" -ForegroundColor White
        
        $result = New-ConditionalAccessPolicy -PolicyConfig $policy -NoMfaGroupId $noMfaGroupId
        
        if ($result) {
            $createdPolicies += $result
        } else {
            $failedPolicies += $policy.DisplayName
        }
        
        # Small delay to avoid throttling
        Start-Sleep -Milliseconds 500
    }
    
    # Summary
    Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
    Write-Host "📊 SUMMARY" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host "✅ Successfully created: $($createdPolicies.Count) policies" -ForegroundColor Green
    
    if ($failedPolicies.Count -gt 0) {
        Write-Host "❌ Failed to create: $($failedPolicies.Count) policies" -ForegroundColor Red
        foreach ($failed in $failedPolicies) {
            Write-Host "   - $failed" -ForegroundColor Red
        }
    }
    
    Write-Host "`n💡 Next Steps:" -ForegroundColor Yellow
    Write-Host "   1. Verify policies in Entra admin center" -ForegroundColor Gray
    Write-Host "   2. Test with pilot users before full deployment" -ForegroundColor Gray
    Write-Host "   3. Monitor sign-in logs for policy impact" -ForegroundColor Gray
    Write-Host "   4. Add break-glass accounts to NoMFA Exclusion Group" -ForegroundColor Gray
    
    Write-Host "`n⚠️  IMPORTANT:" -ForegroundColor Red
    Write-Host "   All policies are ENABLED by default" -ForegroundColor Red
    Write-Host "   Ensure break-glass accounts are excluded!" -ForegroundColor Red
    
    return $createdPolicies
}

# Initialize and run
try {
    Initialize-Modules
    $results = Start-CAPolicyCreation
    
    if ($results) {
        Write-Host "`n🎉 Conditional Access policy creation completed!" -ForegroundColor Green
        Write-Host "🔐 Security Defaults disabled, CA policies active" -ForegroundColor Green
    }
}
catch {
    Write-Error "❌ Script execution failed: $($_.Exception.Message)"
}

# ▼ CB & Claude | BITS 365 Automation | v1.0 | "Smarter not Harder"