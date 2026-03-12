#Requires -Version 7.0

<#
.SYNOPSIS
    Creates Conditional Access policies for fresh tenant security
.DESCRIPTION
    Disables Security Defaults and creates comprehensive CA policies with proper exclusions.
    Includes auto-fix for prerequisites like Security Defaults and missing groups.
.AUTHOR
    CB & Claude Partnership
.VERSION
    2.0 - Standardized UX with preview mode and auto-fix
#>

# ============================================================================
# CONFIGURATION
# ============================================================================

$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Groups'
)

$RequiredScopes = @(
    "Policy.ReadWrite.ConditionalAccess",
    "Policy.ReadWrite.SecurityDefaults",
    "Group.ReadWrite.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory"
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
# PREREQUISITES WITH AUTO-FIX
# ============================================================================

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Verify all prerequisites and offer to auto-fix issues
    #>

    Write-Host ""
    Write-Host "   PREREQUISITES CHECK" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    # Check Graph connection
    Write-Host "   Checking Microsoft Graph connection..." -ForegroundColor Gray
    $context = Get-MgContext
    if (!$context) {
        Write-Host "   Not connected to Microsoft Graph" -ForegroundColor Red
        Write-Host "   Please connect using the main menu first" -ForegroundColor Yellow
        return @{ Success = $false }
    }
    Write-Host "   Connected as: $($context.Account)" -ForegroundColor Green

    # Check and request scopes
    Write-Host "   Checking required permissions..." -ForegroundColor Gray
    $missingScopes = $RequiredScopes | Where-Object { $_ -notin $context.Scopes }

    if ($missingScopes.Count -gt 0) {
        Write-Host "   Missing scopes: $($missingScopes -join ', ')" -ForegroundColor Yellow
        Write-Host "   Requesting additional permissions..." -ForegroundColor Yellow

        try {
            $allScopes = ($context.Scopes + $missingScopes) | Select-Object -Unique
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            Connect-MgGraph -Scopes $allScopes -NoWelcome -ErrorAction Stop
            Write-Host "   Permissions updated" -ForegroundColor Green
        }
        catch {
            Write-Host "   Could not get required permissions: $($_.Exception.Message)" -ForegroundColor Red
            return @{ Success = $false }
        }
    }
    else {
        Write-Host "   All required permissions present" -ForegroundColor Green
    }

    # Check Security Defaults status
    Write-Host "   Checking Security Defaults status..." -ForegroundColor Gray
    $securityDefaultsResult = Test-SecurityDefaults

    if (!$securityDefaultsResult.Success) {
        return @{ Success = $false }
    }

    # Check for NoMFA Exclusion Group
    Write-Host "   Checking for NoMFA Exclusion Group..." -ForegroundColor Gray
    $noMfaGroupResult = Test-NoMfaGroup

    if (!$noMfaGroupResult.Success) {
        return @{ Success = $false }
    }

    Write-Host ""
    return @{
        Success = $true
        NoMfaGroupId = $noMfaGroupResult.GroupId
        SecurityDefaultsDisabled = $securityDefaultsResult.IsDisabled
    }
}

function Test-SecurityDefaults {
    <#
    .SYNOPSIS
        Check Security Defaults and offer to disable if enabled
    #>

    try {
        $policy = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop

        if ($policy.IsEnabled -eq $true) {
            Write-Host "   Security Defaults is ENABLED" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "   Conditional Access policies CANNOT be created while Security Defaults is enabled." -ForegroundColor Yellow
            Write-Host "   Security Defaults must be disabled first." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "   [Y] Disable Security Defaults now  [N] Cancel" -ForegroundColor Gray
            $confirm = Read-Host "   Disable Security Defaults? (Y/N)"

            if ($confirm -notlike "Y*") {
                Write-Host "   Cancelled - Security Defaults remains enabled" -ForegroundColor Yellow
                return @{ Success = $false; IsDisabled = $false }
            }

            # Disable Security Defaults via REST (more reliable than cmdlet)
            Write-Host "   Disabling Security Defaults..." -ForegroundColor Yellow
            $null = Invoke-MgGraphRequest -Method PATCH `
                -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy" `
                -Body (@{ isEnabled = $false } | ConvertTo-Json) `
                -ErrorAction Stop

            # Verify with retry - Graph API changes can take a few seconds to propagate
            $verified = $false
            for ($i = 1; $i -le 5; $i++) {
                Start-Sleep -Seconds 3
                $verification = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
                if ($verification.isEnabled -eq $false) {
                    $verified = $true
                    break
                }
                Write-Host "   Waiting for change to propagate... ($i/5)" -ForegroundColor Gray
            }

            if ($verified) {
                Write-Host "   Security Defaults disabled successfully" -ForegroundColor Green
                return @{ Success = $true; IsDisabled = $true }
            }
            else {
                # Update was sent - proceed even if verification timed out
                Write-Host "   Security Defaults update sent - proceeding" -ForegroundColor Yellow
                return @{ Success = $true; IsDisabled = $true }
            }
        }
        else {
            Write-Host "   Security Defaults already disabled" -ForegroundColor Green
            return @{ Success = $true; IsDisabled = $true }
        }
    }
    catch {
        Write-Host "   Error checking Security Defaults: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "   Try manual disable: Entra admin center > Identity > Overview > Properties" -ForegroundColor Yellow
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Test-NoMfaGroup {
    <#
    .SYNOPSIS
        Check for NoMFA Exclusion Group and offer to create if missing
    #>

    try {
        $group = Get-MgGroup -Filter "displayName eq 'NoMFA Exclusion Group'" -ErrorAction SilentlyContinue

        if ($group) {
            Write-Host "   NoMFA Exclusion Group found (ID: $($group.Id))" -ForegroundColor Green
            return @{ Success = $true; GroupId = $group.Id }
        }

        # Group doesn't exist - offer to create
        Write-Host "   NoMFA Exclusion Group not found" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "   This group is required to exclude break-glass accounts from MFA policies." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "   [Y] Create NoMFA Exclusion Group now  [N] Cancel" -ForegroundColor Gray
        $confirm = Read-Host "   Create the group? (Y/N)"

        if ($confirm -notlike "Y*") {
            Write-Host "   Cancelled - run Security Groups script first" -ForegroundColor Yellow
            return @{ Success = $false }
        }

        # Create the group
        Write-Host "   Creating NoMFA Exclusion Group..." -ForegroundColor Yellow

        $groupParams = @{
            DisplayName = "NoMFA Exclusion Group"
            Description = "Members excluded from MFA requirements - USE FOR BREAK-GLASS ACCOUNTS ONLY"
            MailEnabled = $false
            MailNickname = "NoMFA-Exclusion"
            SecurityEnabled = $true
        }

        $newGroup = New-MgGroup -BodyParameter $groupParams -ErrorAction Stop
        Write-Host "   Created NoMFA Exclusion Group (ID: $($newGroup.Id))" -ForegroundColor Green
        Write-Host "   IMPORTANT: Add break-glass accounts to this group!" -ForegroundColor Yellow

        return @{ Success = $true; GroupId = $newGroup.Id; Created = $true }
    }
    catch {
        Write-Host "   Error with NoMFA group: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ============================================================================
# DATA FUNCTIONS
# ============================================================================

function Get-TenantInfo {
    try {
        $org = Get-MgOrganization | Select-Object -First 1
        $domain = $org.VerifiedDomains | Where-Object { $_.IsDefault -eq $true } | Select-Object -ExpandProperty Name
        $companyInitials = ($domain -split '\.')[0].ToUpper()

        return @{
            Domain = $domain
            CompanyInitials = $companyInitials
            TenantId = $org.Id
            OrganizationName = $org.DisplayName
        }
    }
    catch {
        Write-Host "   Failed to get tenant info: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Get-PolicyDefinitions {
    param([string]$NoMfaGroupId)

    return @(
        @{
            displayName = "C001 - Block High Risk Users"
            state = "enabled"
            conditions = @{
                applications = @{ includeApplications = @("All") }
                clientAppTypes = @("all")
                userRiskLevels = @("high")
                users = @{
                    includeUsers = @("All")
                    excludeGroups = @($NoMfaGroupId)
                }
            }
            grantControls = @{
                builtInControls = @("block")
                operator = "OR"
            }
        },
        @{
            displayName = "C002 - MFA Required for All Users"
            state = "enabled"
            conditions = @{
                applications = @{ includeApplications = @("All") }
                clientAppTypes = @("browser", "mobileAppsAndDesktopClients")
                users = @{
                    includeUsers = @("All")
                    excludeGroups = @($NoMfaGroupId)
                }
            }
            grantControls = @{
                builtInControls = @("mfa")
                operator = "OR"
            }
        },
        @{
            displayName = "C003 - Block Non Corporate Devices"
            state = "enabled"
            conditions = @{
                applications = @{ includeApplications = @("All") }
                clientAppTypes = @("all")
                users = @{
                    includeUsers = @("All")
                    excludeGroups = @($NoMfaGroupId)
                    excludeRoles = @("d29b2b05-8046-44ba-8758-1e26182fcf32")
                }
            }
            grantControls = @{
                builtInControls = @("mfa", "compliantDevice", "domainJoinedDevice")
                operator = "OR"
            }
        },
        @{
            displayName = "C004 - Require Password Change for High Risk Users"
            state = "enabled"
            conditions = @{
                applications = @{ includeApplications = @("All") }
                clientAppTypes = @("all")
                userRiskLevels = @("high")
                users = @{
                    includeUsers = @("All")
                    excludeGroups = @($NoMfaGroupId)
                }
            }
            grantControls = @{
                builtInControls = @("mfa", "passwordChange")
                operator = "AND"
            }
        },
        @{
            displayName = "C005 - Require MFA for Risky Sign-Ins"
            state = "enabled"
            conditions = @{
                applications = @{ includeApplications = @("All") }
                clientAppTypes = @("all")
                signInRiskLevels = @("high", "medium")
                users = @{
                    includeUsers = @("All")
                    excludeGroups = @($NoMfaGroupId)
                }
            }
            grantControls = @{
                builtInControls = @("mfa")
                operator = "OR"
            }
        }
    )
}

# ============================================================================
# PREVIEW MODE
# ============================================================================

function Show-PolicyPreview {
    param(
        [array]$Policies,
        [string]$NoMfaGroupId
    )

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  PREVIEW: Conditional Access Policies" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  The following $($Policies.Count) CA policies will be created:" -ForegroundColor White
    Write-Host ""

    # Header
    Write-Host "  # | Policy Name                                  | State   | Grant" -ForegroundColor Yellow
    Write-Host "  --|----------------------------------------------|---------|------------------" -ForegroundColor Gray

    $index = 1
    foreach ($policy in $Policies) {
        $name = $policy.displayName
        if ($name.Length -gt 44) { $name = $name.Substring(0, 41) + "..." }

        $grant = ($policy.grantControls.builtInControls -join "+")
        if ($grant.Length -gt 16) { $grant = $grant.Substring(0, 13) + "..." }

        Write-Host ("  {0,2} | {1,-44} | {2,-7} | {3}" -f $index, $name, $policy.state, $grant) -ForegroundColor White
        $index++
    }

    Write-Host ""
    Write-Host "  All policies will:" -ForegroundColor Yellow
    Write-Host "    - Exclude NoMFA Exclusion Group (break-glass accounts)" -ForegroundColor Gray
    Write-Host "    - Be ENABLED immediately" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  NoMFA Exclusion Group ID: $NoMfaGroupId" -ForegroundColor Gray
    Write-Host ""
}

# ============================================================================
# POLICY CREATION
# ============================================================================

function New-ConditionalAccessPolicy {
    param(
        [hashtable]$PolicyConfig,
        [string]$NoMfaGroupId
    )

    $policyName = $PolicyConfig.displayName

    try {
        # Check if policy already exists
        $existingPolicy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$policyName'" -ErrorAction SilentlyContinue

        if ($existingPolicy) {
            Write-Host "     Already exists (skipped)" -ForegroundColor Yellow
            return @{ Success = $true; Policy = $existingPolicy; Skipped = $true }
        }

        # Ensure NoMFA group is in exclusions
        if ($NoMfaGroupId -and $PolicyConfig.conditions.users.excludeGroups -notcontains $NoMfaGroupId) {
            $PolicyConfig.conditions.users.excludeGroups = @($NoMfaGroupId)
        }

        # Create policy
        $newPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicyConfig -ErrorAction Stop

        Write-Host "     Created successfully (ID: $($newPolicy.Id))" -ForegroundColor Green
        return @{ Success = $true; Policy = $newPolicy; Skipped = $false }
    }
    catch {
        Write-Host "     Failed: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-CAPolicyCreation {
    # Header
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  CONDITIONAL ACCESS POLICIES" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Creates security policies for identity protection" -ForegroundColor Gray
    Write-Host ""

    # Step 1: Prerequisites (with auto-fix)
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

    $noMfaGroupId = $prereqResult.NoMfaGroupId

    # Step 2: Load data
    Write-Host "  STEP 2: Loading Data" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    $tenantInfo = Get-TenantInfo
    if (!$tenantInfo) {
        Write-Host "   Failed to get tenant information" -ForegroundColor Red
        return
    }
    Write-Host "   Tenant: $($tenantInfo.OrganizationName)" -ForegroundColor Green

    $policies = Get-PolicyDefinitions -NoMfaGroupId $noMfaGroupId
    Write-Host "   Loaded $($policies.Count) policy definitions" -ForegroundColor Green

    # Step 3: Preview
    Write-Host ""
    Write-Host "  STEP 3: Preview" -ForegroundColor Yellow
    Show-PolicyPreview -Policies $policies -NoMfaGroupId $noMfaGroupId

    # Confirmation
    Write-Host "  [Y] Proceed with creation  [N] Cancel" -ForegroundColor Gray
    Write-Host ""
    $confirm = Read-Host "  Create these CA policies? (Y/N)"

    if ($confirm -notlike "Y*") {
        Write-Host ""
        Write-Host "  Cancelled by user" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    # Step 4: Execute
    Write-Host ""
    Write-Host "  STEP 4: Creating Policies" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    $results = @{
        Created = @()
        Skipped = @()
        Failed = @()
    }

    foreach ($policy in $policies) {
        Write-Host "   $($policy.DisplayName)..." -ForegroundColor White

        $result = New-ConditionalAccessPolicy -PolicyConfig $policy -NoMfaGroupId $noMfaGroupId

        if ($result.Success) {
            if ($result.Skipped) {
                $results.Skipped += $policy.DisplayName
            }
            else {
                $results.Created += $policy.DisplayName
            }
        }
        else {
            $results.Failed += @{ Name = $policy.DisplayName; Error = $result.Error }
        }

        Start-Sleep -Milliseconds 500
    }

    # Step 5: Summary
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  Created: $($results.Created.Count)" -ForegroundColor Green
    Write-Host "  Skipped (existing): $($results.Skipped.Count)" -ForegroundColor Yellow
    Write-Host "  Failed: $($results.Failed.Count)" -ForegroundColor $(if ($results.Failed.Count -gt 0) { "Red" } else { "Green" })
    Write-Host ""

    if ($results.Created.Count -gt 0) {
        Write-Host "  Created Policies:" -ForegroundColor Green
        foreach ($name in $results.Created) {
            Write-Host "    - $name" -ForegroundColor White
        }
        Write-Host ""
    }

    if ($results.Failed.Count -gt 0) {
        Write-Host "  Failed Policies:" -ForegroundColor Red
        foreach ($fail in $results.Failed) {
            Write-Host "    - $($fail.Name): $($fail.Error)" -ForegroundColor Red
        }
        Write-Host ""
    }

    # Important warnings
    Write-Host "  IMPORTANT:" -ForegroundColor Red
    Write-Host "    - All policies are ENABLED immediately" -ForegroundColor Yellow
    Write-Host "    - Add break-glass accounts to NoMFA Exclusion Group NOW" -ForegroundColor Yellow
    Write-Host "    - Test with pilot users before full deployment" -ForegroundColor Yellow
    Write-Host ""

    Write-Host "  Next Steps:" -ForegroundColor Yellow
    Write-Host "    1. Add break-glass accounts to NoMFA Exclusion Group" -ForegroundColor Gray
    Write-Host "    2. Verify policies in Entra admin center" -ForegroundColor Gray
    Write-Host "    3. Monitor sign-in logs for policy impact" -ForegroundColor Gray
    Write-Host "    4. Test with pilot users" -ForegroundColor Gray
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

    Start-CAPolicyCreation
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
}
