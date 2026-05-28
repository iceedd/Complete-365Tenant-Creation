#Requires -Version 7.0

<#
.SYNOPSIS
    Configures Microsoft Purview retention policies and labels
.DESCRIPTION
    Manages data retention policies with prerequisite checks for Purview roles.
    Includes preview mode and auto-fix for common issues.
.AUTHOR
    BITS
.VERSION
    2.0 - Standardized UX with preview mode and role checks
#>

# ============================================================================
# CONFIGURATION
# ============================================================================

$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'ExchangeOnlineManagement'
)

$RequiredGraphScopes = @(
    "Directory.Read.All",
    "RoleManagement.Read.Directory"
)

# Purview role IDs (built-in Azure AD roles)
$PurviewRoles = @{
    "Compliance Administrator" = "17315797-102d-40b4-93e0-432062caca18"
    "Compliance Data Administrator" = "e6d1a23a-da11-4be4-9570-befc86d067a7"
    "Records Management" = "eb1d8c34-ebf8-43b5-b03b-e83f52531794"
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
# PREREQUISITES WITH ROLE CHECK
# ============================================================================

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Verify all prerequisites including Purview role assignments
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
    $missingScopes = $RequiredGraphScopes | Where-Object { $_ -notin $context.Scopes }

    if ($missingScopes.Count -gt 0) {
        Write-Host "   Missing scopes: $($missingScopes -join ', ')" -ForegroundColor Yellow
        Write-Host "   Requesting additional permissions..." -ForegroundColor Yellow

        try {
            $allScopes = ($context.Scopes + $missingScopes) | Select-Object -Unique
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            Connect-MgGraph -Scopes $allScopes -NoWelcome -ErrorAction Stop
            Write-Host "   Permissions updated" -ForegroundColor Green
            $context = Get-MgContext
        }
        catch {
            Write-Host "   Could not get required permissions: $($_.Exception.Message)" -ForegroundColor Red
            return @{ Success = $false }
        }
    }
    else {
        Write-Host "   All required permissions present" -ForegroundColor Green
    }

    # Check Purview/Compliance role
    Write-Host "   Checking Purview role assignments..." -ForegroundColor Gray
    $roleResult = Test-PurviewRole -UserEmail $context.Account

    if (!$roleResult.Success) {
        return @{ Success = $false }
    }

    Write-Host ""
    return @{
        Success = $true
        UserEmail = $context.Account
        PurviewRole = $roleResult.RoleName
    }
}

function Test-PurviewRole {
    param([string]$UserEmail)

    try {
        # Get user ID
        $user = Get-MgUser -Filter "userPrincipalName eq '$UserEmail'" -ErrorAction Stop

        if (!$user) {
            Write-Host "   Could not find user: $UserEmail" -ForegroundColor Red
            return @{ Success = $false }
        }

        # Check each Purview role
        foreach ($roleName in $PurviewRoles.Keys) {
            $roleId = $PurviewRoles[$roleName]

            try {
                $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($user.Id)' and roleDefinitionId eq '$roleId'" -ErrorAction SilentlyContinue

                if ($roleAssignments) {
                    Write-Host "   User has '$roleName' role" -ForegroundColor Green
                    return @{ Success = $true; RoleName = $roleName }
                }
            }
            catch {
                # Continue checking other roles
            }
        }

        # Also check Global Admin
        $globalAdminId = "62e90394-69f5-4237-9190-012177145e10"
        $globalAdminAssignment = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($user.Id)' and roleDefinitionId eq '$globalAdminId'" -ErrorAction SilentlyContinue

        if ($globalAdminAssignment) {
            Write-Host "   User has Global Administrator role" -ForegroundColor Green
            return @{ Success = $true; RoleName = "Global Administrator" }
        }

        # No required role found
        Write-Host "   Missing required Purview role!" -ForegroundColor Red
        Write-Host ""
        Write-Host "   To manage retention policies, you need one of these roles:" -ForegroundColor Yellow
        Write-Host "     - Compliance Administrator" -ForegroundColor Gray
        Write-Host "     - Compliance Data Administrator" -ForegroundColor Gray
        Write-Host "     - Records Management" -ForegroundColor Gray
        Write-Host "     - Global Administrator" -ForegroundColor Gray
        Write-Host ""
        Write-Host "   To assign a role:" -ForegroundColor Yellow
        Write-Host "   1. Go to Microsoft Entra admin center" -ForegroundColor Gray
        Write-Host "   2. Navigate to Roles and administrators" -ForegroundColor Gray
        Write-Host "   3. Search for 'Compliance Administrator'" -ForegroundColor Gray
        Write-Host "   4. Add your account as a member" -ForegroundColor Gray
        Write-Host "   5. Wait 5-10 minutes for role to propagate" -ForegroundColor Gray
        Write-Host ""

        return @{ Success = $false; MissingRole = $true }
    }
    catch {
        Write-Host "   Error checking roles: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "   Proceeding anyway - connection may still work" -ForegroundColor Yellow
        return @{ Success = $true; RoleName = "Unknown (proceeding)" }
    }
}

function Connect-SecurityCompliance {
    Write-Host "   Connecting to Security & Compliance Center..." -ForegroundColor Yellow

    try {
        # Probe for an active IPPS session by calling a Purview cmdlet.
        # Get-ConnectionInformation only checks Exchange Online connections, not IPPS.
        $null = Get-RetentionCompliancePolicy -ResultSize 1 -ErrorAction Stop
        Write-Host "   Already connected to Security & Compliance" -ForegroundColor Green
        return $true
    }
    catch {
        # Not connected — attempt fresh IPPS connection
    }

    try {
        Connect-IPPSSession -ErrorAction Stop
        Write-Host "   Connected to Security & Compliance Center" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "   Failed to connect to Security & Compliance: $($_.Exception.Message)" -ForegroundColor Red

        # Provide helpful troubleshooting
        if ($_.Exception.Message -like "*Access denied*" -or $_.Exception.Message -like "*Forbidden*") {
            Write-Host ""
            Write-Host "   ACCESS DENIED - This usually means:" -ForegroundColor Yellow
            Write-Host "   1. Your account lacks the required Purview role" -ForegroundColor Gray
            Write-Host "   2. The role was just assigned and hasn't propagated yet" -ForegroundColor Gray
            Write-Host "   3. The tenant doesn't have the required license" -ForegroundColor Gray
            Write-Host ""
            Write-Host "   Try these steps:" -ForegroundColor Yellow
            Write-Host "   - Wait 10-15 minutes if you just got the role assigned" -ForegroundColor Gray
            Write-Host "   - Sign out and sign back in completely" -ForegroundColor Gray
            Write-Host "   - Verify your role in Entra admin center" -ForegroundColor Gray
        }

        return $false
    }
}

# ============================================================================
# DATA FUNCTIONS
# ============================================================================

function Get-RetentionPolicyDefinitions {
    return @(
        @{
            Name = "7 Year Archive"
            Description = "Retain Exchange mailboxes and Microsoft 365 Group content for 7 years"
            RetentionDays = 2555
            Action = "Keep"
            Locations = @("Exchange", "Microsoft 365 Groups")
            RuleName = "7 Year Archive Rule"
            RuleComment = "Keep content for 7 years (2555 days)"
        }
    )
}

# ============================================================================
# PREVIEW MODE
# ============================================================================

function Show-RetentionPreview {
    param([array]$Policies)

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  PREVIEW: Retention Policies" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  The following retention policies will be created:" -ForegroundColor White
    Write-Host ""

    foreach ($policy in $Policies) {
        Write-Host "  Policy: $($policy.Name)" -ForegroundColor Yellow
        Write-Host "  ----------------------------------------" -ForegroundColor Gray
        Write-Host "    Description:      $($policy.Description)" -ForegroundColor White
        Write-Host "    Retention Period: $($policy.RetentionDays) days ($([math]::Round($policy.RetentionDays / 365, 1)) years)" -ForegroundColor White
        Write-Host "    Action:           $($policy.Action) (archive, don't delete)" -ForegroundColor White
        Write-Host "    Locations:        $($policy.Locations -join ', ')" -ForegroundColor White
        Write-Host "    Status:           Enabled" -ForegroundColor White
        Write-Host ""
    }

    Write-Host "  Note: Policies can take up to 24 hours to fully propagate." -ForegroundColor Gray
    Write-Host ""
}

# ============================================================================
# POLICY CREATION
# ============================================================================

function New-RetentionPolicyWithRule {
    param([hashtable]$PolicyConfig)

    $policyName = $PolicyConfig.Name

    try {
        # Check if policy already exists
        $existingPolicy = Get-RetentionCompliancePolicy -Identity $policyName -ErrorAction SilentlyContinue

        if ($existingPolicy) {
            Write-Host "     Already exists (skipped)" -ForegroundColor Yellow
            return @{ Success = $true; Skipped = $true; Policy = $existingPolicy }
        }

        # Create the retention policy
        Write-Host "     Creating policy..." -ForegroundColor Gray
        $policy = New-RetentionCompliancePolicy `
            -Name $policyName `
            -Comment $PolicyConfig.Description `
            -ExchangeLocation All `
            -ModernGroupLocation All `
            -Enabled $true `
            -ErrorAction Stop

        # Create the retention rule
        Write-Host "     Creating retention rule..." -ForegroundColor Gray
        $null = New-RetentionComplianceRule `
            -Name $PolicyConfig.RuleName `
            -Policy $policyName `
            -RetentionDuration $PolicyConfig.RetentionDays `
            -RetentionComplianceAction $PolicyConfig.Action `
            -Comment $PolicyConfig.RuleComment `
            -ErrorAction Stop

        Write-Host "     Created successfully" -ForegroundColor Green
        return @{ Success = $true; Skipped = $false; Policy = $policy }
    }
    catch {
        Write-Host "     Failed: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-RetentionPolicies {
    # Header
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  PURVIEW RETENTION POLICIES" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Creates data retention and archival policies" -ForegroundColor Gray
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

    # Step 2: Connect to Security & Compliance
    Write-Host ""
    Write-Host "  STEP 2: Connecting to Purview" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    if (!(Connect-SecurityCompliance)) {
        Write-Host ""
        Write-Host "  Failed to connect to Security & Compliance Center." -ForegroundColor Red
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    # Step 3: Load policy definitions
    Write-Host ""
    Write-Host "  STEP 3: Loading Policy Definitions" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    $policies = Get-RetentionPolicyDefinitions
    Write-Host "   Loaded $($policies.Count) policy definitions" -ForegroundColor Green

    # Step 4: Preview
    Write-Host ""
    Write-Host "  STEP 4: Preview" -ForegroundColor Yellow
    Show-RetentionPreview -Policies $policies

    # Confirmation
    Write-Host "  [Y] Proceed with creation  [N] Cancel" -ForegroundColor Gray
    Write-Host ""
    $confirm = Read-Host "  Create these retention policies? (Y/N)"

    if ($confirm -notlike "Y*") {
        Write-Host ""
        Write-Host "  Cancelled by user" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    # Step 5: Execute
    Write-Host ""
    Write-Host "  STEP 5: Creating Policies" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    $results = @{
        Created = @()
        Skipped = @()
        Failed = @()
    }

    foreach ($policy in $policies) {
        Write-Host "   $($policy.Name)..." -ForegroundColor White

        $result = New-RetentionPolicyWithRule -PolicyConfig $policy

        if ($result.Success) {
            if ($result.Skipped) {
                $results.Skipped += $policy.Name
            }
            else {
                $results.Created += $policy.Name
            }
        }
        else {
            $results.Failed += @{ Name = $policy.Name; Error = $result.Error }
        }

        Start-Sleep -Milliseconds 500
    }

    # Step 6: Summary
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

    # Important notes
    Write-Host "  IMPORTANT:" -ForegroundColor Yellow
    Write-Host "    - Policies can take up to 24 hours to fully propagate" -ForegroundColor Gray
    Write-Host "    - Content already in mailboxes will be scanned and retained" -ForegroundColor Gray
    Write-Host "    - This is ARCHIVE retention, not deletion" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  Next Steps:" -ForegroundColor Yellow
    Write-Host "    1. Verify policies in Microsoft Purview portal" -ForegroundColor Gray
    Write-Host "    2. Check policy status after 24 hours" -ForegroundColor Gray
    Write-Host "    3. Consider adding Sensitivity Labels (Phase 2)" -ForegroundColor Gray
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

    Start-RetentionPolicies
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
}
