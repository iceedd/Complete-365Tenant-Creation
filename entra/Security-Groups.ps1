#Requires -Version 7.0

<#
.SYNOPSIS
    Creates security groups for Entra ID management
.DESCRIPTION
    Creates user security groups for MFA exclusions, admin identification, SSPR, and license-based grouping.
    Includes preview mode and confirmation before creation.
.AUTHOR
    CB & Claude Partnership
.VERSION
    2.1 - Added Helpdesk Operator Group with Intune Help Desk Operator role assignment
#>

# ============================================================================
# CONFIGURATION
# ============================================================================

$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Groups'
)

$RequiredScopes = @(
    "Group.ReadWrite.All",
    "Directory.Read.All",
    "DeviceManagementRBAC.ReadWrite.All"
)

# Security group definitions
$SecurityGroups = @(
    @{
        Name = "NoMFA Exclusion Group"
        Description = "Users excluded from all Conditional Access policies and MFA requirements"
        GroupType = "Assigned"
        MembershipType = "Manual"
    },
    @{
        Name = "BITS Admin Users"
        Description = "Dynamic group containing all BITS admin users"
        MembershipRule = '(user.userPrincipalName -contains "BITS-Admin") or (user.displayName -contains "BITS-Admin")'
        GroupType = "DynamicMembership"
        MembershipType = "Dynamic"
    },
    @{
        Name = "SSPR Eligible Users"
        Description = "All enabled users eligible for Self-Service Password Reset (excludes BITS admins and disabled accounts)"
        MembershipRule = '(user.accountEnabled -eq true) and (user.userType -eq "Member") and not ((user.userPrincipalName -contains "BITS-Admin") or (user.displayName -contains "BITS-Admin"))'
        GroupType = "DynamicMembership"
        MembershipType = "Dynamic"
    },
    @{
        Name = "License - Business Basic"
        Description = "Enabled users with Business Basic licensing assignment"
        MembershipRule = '(user.accountEnabled -eq true) and (user.extensionAttribute1 -eq "BusinessBasic")'
        GroupType = "DynamicMembership"
        MembershipType = "Dynamic"
    },
    @{
        Name = "License - Business Standard"
        Description = "Enabled users with Business Standard licensing assignment"
        MembershipRule = '(user.accountEnabled -eq true) and (user.extensionAttribute1 -eq "BusinessStandard")'
        GroupType = "DynamicMembership"
        MembershipType = "Dynamic"
    },
    @{
        Name = "License - Business Premium"
        Description = "Enabled users with Business Premium licensing assignment"
        MembershipRule = '(user.accountEnabled -eq true) and (user.extensionAttribute1 -eq "BusinessPremium")'
        GroupType = "DynamicMembership"
        MembershipType = "Dynamic"
    },
    @{
        Name = "License - Exchange Online Plan 1"
        Description = "Enabled users with Exchange Online Plan 1 licensing assignment"
        MembershipRule = '(user.accountEnabled -eq true) and (user.extensionAttribute1 -eq "ExchangeOnline1")'
        GroupType = "DynamicMembership"
        MembershipType = "Dynamic"
    },
    @{
        Name = "License - Exchange Online Plan 2"
        Description = "Enabled users with Exchange Online Plan 2 licensing assignment"
        MembershipRule = '(user.accountEnabled -eq true) and (user.extensionAttribute1 -eq "ExchangeOnline2")'
        GroupType = "DynamicMembership"
        MembershipType = "Dynamic"
    },
    @{
        Name = "Helpdesk Operator Group"
        Description = "Dynamic group for Intune Help Desk Operator role - contains Cloud and HD admins"
        MembershipRule = '(user.displayName -startsWith "BITS-Admin-Cloud") or (user.displayName -startsWith "BITS-Admin-HD")'
        GroupType = "DynamicMembership"
        MembershipType = "Dynamic"
        AssignIntuneRole = $true
    }
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
# PREREQUISITES
# ============================================================================

function Test-Prerequisites {
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

    # Check for existing groups
    Write-Host "   Checking for existing groups..." -ForegroundColor Gray
    $existingGroups = @()
    foreach ($group in $SecurityGroups) {
        $existing = Get-MgGroup -Filter "displayName eq '$($group.Name)'" -ErrorAction SilentlyContinue
        if ($existing) {
            $existingGroups += $group.Name
        }
    }

    if ($existingGroups.Count -gt 0) {
        Write-Host "   Found $($existingGroups.Count) existing groups (will be skipped)" -ForegroundColor Yellow
    }
    else {
        Write-Host "   No existing groups found" -ForegroundColor Green
    }

    Write-Host ""
    return @{
        Success = $true
        ExistingGroups = $existingGroups
    }
}

# ============================================================================
# PREVIEW MODE
# ============================================================================

function Show-GroupPreview {
    param(
        [array]$Groups,
        [array]$ExistingGroups
    )

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  PREVIEW: Security Groups" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  The following $($Groups.Count) security groups will be created:" -ForegroundColor White
    Write-Host ""

    # Header
    Write-Host "  # | Name                           | Type     | Status" -ForegroundColor Yellow
    Write-Host "  --|--------------------------------|----------|--------" -ForegroundColor Gray

    $index = 1
    foreach ($group in $Groups) {
        $name = $group.Name
        if ($name.Length -gt 30) { $name = $name.Substring(0, 27) + "..." }

        $status = if ($ExistingGroups -contains $group.Name) { "EXISTS" } else { "NEW" }
        $statusColor = if ($status -eq "EXISTS") { "Yellow" } else { "Green" }

        Write-Host -NoNewline ("  {0,2} | {1,-30} | {2,-8} | " -f $index, $name, $group.MembershipType)
        Write-Host $status -ForegroundColor $statusColor
        $index++
    }

    Write-Host ""
    Write-Host "  Group Types:" -ForegroundColor Yellow
    Write-Host "    - Assigned: Members manually added" -ForegroundColor Gray
    Write-Host "    - Dynamic:  Members auto-populated by rule" -ForegroundColor Gray
    Write-Host ""

    $newCount = $Groups.Count - $ExistingGroups.Count
    Write-Host "  Summary: $newCount new groups will be created, $($ExistingGroups.Count) existing will be skipped" -ForegroundColor White
    Write-Host ""
}

# ============================================================================
# INTUNE ROLE ASSIGNMENT
# ============================================================================

function Add-IntuneHelpDeskOperatorRole {
    <#
    .SYNOPSIS
        Assigns the Intune Help Desk Operator role to a group
    #>
    param([string]$GroupId)

    try {
        Write-Host "     Assigning Intune Help Desk Operator role..." -ForegroundColor Gray

        # Get the built-in Help Desk Operator role definition
        $roleDefsUri = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions?`$filter=isBuiltIn eq true"
        $roleDefs = Invoke-MgGraphRequest -Uri $roleDefsUri -Method GET
        $helpDeskRole = $roleDefs.value | Where-Object { $_.displayName -eq "Help Desk Operator" } | Select-Object -First 1

        if (!$helpDeskRole) {
            Write-Host "       Help Desk Operator role not found in Intune" -ForegroundColor Yellow
            return $false
        }

        # Check if assignment already exists
        $existingUri = "https://graph.microsoft.com/beta/deviceManagement/roleAssignments?`$filter=displayName eq 'Helpdesk Operator Group Assignment'"
        $existing = Invoke-MgGraphRequest -Uri $existingUri -Method GET
        if ($existing.value.Count -gt 0) {
            Write-Host "       Role assignment already exists" -ForegroundColor Gray
            return $true
        }

        # Create the role assignment - simpler structure for allDevices scope
        $assignmentBody = @{
            id = ""
            displayName = "Helpdesk Operator Group Assignment"
            description = "Assigns Help Desk Operator role to Helpdesk Operator Group"
            members = @($GroupId)
            resourceScopes = @()
            scopeType = "allDevices"
            "roleDefinition@odata.bind" = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions('$($helpDeskRole.id)')"
        }

        $assignUri = "https://graph.microsoft.com/beta/deviceManagement/roleAssignments"
        $null = Invoke-MgGraphRequest -Uri $assignUri -Method POST -Body $assignmentBody
        Write-Host "       Intune Help Desk Operator role assigned" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "       Failed to assign Intune role: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "       You may need to assign this manually in Intune" -ForegroundColor Gray
        return $false
    }
}

# ============================================================================
# GROUP CREATION
# ============================================================================

function New-SecurityGroupItem {
    param([hashtable]$GroupConfig)

    $groupName = $GroupConfig.Name

    try {
        # Check if group already exists
        $existingGroup = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue

        if ($existingGroup) {
            Write-Host "     Already exists (skipped)" -ForegroundColor Yellow
            return @{ Success = $true; Skipped = $true; Group = $existingGroup }
        }

        # Create mail nickname (required for all groups)
        $mailNickname = $groupName -replace '[^a-zA-Z0-9]', '' -replace '\s', ''

        # Base group parameters
        $groupParams = @{
            DisplayName = $groupName
            Description = $GroupConfig.Description
            SecurityEnabled = $true
            MailEnabled = $false
            MailNickname = $mailNickname
        }

        # Add dynamic membership settings if specified
        if ($GroupConfig.GroupType -eq "DynamicMembership") {
            $groupParams.GroupTypes = @("DynamicMembership")
            $groupParams.MembershipRule = $GroupConfig.MembershipRule
            $groupParams.MembershipRuleProcessingState = "On"
        }
        else {
            $groupParams.GroupTypes = @()
        }

        # Create the group
        $newGroup = New-MgGroup -BodyParameter $groupParams -ErrorAction Stop

        Write-Host "     Created (ID: $($newGroup.Id))" -ForegroundColor Green
        return @{ Success = $true; Skipped = $false; Group = $newGroup }
    }
    catch {
        Write-Host "     Failed: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-SecurityGroupCreation {
    # Header
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  SECURITY GROUPS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Creates Entra ID security groups for access management" -ForegroundColor Gray
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

    # Step 2: Preview
    Write-Host ""
    Write-Host "  STEP 2: Preview" -ForegroundColor Yellow
    Show-GroupPreview -Groups $SecurityGroups -ExistingGroups $prereqResult.ExistingGroups

    # Confirmation
    Write-Host "  [Y] Proceed with creation  [N] Cancel" -ForegroundColor Gray
    Write-Host ""
    $confirm = Read-Host "  Create these security groups? (Y/N)"

    if ($confirm -notlike "Y*") {
        Write-Host ""
        Write-Host "  Cancelled by user" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    # Step 3: Execute
    Write-Host ""
    Write-Host "  STEP 3: Creating Groups" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    $results = @{
        Created = @()
        Skipped = @()
        Failed = @()
    }

    foreach ($group in $SecurityGroups) {
        Write-Host "   $($group.Name)..." -ForegroundColor White

        $result = New-SecurityGroupItem -GroupConfig $group

        if ($result.Success) {
            if ($result.Skipped) {
                $results.Skipped += @{ Name = $group.Name; Id = $result.Group.Id }
            }
            else {
                $results.Created += @{ Name = $group.Name; Id = $result.Group.Id }
            }

            # Assign Intune Help Desk Operator role if this is the Helpdesk Operator Group
            if ($group.AssignIntuneRole -and $result.Group.Id) {
                $null = Add-IntuneHelpDeskOperatorRole -GroupId $result.Group.Id
            }
        }
        else {
            $results.Failed += @{ Name = $group.Name; Error = $result.Error }
        }

        Start-Sleep -Milliseconds 500
    }

    # Step 4: Summary
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
        Write-Host "  Created Groups:" -ForegroundColor Green
        foreach ($item in $results.Created) {
            Write-Host "    - $($item.Name)" -ForegroundColor White
            Write-Host "      ID: $($item.Id)" -ForegroundColor Gray
        }
        Write-Host ""
    }

    if ($results.Failed.Count -gt 0) {
        Write-Host "  Failed Groups:" -ForegroundColor Red
        foreach ($fail in $results.Failed) {
            Write-Host "    - $($fail.Name): $($fail.Error)" -ForegroundColor Red
        }
        Write-Host ""
    }

    # Important notes
    Write-Host "  IMPORTANT:" -ForegroundColor Yellow
    Write-Host "    - Dynamic groups take 5-10 minutes to populate members" -ForegroundColor Gray
    Write-Host "    - BITS Admin Users, Helpdesk Operator Group will auto-populate when admins are created" -ForegroundColor Gray
    Write-Host "    - NoMFA Exclusion Group is MANUAL - Admin-Creation adds BG02 automatically" -ForegroundColor Gray
    Write-Host "    - Set extensionAttribute1 on users for license groups" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  Next Steps:" -ForegroundColor Yellow
    Write-Host "    1. Run Admin-Creation script (adds BG02 to NoMFA group automatically)" -ForegroundColor Gray
    Write-Host "    2. Run Conditional Access Policies script" -ForegroundColor Gray
    Write-Host "    3. Configure user extensionAttribute1 for license assignment" -ForegroundColor Gray
    Write-Host ""

    # Show key group IDs
    $noMfaGroup = $results.Created + $results.Skipped | Where-Object { $_.Name -like "*NoMFA*" }
    if ($noMfaGroup) {
        Write-Host "  Key Group ID (save this):" -ForegroundColor Yellow
        Write-Host "    NoMFA Exclusion Group: $($noMfaGroup.Id)" -ForegroundColor Cyan
    }

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

    Start-SecurityGroupCreation
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
}
