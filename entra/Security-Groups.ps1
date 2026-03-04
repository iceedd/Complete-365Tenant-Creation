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
    3.0 - License groups now use Group-Based Licensing (GBL). Groups are created
          dynamically from tenant SKUs and licenses are attached automatically.
#>

# ============================================================================
# CONFIGURATION
# ============================================================================

$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Identity.DirectoryManagement'
)

$RequiredScopes = @(
    "Group.ReadWrite.All",
    "Directory.Read.All",
    "DeviceManagementRBAC.ReadWrite.All",
    "LicenseAssignment.ReadWrite.All"
)

# Friendly display names for common Microsoft 365 SKU part numbers
$SkuFriendlyNames = @{
    'O365_BUSINESS_ESSENTIALS'        = 'Microsoft 365 Business Basic'
    'SMB_BUSINESS_ESSENTIALS'         = 'Microsoft 365 Business Basic'
    'O365_BUSINESS_PREMIUM'           = 'Microsoft 365 Business Standard'
    'SMB_BUSINESS_PREMIUM'            = 'Microsoft 365 Business Standard'
    'SPE'                             = 'Microsoft 365 Business Premium'
    'SPB'                             = 'Microsoft 365 Business Premium'
    'EXCHANGESTANDARD'                = 'Exchange Online Plan 1'
    'EXCHANGEENTERPRISE'              = 'Exchange Online Plan 2'
    'VISIOONLINE'                     = 'Visio Plan 1'
    'VISIO_PLAN2_DEP'                 = 'Visio Plan 2'
    'MCOEV'                           = 'Teams Phone Standard'
    'DYN365_BUSCENTRAL_ESSENTIAL'     = 'Dynamics 365 Business Central Ess.'
    'DYN365_BUSCENTRAL_PREMIUM'       = 'Dynamics 365 Business Central Prem.'
    'Microsoft_365_Apps_for_Business' = 'Microsoft 365 Apps for Business'
    'TEAMS_ESSENTIALS'                = 'Microsoft Teams Essentials'
    'POWER_BI_PRO'                    = 'Power BI Pro'
    'PROJECTPREMIUM'                  = 'Project Plan 5'
    'PROJECTPROFESSIONAL'             = 'Project Plan 3'
}

# ─────────────────────────────────────────────────────────────────────────────
# LICENSE GROUPS — GROUP-BASED LICENSING (GBL)
# ─────────────────────────────────────────────────────────────────────────────
# One "License - <Name>" assigned security group is created per active SKU.
# The license SKU is attached to each group automatically (Set-MgGroupLicense).
# When a user is added to a group, M365 assigns the license automatically.
# When removed, the license is removed automatically.
# Re-running after a new license purchase creates the new group and attaches it.
#
# HD workflow in the provisioning tool:
#   Create user → select license group(s) → licenses assign automatically
# ─────────────────────────────────────────────────────────────────────────────

# Static security group definitions (non-license groups only)
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

    # Discover tenant licenses and verify which license groups apply
    Write-Host ""
    Write-Host "   STEP 1b: License Discovery" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray
    $licenseResult = Show-TenantLicenses

    Write-Host ""
    return @{
        Success              = $true
        ExistingGroups       = $existingGroups
        DynamicLicenseGroups = $licenseResult.DynamicLicenseGroups
    }
}

# ============================================================================
# LICENSE DISCOVERY
# ============================================================================

function Build-GblLicenseGroups {
    <#
    .SYNOPSIS
        Builds GBL license group configs from the tenant's active SKUs.
        Each group is an assigned security group — adding a user assigns the license.
    #>
    param([array]$ActiveSkus)

    $licenseGroups = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($sku in $ActiveSkus) {
        $friendlyName  = if ($SkuFriendlyNames.ContainsKey($sku.SkuPartNumber)) {
            $SkuFriendlyNames[$sku.SkuPartNumber]
        }
        else {
            $sku.SkuPartNumber
        }

        $available = $sku.PrepaidUnits.Enabled - $sku.ConsumedUnits

        $licenseGroups.Add(@{
            Name           = "License - $friendlyName"
            Description    = "Group-based licensing for $friendlyName. Adding a user to this group automatically assigns the license."
            GroupType      = "Assigned"
            MembershipType = "Manual"
            SkuId          = $sku.SkuId
            SkuPartNumber  = $sku.SkuPartNumber
            FriendlyName   = $friendlyName
            TotalSeats     = $sku.PrepaidUnits.Enabled
            ConsumedSeats  = $sku.ConsumedUnits
            AvailableSeats = $available
        })
    }

    return $licenseGroups.ToArray()
}

function Show-TenantLicenses {
    Write-Host "   Fetching tenant licenses..." -ForegroundColor Gray

    try {
        $allSkus = @(
            Get-MgSubscribedSku -All -ErrorAction Stop |
            Where-Object { $_.CapabilityStatus -eq 'Enabled' -and $_.PrepaidUnits.Enabled -gt 0 } |
            Sort-Object SkuPartNumber
        )

        if ($allSkus.Count -eq 0) {
            Write-Host "   No active licenses found in tenant" -ForegroundColor Yellow
            return @{ DynamicLicenseGroups = @() }
        }

        # Build GBL groups from active SKUs
        $gblGroups = Build-GblLicenseGroups -ActiveSkus $allSkus

        # Display combined table: license + seat counts + GBL group status
        Write-Host ""
        Write-Host "   GBL LICENSE GROUPS (one group per active license)" -ForegroundColor Yellow
        Write-Host ("   " + "-" * 62) -ForegroundColor Gray
        Write-Host ("   {0,-36} {1,7} {2,11}" -f "License Group", "In Use", "Available") -ForegroundColor Yellow
        Write-Host ("   " + "-" * 62) -ForegroundColor Gray

        $noSeatsCount = 0
        foreach ($group in $gblGroups | Sort-Object Name) {
            $display    = if ($group.Name.Length -gt 36) { $group.Name.Substring(0, 33) + '...' } else { $group.Name }
            $available  = $group.AvailableSeats
            $availColor = if ($available -le 0) { 'Red' } elseif ($available -le 5) { 'Yellow' } else { 'Green' }
            $availText  = if ($available -le 0) { 'NO SEATS' } else { "$available" }

            Write-Host -NoNewline ("   {0,-36} {1,7} " -f $display, $group.ConsumedSeats)
            Write-Host ("{0,11}" -f $availText) -ForegroundColor $availColor

            if ($available -le 0) { $noSeatsCount++ }
        }

        Write-Host ("   " + "-" * 62) -ForegroundColor Gray
        Write-Host ("   {0} GBL license group(s) will be created" -f $gblGroups.Count) -ForegroundColor White

        if ($noSeatsCount -gt 0) {
            Write-Host ""
            Write-Host "   WARNING: $noSeatsCount license(s) have no available seats." -ForegroundColor Red
            Write-Host "   HD will receive a warning if they try to assign these." -ForegroundColor Yellow
            Write-Host "   Contact your sales team to purchase additional seats." -ForegroundColor Gray
        }

        Write-Host ""
        return @{ DynamicLicenseGroups = $gblGroups }
    }
    catch {
        Write-Host "   Could not retrieve license data: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "   License group creation skipped" -ForegroundColor Gray
        return @{ DynamicLicenseGroups = @() }
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
# LICENSE ATTACHMENT
# ============================================================================

function Set-GroupLicenseAssignment {
    param(
        [string]$GroupId,
        [string]$SkuId
    )

    try {
        # Check if license is already attached
        $licenseDetails = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId/licenseDetails" `
            -ErrorAction SilentlyContinue
        if ($licenseDetails -and $licenseDetails.value) {
            $existing = @($licenseDetails.value | Where-Object { $_.skuId -eq $SkuId })
            if ($existing.Count -gt 0) {
                Write-Host "     License already attached to group" -ForegroundColor Gray
                return $true
            }
        }

        # Pre-serialize body to avoid Invoke-MgGraphRequest hashtable serialization issues
        $bodyJson = [ordered]@{
            addLicenses    = @([ordered]@{ skuId = $SkuId })
            removeLicenses = @()
        } | ConvertTo-Json -Depth 5 -Compress

        $null = Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId/assignLicense" `
            -Body $bodyJson `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Host "     License attached — members will be assigned automatically" -ForegroundColor Green
        return $true
    }
    catch {
        $errMsg = $_.Exception.Message
        Write-Host "     Failed to attach license: $errMsg" -ForegroundColor Yellow
        if ($errMsg -like "*NotFound*" -or $errMsg -like "*404*") {
            Write-Host "     Common causes for 404 on assignLicense:" -ForegroundColor Gray
            Write-Host "       1. LicenseAssignment.ReadWrite.All consent not granted" -ForegroundColor Gray
            Write-Host "          Fix: re-run script and approve the permission prompt" -ForegroundColor Gray
            Write-Host "       2. Group-Based Licensing requires Azure AD Premium P1 or higher" -ForegroundColor Gray
            Write-Host "          Included in: Business Premium, E3, E5 — NOT in Basic/Standard" -ForegroundColor Gray
            Write-Host "       3. Existing group may be wrong type (must be plain security group)" -ForegroundColor Gray
        }
        Write-Host "     Manual: Entra admin centre > Groups > [group] > Licenses > + Assignments" -ForegroundColor Gray
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
            # For license groups, still verify the license is attached in case it was missed
            if ($GroupConfig.SkuId) {
                $null = Set-GroupLicenseAssignment -GroupId $existingGroup.Id -SkuId $GroupConfig.SkuId
            }
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

        # For license groups, wait briefly for Azure AD replication before attaching SKU
        if ($GroupConfig.SkuId) {
            Write-Host "     Waiting for group to provision..." -ForegroundColor Gray
            Start-Sleep -Seconds 5
            $null = Set-GroupLicenseAssignment -GroupId $newGroup.Id -SkuId $GroupConfig.SkuId
        }

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

    # Combine static groups with dynamically discovered license groups
    $groupsToCreate = @($SecurityGroups) + @($prereqResult.DynamicLicenseGroups)

    # Step 2: Preview
    Write-Host ""
    Write-Host "  STEP 2: Preview" -ForegroundColor Yellow
    Show-GroupPreview -Groups $groupsToCreate -ExistingGroups $prereqResult.ExistingGroups

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

    foreach ($group in $groupsToCreate) {
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
    Write-Host "    - Dynamic groups (BITS Admin, SSPR, Helpdesk) take 5-10 min to populate" -ForegroundColor Gray
    Write-Host "    - NoMFA Exclusion Group is MANUAL - Admin-Creation adds BG02 automatically" -ForegroundColor Gray
    Write-Host "    - License groups use Group-Based Licensing (GBL):" -ForegroundColor Gray
    Write-Host "        Add user to group  ->  M365 assigns license automatically" -ForegroundColor Gray
    Write-Host "        Remove from group  ->  M365 removes license automatically" -ForegroundColor Gray
    Write-Host "    - Users can be in multiple license groups to receive multiple licenses" -ForegroundColor Gray
    Write-Host "    - GBL processing can take up to 10 minutes after group membership changes" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  Next Steps:" -ForegroundColor Yellow
    Write-Host "    1. Run Admin-Creation script (adds BG02 to NoMFA group automatically)" -ForegroundColor Gray
    Write-Host "    2. Use the provisioning tool to create users and assign them to license groups" -ForegroundColor Gray
    Write-Host "    3. Run Conditional Access Policies script" -ForegroundColor Gray
    Write-Host "    4. Re-run this script after purchasing new licenses to add new GBL groups" -ForegroundColor Gray
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
