#Requires -Version 7.0

<#
.SYNOPSIS
    Creates comprehensive Intune compliance policies with device group assignments
.DESCRIPTION
    Creates 4 platform-specific compliance policies using exported settings data.
    Includes password/passcode requirements, encryption enforcement, OS version compliance,
    and security baseline settings for Android, iOS, macOS, and Windows devices.
.AUTHOR
    CB & Claude Partnership
.VERSION
    2.0 - Standardized UX with preview mode
#>

# ============================================================================
# CONFIGURATION
# ============================================================================

$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.DeviceManagement',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Identity.DirectoryManagement'
)

$RequiredScopes = @(
    'DeviceManagementConfiguration.ReadWrite.All',
    'DeviceManagementManagedDevices.ReadWrite.All',
    'Group.Read.All',
    'Directory.Read.All'
)

# Policy assignment configuration - maps to our dynamic device groups
$PolicyAssignments = @{
    "Android Basic Compliance" = @("Android Devices", "Corporate Owned Devices")
    "iOS Basic Compliance" = @("iOS Devices", "Corporate Owned Devices")
    "macOS Basic Compliance" = @("macOS Devices", "Corporate Owned Devices")
    "Windows 10/11 Basic Compliance" = @("Windows Devices (Autopilot)", "Corporate Owned Devices")
}

# ============================================================================
# HELPER FUNCTIONS (fallback if shared helpers not loaded)
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
    <#
    .SYNOPSIS
        Verify all prerequisites before running
    #>

    Write-Host ""
    Write-Host "   PREREQUISITES CHECK" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 40) -ForegroundColor Gray

    $allPassed = $true

    # Check Graph connection
    Write-Host "   Checking Microsoft Graph connection..." -ForegroundColor Gray
    $context = Get-MgContext
    if (!$context) {
        Write-Host "   Not connected to Microsoft Graph" -ForegroundColor Red
        Write-Host "   Please connect using the main menu first" -ForegroundColor Yellow
        return $false
    }
    Write-Host "   Connected as: $($context.Account)" -ForegroundColor Green

    # Check scopes
    Write-Host "   Checking required permissions..." -ForegroundColor Gray
    $missingScopes = $RequiredScopes | Where-Object { $_ -notin $context.Scopes }

    if ($missingScopes.Count -gt 0) {
        Write-Host "   Missing scopes: $($missingScopes -join ', ')" -ForegroundColor Yellow
        Write-Host "   Attempting to request additional permissions..." -ForegroundColor Yellow

        try {
            $allScopes = ($context.Scopes + $missingScopes) | Select-Object -Unique
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            Connect-MgGraph -Scopes $allScopes -NoWelcome -ErrorAction Stop
            Write-Host "   Permissions updated" -ForegroundColor Green
        }
        catch {
            Write-Host "   Could not get required permissions: $($_.Exception.Message)" -ForegroundColor Red
            $allPassed = $false
        }
    }
    else {
        Write-Host "   All required permissions present" -ForegroundColor Green
    }

    # Check for device groups
    Write-Host "   Checking for required device groups..." -ForegroundColor Gray
    $allGroupNames = $PolicyAssignments.Values | ForEach-Object { $_ } | Select-Object -Unique
    $missingGroups = @()

    foreach ($groupName in $allGroupNames) {
        $group = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue
        if (!$group) {
            $missingGroups += $groupName
        }
    }

    if ($missingGroups.Count -gt 0) {
        Write-Host "   Missing device groups:" -ForegroundColor Yellow
        foreach ($missing in $missingGroups) {
            Write-Host "     - $missing" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "   Run 'Device Groups' script first to create these groups" -ForegroundColor Yellow
        Write-Host "   Policies will be created but assignments will fail for missing groups" -ForegroundColor Yellow
        # Don't fail - just warn
    }
    else {
        Write-Host "   All required device groups found" -ForegroundColor Green
    }

    Write-Host ""
    return $allPassed
}

# ============================================================================
# DATA LOADING
# ============================================================================

function Get-TenantInfo {
    try {
        $org = Get-MgOrganization | Select-Object -First 1
        $domain = $org.VerifiedDomains | Where-Object { $_.IsDefault -eq $true } | Select-Object -ExpandProperty Name
        $tenantName = ($domain -split '\.')[0]

        return @{
            TenantId = $org.Id
            Domain = $domain
            TenantName = $tenantName
            OrganizationName = $org.DisplayName
        }
    }
    catch {
        Write-Host "   Failed to get tenant info: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Get-DeviceGroupId {
    param([string]$GroupName)

    try {
        $group = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue
        if ($group) {
            return $group.Id
        }
        return $null
    }
    catch {
        return $null
    }
}

function Get-PolicyDefinitions {
    <#
    .SYNOPSIS
        Load compliance policy definitions from GitHub or local fallback
    #>

    try {
        # Try GitHub download first
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $url = "https://raw.githubusercontent.com/$Global:GitHubRepo/$Global:GitHubBranch/Intune/CompliancePolicies_Complete.json"
            $jsonContent = Invoke-RestMethod -Uri $url -TimeoutSec 15 -ErrorAction Stop

            if ($jsonContent -is [string]) {
                $jsonContent = $jsonContent | ConvertFrom-Json -AsHashtable
            }
            elseif ($jsonContent -is [array] -or $jsonContent -is [PSCustomObject]) {
                $jsonContent = $jsonContent | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable
            }

            Write-Host "   Loaded $($jsonContent.Count) policies from GitHub" -ForegroundColor Green
            return $jsonContent
        }
        catch {
            Write-Host "   GitHub download failed, trying local files..." -ForegroundColor Yellow
        }

        # Try local file locations
        $possiblePaths = @(
            ".\CompliancePolicies_Complete.json",
            ".\Intune\CompliancePolicies_Complete.json",
            "$PSScriptRoot\CompliancePolicies_Complete.json"
        )

        foreach ($path in $possiblePaths) {
            if (Test-Path $path -ErrorAction SilentlyContinue) {
                $jsonContent = Get-Content $path -Raw | ConvertFrom-Json -AsHashtable
                Write-Host "   Loaded $($jsonContent.Count) policies from local file" -ForegroundColor Green
                return $jsonContent
            }
        }

        throw "Policy definitions not found"
    }
    catch {
        Write-Host "   Failed to load policy definitions: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# ============================================================================
# PREVIEW MODE
# ============================================================================

function Show-PolicyPreview {
    param(
        [array]$Policies,
        [hashtable]$GroupCache
    )

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  PREVIEW: Compliance Policies" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  The following $($Policies.Count) compliance policies will be created:" -ForegroundColor White
    Write-Host ""

    # Header
    Write-Host "  # | Policy Name                    | Platform   | Target Groups" -ForegroundColor Yellow
    Write-Host "  --|--------------------------------|------------|----------------------------" -ForegroundColor Gray

    $index = 1
    foreach ($policy in $Policies) {
        $platform = $policy.'@odata.type' -replace '#microsoft.graph.', '' -replace 'CompliancePolicy', ''
        $platform = $platform.Substring(0, [Math]::Min(10, $platform.Length))

        $targetGroups = if ($PolicyAssignments.ContainsKey($policy.displayName)) {
            $groupNames = $PolicyAssignments[$policy.displayName]
            $validGroups = $groupNames | Where-Object { $GroupCache[$_] }
            if ($validGroups.Count -gt 0) {
                ($validGroups | ForEach-Object { $_.Substring(0, [Math]::Min(12, $_.Length)) }) -join ", "
            }
            else { "(no valid groups)" }
        }
        else { "(none)" }

        $name = $policy.displayName
        if ($name.Length -gt 30) { $name = $name.Substring(0, 27) + "..." }

        Write-Host ("  {0,2} | {1,-30} | {2,-10} | {3}" -f $index, $name, $platform, $targetGroups) -ForegroundColor White
        $index++
    }

    Write-Host ""

    # Show group status
    Write-Host "  Device Group Status:" -ForegroundColor Yellow
    foreach ($groupName in ($GroupCache.Keys | Sort-Object)) {
        $status = if ($GroupCache[$groupName]) { "Found" } else { "Missing" }
        $color = if ($GroupCache[$groupName]) { "Green" } else { "Yellow" }
        Write-Host "    $groupName : $status" -ForegroundColor $color
    }

    Write-Host ""
}

# ============================================================================
# POLICY CREATION
# ============================================================================

function New-CompliancePolicy {
    param(
        [hashtable]$PolicyDefinition,
        [string[]]$DeviceGroupIds = @()
    )

    $policyName = $PolicyDefinition.displayName

    try {
        # Check if policy already exists
        $existingPolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies" -Method GET
        $existingPolicy = $existingPolicies.value | Where-Object { $_.displayName -eq $policyName }

        if ($existingPolicy) {
            Write-Host "     Already exists (skipped)" -ForegroundColor Yellow
            return @{ Success = $true; Policy = $existingPolicy; Skipped = $true }
        }

        # Clean policy definition
        $cleanPolicy = $PolicyDefinition.Clone()
        $fieldsToRemove = @('id', 'createdDateTime', 'lastModifiedDateTime', 'version', '@odata.context')
        foreach ($field in $fieldsToRemove) {
            if ($cleanPolicy.ContainsKey($field)) {
                $cleanPolicy.Remove($field)
            }
        }

        # Create policy
        $newPolicy = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies" -Method POST -Body ($cleanPolicy | ConvertTo-Json -Depth 20)

        Write-Host "     Created successfully (ID: $($newPolicy.id))" -ForegroundColor Green

        # Assign to device groups using Invoke-MgGraphRequest (reliable method)
        if ($DeviceGroupIds.Count -gt 0) {
            $assignmentBody = @{
                assignments = @()
            }

            foreach ($groupId in $DeviceGroupIds) {
                if ($groupId) {
                    $assignmentBody.assignments += @{
                        target = @{
                            "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                            groupId = $groupId
                        }
                    }
                }
            }

            if ($assignmentBody.assignments.Count -gt 0) {
                try {
                    # Use Invoke-MgGraphRequest instead of broken REST method
                    $assignmentUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$($newPolicy.id)')/assign"
                    Invoke-MgGraphRequest -Uri $assignmentUri -Method POST -Body $assignmentBody | Out-Null

                    Write-Host "     Assigned to $($assignmentBody.assignments.Count) group(s)" -ForegroundColor Green
                }
                catch {
                    Write-Host "     Assignment failed: $($_.Exception.Message)" -ForegroundColor Yellow

                    # Try individual assignments as fallback
                    $assignedCount = 0
                    foreach ($assignment in $assignmentBody.assignments) {
                        try {
                            $singleAssignment = @{ assignments = @($assignment) }
                            Invoke-MgGraphRequest -Uri $assignmentUri -Method POST -Body $singleAssignment -ErrorAction Stop
                            $assignedCount++
                        }
                        catch {
                            # Silent fail for individual
                        }
                    }

                    if ($assignedCount -gt 0) {
                        Write-Host "     Assigned to $assignedCount group(s) via fallback" -ForegroundColor Yellow
                    }
                }
            }
        }

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

function Start-CompliancePolicyCreation {
    # Header
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  INTUNE COMPLIANCE POLICIES" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Creates platform-specific compliance policies for device management" -ForegroundColor Gray
    Write-Host ""

    # Step 1: Prerequisites
    Write-Host "  STEP 1: Prerequisites" -ForegroundColor Yellow
    if (!(Test-Prerequisites)) {
        Write-Host ""
        Write-Host "  Prerequisites not met. Please resolve issues and try again." -ForegroundColor Red
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    # Step 2: Load data
    Write-Host "  STEP 2: Loading Data" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 40) -ForegroundColor Gray

    $tenantInfo = Get-TenantInfo
    if (!$tenantInfo) {
        Write-Host "   Failed to get tenant information" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }
    Write-Host "   Tenant: $($tenantInfo.OrganizationName)" -ForegroundColor Green

    Write-Host "   Loading policy definitions..." -ForegroundColor Gray
    $policies = Get-PolicyDefinitions
    if ($policies.Count -eq 0) {
        Write-Host "   No policies found to deploy" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    # Build group cache
    Write-Host "   Resolving device groups..." -ForegroundColor Gray
    $groupCache = @{}
    $allGroupNames = $PolicyAssignments.Values | ForEach-Object { $_ } | Select-Object -Unique

    foreach ($groupName in $allGroupNames) {
        $groupId = Get-DeviceGroupId -GroupName $groupName
        $groupCache[$groupName] = $groupId
    }

    # Step 3: Preview
    Write-Host ""
    Write-Host "  STEP 3: Preview" -ForegroundColor Yellow
    Show-PolicyPreview -Policies $policies -GroupCache $groupCache

    # Confirmation
    Write-Host "  [Y] Proceed with creation  [N] Cancel" -ForegroundColor Gray
    Write-Host ""
    $confirm = Read-Host "  Create these compliance policies? (Y/N)"

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
    Write-Host ("   " + "-" * 40) -ForegroundColor Gray

    $results = @{
        Created = @()
        Skipped = @()
        Failed = @()
    }

    foreach ($policy in $policies) {
        Write-Host "   $($policy.displayName)..." -ForegroundColor White

        # Get group IDs for this policy
        $deviceGroupIds = @()
        if ($PolicyAssignments.ContainsKey($policy.displayName)) {
            foreach ($groupName in $PolicyAssignments[$policy.displayName]) {
                $groupId = $groupCache[$groupName]
                if ($groupId) {
                    $deviceGroupIds += $groupId
                }
            }
        }

        $result = New-CompliancePolicy -PolicyDefinition $policy -DeviceGroupIds $deviceGroupIds

        if ($result.Success) {
            if ($result.Skipped) {
                $results.Skipped += $policy.displayName
            }
            else {
                $results.Created += $policy.displayName
            }
        }
        else {
            $results.Failed += @{ Name = $policy.displayName; Error = $result.Error }
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

    Write-Host "  Next Steps:" -ForegroundColor Yellow
    Write-Host "    1. Verify policies in Intune admin center" -ForegroundColor Gray
    Write-Host "    2. Check policy assignments to device groups" -ForegroundColor Gray
    Write-Host "    3. Monitor device compliance reporting" -ForegroundColor Gray
    Write-Host "    4. Test compliance evaluation on pilot devices" -ForegroundColor Gray
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

    Start-CompliancePolicyCreation
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
}
