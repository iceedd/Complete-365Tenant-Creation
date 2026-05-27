#Requires -Version 7.0

<#
.SYNOPSIS
    Creates comprehensive Intune configuration policies
.DESCRIPTION
    Creates 18 production-ready configuration policies using exported settings data.
    Includes preview mode and automatic group assignment.
.AUTHOR
    BITS
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
    "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementManagedDevices.ReadWrite.All",
    "Group.Read.All",
    "Directory.Read.All"
)

# Policy assignment configuration
$PolicyAssignments = @{
    "Default Web Pages" = @("Windows Devices (Autopilot)")
    "Defender Configuration" = @("Windows Devices (Autopilot)")
    "Disable UAC for Quickassist" = @("Windows Devices (Autopilot)")
    "Edge Update Policy" = @("Windows Devices (Autopilot)")
    "EDR Policy" = @("Windows Devices (Autopilot)")
    "Enable Bitlocker" = @("Windows Devices (Autopilot)")
    "Enable Built-in Administrator Account" = @("Windows Devices (Autopilot)")
    "LAPS" = @("Windows Devices (Autopilot)")
    "Office Updates Configuration" = @("Windows Devices (Autopilot)")
    "OneDrive Configuration" = @("Windows Devices (Autopilot)")
    "Outlook Configuration" = @("Windows Devices (Autopilot)")
    "Power Options" = @("Windows Devices (Autopilot)")
    "Prevent Users From Unenrolling Devices" = @("Windows Devices (Autopilot)", "Corporate Owned Devices")
    "Sharepoint File Sync" = @("Windows Devices (Autopilot)")
    "System Services" = @("Windows Devices (Autopilot)")
    "Tamper Protection" = @("Windows Devices (Autopilot)")
    "Web Sign-in Policy" = @("Windows Devices (Autopilot)")
    "NGP Windows Default Policy" = @("Windows Devices (Autopilot)", "Corporate Owned Devices")
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

function Get-TenantInfo {
    try {
        $org = Get-MgOrganization | Select-Object -First 1
        $domain = $org.VerifiedDomains | Where-Object { $_.IsDefault -eq $true } | Select-Object -ExpandProperty Name
        $tenantName = ($domain -split '\.')[0]

        return @{
            TenantId = $org.Id
            Domain = $domain
            TenantName = $tenantName
            SharePointUrl = "https://$tenantName.sharepoint.com/"
            OrganizationName = $org.DisplayName
        }
    }
    catch {
        return $null
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

    # Get tenant info
    Write-Host "   Getting tenant information..." -ForegroundColor Gray
    $tenantInfo = Get-TenantInfo
    if (!$tenantInfo) {
        Write-Host "   Failed to get tenant information" -ForegroundColor Red
        return @{ Success = $false }
    }
    Write-Host "   Tenant: $($tenantInfo.OrganizationName)" -ForegroundColor Green
    Write-Host "   SharePoint: $($tenantInfo.SharePointUrl)" -ForegroundColor Green

    # Load policy definitions
    Write-Host "   Loading policy definitions..." -ForegroundColor Gray
    $policies = Get-PolicyDefinitions
    if ($policies.Count -eq 0) {
        Write-Host "   No policy definitions found" -ForegroundColor Red
        return @{ Success = $false }
    }
    Write-Host "   Loaded $($policies.Count) policy definitions" -ForegroundColor Green

    # Check device groups
    Write-Host "   Checking device groups..." -ForegroundColor Gray
    $groupCache = @{}
    $missingGroups = @()

    $uniqueGroups = $PolicyAssignments.Values | ForEach-Object { $_ } | Select-Object -Unique
    foreach ($groupName in $uniqueGroups) {
        $group = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue
        if ($group) {
            $groupCache[$groupName] = $group.Id
        }
        else {
            $missingGroups += $groupName
        }
    }

    if ($missingGroups.Count -gt 0) {
        Write-Host "   Missing groups: $($missingGroups -join ', ')" -ForegroundColor Yellow
        Write-Host "   Run Device Groups script first" -ForegroundColor Yellow
    }
    else {
        Write-Host "   All device groups found" -ForegroundColor Green
    }

    Write-Host ""
    return @{
        Success = $true
        TenantInfo = $tenantInfo
        Policies = $policies
        GroupCache = $groupCache
        MissingGroups = $missingGroups
    }
}

function Get-PolicyDefinitions {
    try {
        # Try GitHub download first
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $url = "https://raw.githubusercontent.com/$Global:GitHubRepo/$Global:GitHubBranch/Intune/AllPolicies_Complete.json"
            $jsonContent = Invoke-RestMethod -Uri $url -ErrorAction Stop

            if ($jsonContent -is [string]) {
                $jsonContent = $jsonContent | ConvertFrom-Json -AsHashtable
            }
            elseif ($jsonContent -is [array] -or $jsonContent -is [PSCustomObject]) {
                $jsonContent = $jsonContent | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable
            }

            return $jsonContent
        }
        catch {
            # Try local file
        }

        # Try local file locations
        $possiblePaths = @(
            ".\AllPolicies_Complete.json",
            ".\Intune\AllPolicies_Complete.json",
            "$PWD\AllPolicies_Complete.json"
        )

        foreach ($path in $possiblePaths) {
            if ($path -and (Test-Path $path -ErrorAction SilentlyContinue)) {
                $jsonContent = Get-Content $path -Raw | ConvertFrom-Json -AsHashtable
                return $jsonContent
            }
        }

        return @()
    }
    catch {
        return @()
    }
}

# ============================================================================
# PREVIEW MODE
# ============================================================================

function Show-PolicyPreview {
    param(
        [array]$Policies,
        [hashtable]$TenantInfo
    )

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  PREVIEW: Configuration Policies" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Tenant: $($TenantInfo.OrganizationName)" -ForegroundColor White
    Write-Host "  SharePoint URL: $($TenantInfo.SharePointUrl)" -ForegroundColor White
    Write-Host ""
    Write-Host "  The following $($Policies.Count) configuration policies will be created:" -ForegroundColor White
    Write-Host ""

    # Header
    Write-Host "  # | Policy Name                              | Settings | Assignments" -ForegroundColor Yellow
    Write-Host "  --|------------------------------------------|----------|------------" -ForegroundColor Gray

    $index = 1
    foreach ($policy in $Policies) {
        $name = $policy.name
        if ($name.Length -gt 40) { $name = $name.Substring(0, 37) + "..." }

        $settingsCount = if ($policy.settings) { $policy.settings.Count } else { 0 }
        $assignmentCount = if ($PolicyAssignments.ContainsKey($policy.name)) { $PolicyAssignments[$policy.name].Count } else { 0 }

        Write-Host ("  {0,2} | {1,-40} | {2,8} | {3}" -f $index, $name, $settingsCount, $assignmentCount) -ForegroundColor White
        $index++
    }

    Write-Host ""
    Write-Host "  Key Configurations:" -ForegroundColor Yellow
    Write-Host "    - BitLocker encryption with LAPS" -ForegroundColor Gray
    Write-Host "    - OneDrive Known Folder Move" -ForegroundColor Gray
    Write-Host "    - Edge browser policies" -ForegroundColor Gray
    Write-Host "    - Defender and EDR configurations" -ForegroundColor Gray
    Write-Host "    - Power management settings" -ForegroundColor Gray
    Write-Host ""
}

# ============================================================================
# POLICY CREATION
# ============================================================================

function Update-PolicyDynamicValues {
    param(
        [hashtable]$Policy,
        [hashtable]$TenantInfo,
        [string]$LapsAdminName
    )

    $policyJson = $Policy | ConvertTo-Json -Depth 20
    $policyJson = $policyJson -replace "https://contoso\.sharepoint\.com/", $TenantInfo.SharePointUrl
    # Replace LAPS admin name in both policies (Enable Built-in Admin + LAPS)
    $policyJson = $policyJson -replace '"BLadmin"', "`"$LapsAdminName`""
    $policyJson = $policyJson -replace 'tenantId=', "tenantId=$($TenantInfo.TenantId)"

    return $policyJson | ConvertFrom-Json -AsHashtable
}

function New-ConfigurationPolicyItem {
    param(
        [hashtable]$PolicyDefinition,
        [hashtable]$TenantInfo,
        [string]$LapsAdminName,
        [hashtable]$GroupCache
    )

    $policyName = $PolicyDefinition.name

    try {
        # Check if policy exists
        $existingPolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -Method GET
        $existingPolicy = $existingPolicies.value | Where-Object { $_.name -eq $policyName }

        if ($existingPolicy) {
            Write-Host "     Already exists (skipped)" -ForegroundColor Yellow
            return @{ Success = $true; Skipped = $true; Policy = $existingPolicy }
        }

        # Update dynamic values
        $updatedPolicy = Update-PolicyDynamicValues -Policy $PolicyDefinition -TenantInfo $TenantInfo -LapsAdminName $LapsAdminName

        # Create policy
        $newPolicy = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -Method POST -Body ($updatedPolicy | ConvertTo-Json -Depth 20)

        # Assign to groups
        if ($PolicyAssignments.ContainsKey($policyName)) {
            $deviceGroupIds = @()
            foreach ($groupName in $PolicyAssignments[$policyName]) {
                if ($GroupCache.ContainsKey($groupName) -and $GroupCache[$groupName]) {
                    $deviceGroupIds += $GroupCache[$groupName]
                }
            }

            if ($deviceGroupIds.Count -gt 0) {
                $assignmentBody = @{
                    assignments = @()
                }

                foreach ($groupId in $deviceGroupIds) {
                    $assignmentBody.assignments += @{
                        target = @{
                            "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                            groupId = $groupId
                        }
                    }
                }

                $null = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($newPolicy.id)')/assign" -Method POST -Body ($assignmentBody | ConvertTo-Json -Depth 10)
            }
        }

        Write-Host "     Created (ID: $($newPolicy.id))" -ForegroundColor Green
        return @{ Success = $true; Skipped = $false; Policy = $newPolicy }
    }
    catch {
        $errorMessage = $_.Exception.Message
        # Try to get more details from the response
        if ($_.ErrorDetails.Message) {
            try {
                $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json
                if ($errorDetails.error.message) {
                    $errorMessage = "$errorMessage - $($errorDetails.error.message)"
                }
            } catch { }
        }
        Write-Host "     Failed: $errorMessage" -ForegroundColor Red
        return @{ Success = $false; Error = $errorMessage }
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-ConfigurationPolicyCreation {
    # Header
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  CONFIGURATION POLICIES" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Creates Intune device configuration policies" -ForegroundColor Gray
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

    # Step 2: Get LAPS admin name
    Write-Host ""
    Write-Host "  STEP 2: Configuration" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray
    Write-Host "   Enter the local admin account name for LAPS" -ForegroundColor Gray
    Write-Host "   (This will be the local admin on all Windows devices)" -ForegroundColor Gray
    Write-Host ""
    $lapsAdminName = Read-Host "   LAPS admin name (default: Localadmin)"
    if ([string]::IsNullOrWhiteSpace($lapsAdminName)) {
        $lapsAdminName = "Localadmin"
    }
    Write-Host "   Using LAPS admin: $lapsAdminName" -ForegroundColor Green

    # Step 3: Preview
    Write-Host ""
    Write-Host "  STEP 3: Preview" -ForegroundColor Yellow
    Show-PolicyPreview -Policies $prereqResult.Policies -TenantInfo $prereqResult.TenantInfo

    # Confirmation
    Write-Host "  [Y] Proceed with creation  [N] Cancel" -ForegroundColor Gray
    Write-Host ""
    $confirm = Read-Host "  Create these configuration policies? (Y/N)"

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

    foreach ($policy in $prereqResult.Policies) {
        Write-Host "   $($policy.name)..." -ForegroundColor White

        $result = New-ConfigurationPolicyItem -PolicyDefinition $policy -TenantInfo $prereqResult.TenantInfo -LapsAdminName $lapsAdminName -GroupCache $prereqResult.GroupCache

        if ($result.Success) {
            if ($result.Skipped) {
                $results.Skipped += $policy.name
            }
            else {
                $results.Created += $policy.name
            }
        }
        else {
            $results.Failed += @{ Name = $policy.name; Error = $result.Error }
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

    if ($results.Failed.Count -gt 0) {
        Write-Host "  Failed Policies:" -ForegroundColor Red
        foreach ($fail in $results.Failed) {
            Write-Host "    - $($fail.Name): $($fail.Error)" -ForegroundColor Red
        }
        Write-Host ""

        # Check for EDR policy failure
        if ($results.Failed.Name -contains "EDR Policy") {
            Write-Host "  EDR POLICY MANUAL SETUP REQUIRED:" -ForegroundColor Yellow
            Write-Host "    1. Go to Intune Admin Center" -ForegroundColor Gray
            Write-Host "    2. Endpoint Security > Microsoft Defender for Endpoint" -ForegroundColor Gray
            Write-Host "    3. Connect Defender to Intune" -ForegroundColor Gray
            Write-Host "    4. Re-run this script after setup" -ForegroundColor Gray
            Write-Host ""
        }
    }

    Write-Host "  IMPORTANT:" -ForegroundColor Yellow
    Write-Host "    - Policies are assigned to device groups automatically" -ForegroundColor Gray
    Write-Host "    - Allow time for policies to sync to devices" -ForegroundColor Gray
    Write-Host "    - LAPS admin name: $lapsAdminName" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  Next Steps:" -ForegroundColor Yellow
    Write-Host "    1. Verify policies in Intune admin center" -ForegroundColor Gray
    Write-Host "    2. Monitor policy deployment status" -ForegroundColor Gray
    Write-Host "    3. Test on pilot devices first" -ForegroundColor Gray
    Write-Host "    4. Run Compliance Policies script" -ForegroundColor Gray
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

    Start-ConfigurationPolicyCreation
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
}
