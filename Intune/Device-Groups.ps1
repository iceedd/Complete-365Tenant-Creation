#Requires -Version 7.0

<#
.SYNOPSIS
    Creates dynamic device groups for Intune management
.DESCRIPTION
    Creates OS-specific dynamic security groups for device management and policy assignment.
    Includes preview mode and confirmation before creation.
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
    'Microsoft.Graph.Groups'
)

$RequiredScopes = @(
    "Group.ReadWrite.All",
    "Directory.Read.All"
)

# Device group definitions
$DeviceGroups = @(
    @{
        Name = "Windows Devices (Autopilot)"
        Description = "All Windows (Autopilot) devices managed by Intune"
        MembershipRule = '(device.devicePhysicalIds -any _ -eq "[OrderID]:WIN-AP-Corp")'
        Platform = "Windows"
    },
    @{
        Name = "macOS Devices"
        Description = "All macOS devices managed by Intune"
        MembershipRule = '(device.deviceOSType -eq "macOS")'
        Platform = "macOS"
    },
    @{
        Name = "iOS Devices"
        Description = "All iOS devices managed by Intune"
        MembershipRule = '(device.deviceOSType -eq "iOS")'
        Platform = "iOS"
    },
    @{
        Name = "Android Devices"
        Description = "All Android devices managed by Intune"
        MembershipRule = '(device.deviceOSType -eq "Android")'
        Platform = "Android"
    },
    @{
        Name = "Corporate Owned Devices"
        Description = "All corporate owned devices"
        MembershipRule = '(device.deviceOwnership -eq "Company")'
        Platform = "All"
    },
    @{
        Name = "Personal Devices"
        Description = "All personal owned devices"
        MembershipRule = '(device.deviceOwnership -eq "Personal")'
        Platform = "All"
    },
    @{
        Name = "Pilot Device Group"
        Description = "Autopatch Test ring - IT/admin devices for initial update testing"
        MembershipRule = '(device.displayName -startsWith "PILOT-")'
        Platform = "All"
        AutopatchRing = "Test"
    },
    @{
        Name = "UAT Device Group"
        Description = "Autopatch Ring1 - Early adopter devices for UAT before broad rollout"
        MembershipRule = '(device.displayName -startsWith "UAT-")'
        Platform = "All"
        AutopatchRing = "Ring1"
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
    foreach ($group in $DeviceGroups) {
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

function Show-DeviceGroupPreview {
    param(
        [array]$Groups,
        [array]$ExistingGroups
    )

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  PREVIEW: Device Groups" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  The following $($Groups.Count) device groups will be created:" -ForegroundColor White
    Write-Host ""

    # Header
    Write-Host "  # | Name                           | Platform | Status" -ForegroundColor Yellow
    Write-Host "  --|--------------------------------|----------|--------" -ForegroundColor Gray

    $index = 1
    foreach ($group in $Groups) {
        $name = $group.Name
        if ($name.Length -gt 30) { $name = $name.Substring(0, 27) + "..." }

        $status = if ($ExistingGroups -contains $group.Name) { "EXISTS" } else { "NEW" }
        $statusColor = if ($status -eq "EXISTS") { "Yellow" } else { "Green" }

        Write-Host -NoNewline ("  {0,2} | {1,-30} | {2,-8} | " -f $index, $name, $group.Platform)
        Write-Host $status -ForegroundColor $statusColor
        $index++
    }

    Write-Host ""
    Write-Host "  All groups are Dynamic (membership rule-based)" -ForegroundColor Gray
    Write-Host ""

    $newCount = $Groups.Count - $ExistingGroups.Count
    Write-Host "  Summary: $newCount new groups will be created, $($ExistingGroups.Count) existing will be skipped" -ForegroundColor White
    Write-Host ""
}

# ============================================================================
# GROUP CREATION
# ============================================================================

function New-DeviceGroupItem {
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

        # Create group parameters
        $groupParams = @{
            DisplayName = $groupName
            Description = $GroupConfig.Description
            GroupTypes = @("DynamicMembership")
            SecurityEnabled = $true
            MailEnabled = $false
            MailNickname = $mailNickname
            MembershipRule = $GroupConfig.MembershipRule
            MembershipRuleProcessingState = "On"
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

function Start-DeviceGroupCreation {
    # Header
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  DEVICE GROUPS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Creates dynamic device groups for Intune policy assignment" -ForegroundColor Gray
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
    Show-DeviceGroupPreview -Groups $DeviceGroups -ExistingGroups $prereqResult.ExistingGroups

    # Confirmation
    Write-Host "  [Y] Proceed with creation  [N] Cancel" -ForegroundColor Gray
    Write-Host ""
    $confirm = Read-Host "  Create these device groups? (Y/N)"

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

    foreach ($group in $DeviceGroups) {
        Write-Host "   $($group.Name)..." -ForegroundColor White

        $result = New-DeviceGroupItem -GroupConfig $group

        if ($result.Success) {
            if ($result.Skipped) {
                $results.Skipped += @{ Name = $group.Name; Id = $result.Group.Id }
            }
            else {
                $results.Created += @{ Name = $group.Name; Id = $result.Group.Id }
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
    Write-Host "    - Devices must be enrolled in Intune to appear in groups" -ForegroundColor Gray
    Write-Host "    - Autopilot devices need matching OrderID tag (WIN-AP-Corp)" -ForegroundColor Gray
    Write-Host "    - Pilot devices: rename to start with 'PILOT-'" -ForegroundColor Gray
    Write-Host "    - UAT devices: rename to start with 'UAT-'" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  Windows Autopatch Deployment Rings:" -ForegroundColor Yellow
    Write-Host "    Test  -> Pilot Device Group (IT/admin devices)" -ForegroundColor Gray
    Write-Host "    Ring1 -> UAT Device Group (early adopters)" -ForegroundColor Gray
    Write-Host "    Last  -> Windows Devices (Autopilot) (all production)" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  Next Steps:" -ForegroundColor Yellow
    Write-Host "    1. Wait for group membership to populate" -ForegroundColor Gray
    Write-Host "    2. Configure Autopatch groups in Intune (Tenant admin > Autopatch)" -ForegroundColor Gray
    Write-Host "    3. Run Compliance Policies script" -ForegroundColor Gray
    Write-Host "    4. Run Configuration Policies script" -ForegroundColor Gray
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

    Start-DeviceGroupCreation
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
}
