#Requires -Version 7.0

<#
.SYNOPSIS
    Configures Microsoft Defender web content filtering policies
.DESCRIPTION
    Creates web content filtering policies via Intune Settings Catalog.
    Requires Microsoft Defender for Endpoint Plan 2 licensing.
.AUTHOR
    BITS
.VERSION
    2.0 - Standardized UX with preview mode and license checks
#>

# ============================================================================
# CONFIGURATION
# ============================================================================

$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.DeviceManagement',
    'Microsoft.Graph.Identity.DirectoryManagement'
)

$RequiredScopes = @(
    "DeviceManagementConfiguration.ReadWrite.All",
    "Directory.Read.All"
)

# Web content categories to block (based on best practices)
$BlockedCategories = @(
    @{ Name = "Cults"; Id = "cults"; Description = "Cult-related content" }
    @{ Name = "Gambling"; Id = "gambling"; Description = "Gambling websites" }
    @{ Name = "Nudity"; Id = "nudity"; Description = "Non-pornographic nudity" }
    @{ Name = "Pornography"; Id = "pornography"; Description = "Adult/explicit content" }
    @{ Name = "Sex Education"; Id = "sexeducation"; Description = "Sexual education content" }
    @{ Name = "Tasteless"; Id = "tasteless"; Description = "Offensive/tasteless content" }
    @{ Name = "Violence"; Id = "violence"; Description = "Violent content" }
    @{ Name = "Peer-to-Peer"; Id = "peertopeer"; Description = "P2P file sharing sites" }
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

    # Check for Defender for Endpoint licensing
    Write-Host "   Checking Defender for Endpoint license..." -ForegroundColor Gray
    $licenseResult = Test-DefenderLicense

    if (!$licenseResult.HasLicense) {
        Write-Host "   WARNING: Defender for Endpoint P2 license not detected" -ForegroundColor Yellow
        Write-Host "   Web content filtering requires this license to function" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "   [Y] Continue anyway (create policy)  [N] Cancel" -ForegroundColor Gray
        $confirm = Read-Host "   Continue? (Y/N)"

        if ($confirm -notlike "Y*") {
            return @{ Success = $false }
        }
    }
    else {
        Write-Host "   Defender license detected" -ForegroundColor Green
    }

    # Check for existing policy
    Write-Host "   Checking for existing web filter policy..." -ForegroundColor Gray
    $existingPolicy = Get-ExistingWebFilterPolicy

    Write-Host ""
    return @{
        Success = $true
        ExistingPolicy = $existingPolicy
        HasDefenderLicense = $licenseResult.HasLicense
    }
}

function Test-DefenderLicense {
    try {
        # Check for Defender for Endpoint related SKUs
        $subscribedSkus = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/subscribedSkus" -ErrorAction SilentlyContinue

        $defenderSkus = @(
            "DEFENDER_ENDPOINT_P2",
            "WIN_DEF_ATP",
            "MICROSOFT_DEFENDER_ATP",
            "M365_E5",
            "SPE_E5",
            "MICROSOFT_365_E5"
        )

        foreach ($sku in $subscribedSkus.value) {
            foreach ($plan in $sku.servicePlans) {
                if ($defenderSkus -contains $plan.servicePlanName) {
                    return @{ HasLicense = $true; SkuName = $sku.skuPartNumber }
                }
            }
        }

        return @{ HasLicense = $false }
    }
    catch {
        # If we can't check, assume they might have it
        Write-Host "   Could not verify license (proceeding)" -ForegroundColor Yellow
        return @{ HasLicense = $true; Unknown = $true }
    }
}

function Get-ExistingWebFilterPolicy {
    try {
        $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$filter=name eq 'Default Web Filter'"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue

        if ($response.value -and $response.value.Count -gt 0) {
            Write-Host "   Found existing 'Default Web Filter' policy" -ForegroundColor Yellow
            return $response.value[0]
        }

        return $null
    }
    catch {
        return $null
    }
}

# ============================================================================
# PREVIEW MODE
# ============================================================================

function Show-WebFilterPreview {
    param([array]$Categories)

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  PREVIEW: Web Content Filtering Policy" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Policy Name: Default Web Filter" -ForegroundColor White
    Write-Host "  Platform:    Windows 10/11" -ForegroundColor White
    Write-Host "  Technology:  Microsoft Defender for Endpoint" -ForegroundColor White
    Write-Host "  Scope:       All Devices (via Intune)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Categories to Block:" -ForegroundColor Yellow
    Write-Host "  ----------------------------------------" -ForegroundColor Gray

    $index = 1
    foreach ($category in $Categories) {
        Write-Host ("  {0,2}. {1,-20} - {2}" -f $index, $category.Name, $category.Description) -ForegroundColor White
        $index++
    }

    Write-Host ""
    Write-Host "  Requirements:" -ForegroundColor Yellow
    Write-Host "    - Microsoft Defender for Endpoint Plan 2 license" -ForegroundColor Gray
    Write-Host "    - Devices must be onboarded to Defender for Endpoint" -ForegroundColor Gray
    Write-Host "    - Intune enrollment required for policy delivery" -ForegroundColor Gray
    Write-Host ""
}

# ============================================================================
# POLICY CREATION
# ============================================================================

function Test-SettingDefinitionsExist {
    param([array]$Categories)

    $missing = @()
    foreach ($category in $Categories) {
        $defId = "device_vendor_msft_defender_configuration_webcontentfiltering_blockcategories_$($category.Id)"
        try {
            $uri      = "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?`$filter=id eq '$defId'&`$select=id"
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            if (-not $response.value -or $response.value.Count -eq 0) {
                $missing += $category.Name
            }
        }
        catch {
            Write-Host "     Could not validate setting ID for '$($category.Name)' (proceeding)" -ForegroundColor Gray
        }
    }

    if ($missing.Count -gt 0) {
        Write-Host "     WARNING: Setting IDs not found in tenant for: $($missing -join ', ')" -ForegroundColor Yellow
        Write-Host "     Microsoft may have changed these IDs. Use manual setup if the policy fails." -ForegroundColor Yellow
        return $false
    }

    return $true
}

function New-WebFilterPolicy {
    param([array]$Categories)

    $policyName = "Default Web Filter"

    try {
        # Check if policy exists
        $existing = Get-ExistingWebFilterPolicy
        if ($existing) {
            Write-Host "     Policy already exists (skipped)" -ForegroundColor Yellow
            return @{ Success = $true; Skipped = $true; Policy = $existing }
        }

        Write-Host "     Validating setting definition IDs..." -ForegroundColor Gray
        Test-SettingDefinitionsExist -Categories $Categories | Out-Null

        Write-Host "     Creating Settings Catalog policy..." -ForegroundColor Gray

        # Build the settings array for each category
        $categorySettings = @()
        foreach ($category in $Categories) {
            $categorySettings += @{
                "@odata.type" = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                settingDefinitionId = "device_vendor_msft_defender_configuration_webcontentfiltering_blockcategories_$($category.Id)"
                choiceSettingValue = @{
                    value = "device_vendor_msft_defender_configuration_webcontentfiltering_blockcategories_$($category.Id)_1"
                }
            }
        }

        $policyBody = @{
            name = $policyName
            description = "Blocks inappropriate web content categories for all devices"
            platforms = "windows10"
            technologies = "mdm,microsoftSense"
            settings = @(
                @{
                    "@odata.type" = "#microsoft.graph.deviceManagementConfigurationSetting"
                    settingInstance = @{
                        "@odata.type" = "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance"
                        settingDefinitionId = "device_vendor_msft_defender_configuration_webcontentfiltering_blockcategories"
                        groupSettingCollectionValue = @(
                            @{
                                children = $categorySettings
                            }
                        )
                    }
                }
            )
        }

        $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
        $policy = Invoke-MgGraphRequest -Method POST -Uri $uri -Body ($policyBody | ConvertTo-Json -Depth 15) -ErrorAction Stop

        Write-Host "     Created successfully (ID: $($policy.id))" -ForegroundColor Green
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

function Start-WebFiltering {
    # Header
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  WEB CONTENT FILTERING" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Blocks inappropriate web content via Defender for Endpoint" -ForegroundColor Gray
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

    # Check if policy already exists
    if ($prereqResult.ExistingPolicy) {
        Write-Host ""
        Write-Host "  Web filter policy 'Default Web Filter' already exists." -ForegroundColor Yellow
        Write-Host "  Policy ID: $($prereqResult.ExistingPolicy.id)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  No action needed." -ForegroundColor Green
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    # Step 2: Preview
    Write-Host ""
    Write-Host "  STEP 2: Preview" -ForegroundColor Yellow
    Show-WebFilterPreview -Categories $BlockedCategories

    # Confirmation
    Write-Host "  [Y] Proceed with creation  [N] Cancel  [M] Manual setup instructions" -ForegroundColor Gray
    Write-Host ""
    $confirm = Read-Host "  Create this policy? (Y/N/M)"

    if ($confirm -like "M*") {
        Show-ManualInstructions
        return
    }

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
    Write-Host "  STEP 3: Creating Policy" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    Write-Host "   Default Web Filter..." -ForegroundColor White
    $result = New-WebFilterPolicy -Categories $BlockedCategories

    # Step 4: Summary
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""

    if ($result.Success) {
        if ($result.Skipped) {
            Write-Host "  Status: Skipped (policy already exists)" -ForegroundColor Yellow
        }
        else {
            Write-Host "  Status: Created successfully" -ForegroundColor Green
            Write-Host "  Policy ID: $($result.Policy.id)" -ForegroundColor Gray
        }
        Write-Host ""
        Write-Host "  Blocked Categories: $($BlockedCategories.Count)" -ForegroundColor White
        Write-Host ""

        Write-Host "  IMPORTANT - Next Steps:" -ForegroundColor Yellow
        Write-Host "    1. Assign the policy to device groups in Intune" -ForegroundColor Gray
        Write-Host "    2. Ensure devices are onboarded to Defender for Endpoint" -ForegroundColor Gray
        Write-Host "    3. Allow up to 24 hours for policy to apply" -ForegroundColor Gray
        Write-Host "    4. Test on a pilot device before broad rollout" -ForegroundColor Gray
        Write-Host ""

        Write-Host "  To assign the policy:" -ForegroundColor Yellow
        Write-Host "    1. Go to Intune admin center (intune.microsoft.com)" -ForegroundColor Gray
        Write-Host "    2. Devices > Configuration > Policies" -ForegroundColor Gray
        Write-Host "    3. Find 'Default Web Filter' and click Assignments" -ForegroundColor Gray
        Write-Host "    4. Add device groups (e.g., 'All Devices')" -ForegroundColor Gray
    }
    else {
        Write-Host "  Status: Failed" -ForegroundColor Red
        Write-Host "  Error: $($result.Error)" -ForegroundColor Red
        Write-Host ""
        Show-ManualInstructions
    }

    Write-Host ""
    Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
    try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
}

function Show-ManualInstructions {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Yellow
    Write-Host "  MANUAL SETUP INSTRUCTIONS" -ForegroundColor Yellow
    Write-Host ("=" * 70) -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  If the API method fails, create the policy manually:" -ForegroundColor White
    Write-Host ""
    Write-Host "  Option 1: Microsoft 365 Defender Portal" -ForegroundColor Cyan
    Write-Host "  ----------------------------------------" -ForegroundColor Gray
    Write-Host "    1. Go to https://security.microsoft.com" -ForegroundColor Gray
    Write-Host "    2. Settings > Endpoints > Web content filtering" -ForegroundColor Gray
    Write-Host "    3. Click 'Add policy'" -ForegroundColor Gray
    Write-Host "    4. Name: Default Web Filter" -ForegroundColor Gray
    Write-Host "    5. Select categories to block:" -ForegroundColor Gray
    foreach ($cat in $BlockedCategories) {
        Write-Host "       - $($cat.Name)" -ForegroundColor Gray
    }
    Write-Host "    6. Apply to 'All machines' or specific groups" -ForegroundColor Gray
    Write-Host "    7. Save the policy" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Option 2: Intune Settings Catalog" -ForegroundColor Cyan
    Write-Host "  ----------------------------------------" -ForegroundColor Gray
    Write-Host "    1. Go to https://intune.microsoft.com" -ForegroundColor Gray
    Write-Host "    2. Devices > Configuration > Create > New Policy" -ForegroundColor Gray
    Write-Host "    3. Platform: Windows 10 and later" -ForegroundColor Gray
    Write-Host "    4. Profile type: Settings catalog" -ForegroundColor Gray
    Write-Host "    5. Search for 'Web Content Filtering'" -ForegroundColor Gray
    Write-Host "    6. Enable blocked categories" -ForegroundColor Gray
    Write-Host "    7. Assign to device groups" -ForegroundColor Gray
    Write-Host ""
}

# ============================================================================
# ENTRY POINT
# ============================================================================

try {
    if (!(Initialize-ScriptModules)) {
        Write-Host "Failed to initialize required modules. Exiting." -ForegroundColor Red
        return
    }

    Start-WebFiltering
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
}
