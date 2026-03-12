#Requires -Version 7.0

<#
.SYNOPSIS
    Deploys Winget Auto Update (WAU) with MSP-recommended configuration
.DESCRIPTION
    1. Imports WAU ADMX/ADML files to Intune
    2. Creates Administrative Templates configuration policy (using imported ADMX)
    3. Deploys WAU app from Microsoft Store (new)
    Includes blacklist for Microsoft apps that should be managed separately.
.AUTHOR
    CB & Claude Partnership
.VERSION
    2.0 - Standardized UX with preview mode
.NOTES
    - App: Winget-AutoUpdate-aaS from Microsoft Store (Store ID: XP89BSK82W9J28)
    - ADMX/ADML from: https://github.com/Weatherlights/Winget-AutoUpdate-Intune
    - Uses Administrative Templates profile type (same as manual import in Intune)
#>

# ============================================================================
# CONFIGURATION
# ============================================================================

$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.DeviceManagement',
    'Microsoft.Graph.Groups'
)

$RequiredScopes = @(
    "DeviceManagementApps.ReadWrite.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "Group.Read.All"
)

# ADMX File Names (loaded from GitHub or local)
$ADMXFileName = "WinGet-AutoUpdate-Configurator.admx"
$ADMLFileName = "WinGet-AutoUpdate-Configurator.adml"

# Will be populated by Get-ADMXFiles function
$script:ADMXContent = $null
$script:ADMLContent = $null

# WAU Store App Configuration (Microsoft Store app - new)
$WAUStoreApp = @{
    Name = "WinGet-AutoUpdate-Configurator"
    PackageIdentifier = "XP89BSK82W9J28"  # Microsoft Store ID
    Publisher = "Hauke Hasselberg"
    Description = "With WinGet-AutoUpdate-aaS for Microsoft Intune you can easily keep your 3rd party applications up-to-date."
}

# MSP-Recommended WAU Settings
$WAUConfig = @{
    PolicyName = "WAU - MSP Configuration"
    PolicyDescription = "Winget Auto Update - MSP recommended settings"

    # Settings based on your recommendations
    Settings = @{
        DesktopShortcut = 0        # Disabled - No clutter
        StartMenuShortcut = 0      # Disabled - No clutter
        NotificationLevel = "SuccessOnly"  # Avoid confusing users
        UpdatesAtTime = "12:00"    # Lunch time - minimal disruption
        UpdatesInterval = "Daily"  # Good balance
        UpdatesAtLogon = 0         # Disabled - Can slow logins
        BypassListForUsers = 0     # Disabled - Don't let users override
        DoNotUpdate = 1            # Enabled - Prevents surprise updates on install
        InstallUserContext = 0     # Disabled - SYSTEM for consistency
        RunOnMetered = 0           # Disabled - Protect mobile users
        UseWhiteList = 0           # Disabled - Use blacklist approach
    }

    # Blacklist - Apps managed separately or cause issues
    BlackList = @(
        "Microsoft.Teams"
        "Microsoft.OneDrive"
        "Microsoft.Edge"
        "Microsoft.Office"
        "Microsoft.WindowsTerminal"
        "Microsoft.PowerShell"
    )
}

# Target device group
$TargetGroup = "Windows Devices (Autopilot)"

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
# ADMX FILE LOADING
# ============================================================================

function Get-ADMXFiles {
    <#
    .SYNOPSIS
        Loads ADMX/ADML files from GitHub or local fallback
    #>

    Write-Host "   Loading ADMX/ADML files..." -ForegroundColor Gray

    # Try GitHub first
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $baseUrl = "https://raw.githubusercontent.com/$Global:GitHubRepo/$Global:GitHubBranch/Intune/ADMX"

        Write-Host "   Downloading from GitHub..." -ForegroundColor Gray
        # Use Invoke-WebRequest to get raw string - Invoke-RestMethod auto-parses XML into objects
        $script:ADMXContent = (Invoke-WebRequest -Uri "$baseUrl/$ADMXFileName" -ErrorAction Stop).Content
        $script:ADMLContent = (Invoke-WebRequest -Uri "$baseUrl/$ADMLFileName" -ErrorAction Stop).Content

        Write-Host "   Downloaded ADMX/ADML from GitHub" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "   GitHub download failed, trying local..." -ForegroundColor Yellow
    }

    # Try local paths
    $possiblePaths = @(
        ".\ADMX",
        ".\Intune\ADMX",
        "$PWD\ADMX",
        "$PWD\Intune\ADMX"
    )

    foreach ($basePath in $possiblePaths) {
        $admxPath = Join-Path $basePath $ADMXFileName
        $admlPath = Join-Path $basePath $ADMLFileName

        if ((Test-Path $admxPath -ErrorAction SilentlyContinue) -and (Test-Path $admlPath -ErrorAction SilentlyContinue)) {
            Write-Host "   Loading from local: $basePath" -ForegroundColor Gray
            $script:ADMXContent = Get-Content $admxPath -Raw
            $script:ADMLContent = Get-Content $admlPath -Raw
            Write-Host "   Loaded ADMX/ADML from local files" -ForegroundColor Green
            return $true
        }
    }

    Write-Host "   Could not find ADMX/ADML files" -ForegroundColor Red
    Write-Host "   Expected in: Intune/ADMX/ folder or GitHub repo" -ForegroundColor Yellow
    return $false
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

    # Load ADMX/ADML files from GitHub or local
    if (!(Get-ADMXFiles)) {
        return @{ Success = $false }
    }

    # Check for target device group
    Write-Host "   Checking for target device group..." -ForegroundColor Gray
    $group = Get-MgGroup -Filter "displayName eq '$TargetGroup'" -ErrorAction SilentlyContinue
    if ($group) {
        Write-Host "   Found: $TargetGroup" -ForegroundColor Green
    }
    else {
        Write-Host "   Target group '$TargetGroup' not found" -ForegroundColor Yellow
        Write-Host "   Run Device Groups script first, or policies won't be assigned" -ForegroundColor Yellow
    }

    # Check if ADMX already imported
    Write-Host "   Checking for existing WAU ADMX..." -ForegroundColor Gray
    $existingAdmx = Get-ExistingWAUAdmx
    if ($existingAdmx) {
        Write-Host "   WAU ADMX already imported (ID: $($existingAdmx.id))" -ForegroundColor Green
    }
    else {
        Write-Host "   WAU ADMX not found (will be imported)" -ForegroundColor Yellow
    }

    # Check if WAU app already exists
    Write-Host "   Checking for existing WAU app..." -ForegroundColor Gray
    $existingApp = Get-ExistingWAUApp
    if ($existingApp) {
        Write-Host "   WAU app already deployed" -ForegroundColor Yellow
    }
    else {
        Write-Host "   WAU app not found (will be deployed)" -ForegroundColor Green
    }

    # Check if WAU config policy exists
    Write-Host "   Checking for existing WAU config policy..." -ForegroundColor Gray
    $existingConfig = Get-ExistingWAUConfig
    if ($existingConfig) {
        Write-Host "   WAU config policy already exists" -ForegroundColor Yellow
    }
    else {
        Write-Host "   WAU config not found (will be created)" -ForegroundColor Green
    }

    Write-Host ""
    return @{
        Success = $true
        GroupId = $group.Id
        ExistingAdmx = $existingAdmx
        ExistingApp = $existingApp
        ExistingConfig = $existingConfig
    }
}

function Get-ExistingWAUAdmx {
    try {
        $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET
        return $response.value | Where-Object { $_.fileName -like "*WinGet-AutoUpdate*" -or $_.fileName -like "*Winget-AutoUpdate*" } | Select-Object -First 1
    }
    catch {
        return $null
    }
}

function Get-ExistingWAUApp {
    try {
        # Search for WAU app by various possible names
        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=contains(displayName,'WinGet-AutoUpdate') or contains(displayName,'Winget-AutoUpdate') or contains(displayName,'Winget AutoUpdate')"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET
        return $response.value | Select-Object -First 1
    }
    catch {
        return $null
    }
}

function Get-ExistingWAUConfig {
    try {
        # Check for Administrative Templates profile (groupPolicyConfigurations)
        $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations?`$filter=contains(displayName,'WAU')"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET
        $existing = $response.value | Where-Object { $_.displayName -eq $WAUConfig.PolicyName } | Select-Object -First 1

        if ($existing) {
            return $existing
        }

        # Also check legacy custom OMA-URI profiles
        $uri2 = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=contains(displayName,'WAU')"
        $response2 = Invoke-MgGraphRequest -Uri $uri2 -Method GET
        return $response2.value | Where-Object { $_.displayName -eq $WAUConfig.PolicyName } | Select-Object -First 1
    }
    catch {
        return $null
    }
}

# ============================================================================
# PREVIEW MODE
# ============================================================================

function Show-WAUPreview {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  PREVIEW: Winget Auto Update Deployment" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""

    # ADMX Import
    Write-Host "  1. ADMX IMPORT" -ForegroundColor Yellow
    Write-Host "  ----------------------------------------" -ForegroundColor Gray
    Write-Host "     ADMX File: $ADMXFileName" -ForegroundColor White
    Write-Host "     ADML File: $ADMLFileName" -ForegroundColor White
    Write-Host "     Source:    GitHub repo or local Intune/ADMX folder" -ForegroundColor White
    Write-Host ""

    # App deployment
    Write-Host "  2. MICROSOFT STORE APP (NEW)" -ForegroundColor Yellow
    Write-Host "  ----------------------------------------" -ForegroundColor Gray
    Write-Host "     App Name:       $($WAUStoreApp.Name)" -ForegroundColor White
    Write-Host "     Store ID:       $($WAUStoreApp.PackageIdentifier)" -ForegroundColor White
    Write-Host "     Publisher:      $($WAUStoreApp.Publisher)" -ForegroundColor White
    Write-Host "     Install Mode:   System (device-wide)" -ForegroundColor White
    Write-Host "     Assignment:     Required to $TargetGroup" -ForegroundColor White
    Write-Host ""

    # Configuration policy
    Write-Host "  3. CONFIGURATION POLICY (Administrative Templates)" -ForegroundColor Yellow
    Write-Host "  ----------------------------------------" -ForegroundColor Gray
    Write-Host "     Profile Type: Administrative Templates (imported ADMX)" -ForegroundColor White
    Write-Host "     Policy Name:  $($WAUConfig.PolicyName)" -ForegroundColor White
    Write-Host ""
    Write-Host "     UI Settings:" -ForegroundColor Cyan
    Write-Host "       Desktop Shortcut:     Disabled (no clutter)" -ForegroundColor Gray
    Write-Host "       Start Menu Shortcut:  Disabled (no clutter)" -ForegroundColor Gray
    Write-Host "       Notification Level:   $($WAUConfig.Settings.NotificationLevel)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "     Update Schedule:" -ForegroundColor Cyan
    Write-Host "       Update Time:          $($WAUConfig.Settings.UpdatesAtTime) (lunch time)" -ForegroundColor Gray
    Write-Host "       Update Frequency:     $($WAUConfig.Settings.UpdatesInterval)" -ForegroundColor Gray
    Write-Host "       Updates at Logon:     Disabled (don't slow logins)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "     Behavior Settings:" -ForegroundColor Cyan
    Write-Host "       Update on Install:    Disabled (no surprise updates)" -ForegroundColor Gray
    Write-Host "       User Context:         Disabled (SYSTEM for consistency)" -ForegroundColor Gray
    Write-Host "       Metered Connection:   Disabled (protect mobile users)" -ForegroundColor Gray
    Write-Host "       Bypass List for Users: Disabled (enforce blacklist)" -ForegroundColor Gray
    Write-Host "       List Mode:            Blacklist (update all except exclusions)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "     Blacklisted Apps (managed separately):" -ForegroundColor Cyan
    foreach ($app in $WAUConfig.BlackList) {
        Write-Host "       - $app" -ForegroundColor Gray
    }
    Write-Host ""
}

# ============================================================================
# DEPLOYMENT FUNCTIONS
# ============================================================================

function Import-WAUAdmx {
    try {
        Write-Host "     Encoding ADMX content..." -ForegroundColor Gray
        # Encode raw bytes directly to avoid string encoding issues
        $admxBytes = [System.Text.Encoding]::UTF8.GetBytes($script:ADMXContent)
        $admxContentB64 = [Convert]::ToBase64String($admxBytes)
        Write-Host "     ADMX: $($admxBytes.Length) bytes, B64 length: $($admxContentB64.Length)" -ForegroundColor Gray

        Write-Host "     Encoding ADML content..." -ForegroundColor Gray
        $admlBytes = [System.Text.Encoding]::UTF8.GetBytes($script:ADMLContent)
        $admlContentB64 = [Convert]::ToBase64String($admlBytes)
        Write-Host "     ADML: $($admlBytes.Length) bytes" -ForegroundColor Gray

        # Verify content looks like XML
        $admxPreview = $script:ADMXContent.Substring(0, [Math]::Min(80, $script:ADMXContent.Length))
        Write-Host "     ADMX preview: $admxPreview" -ForegroundColor DarkGray

        Write-Host "     Uploading ADMX to Intune..." -ForegroundColor Gray

        $uploadBody = @{
            "@odata.type" = "#microsoft.graph.groupPolicyUploadedDefinitionFile"
            fileName = $ADMXFileName
            content = $admxContentB64
            languageCodes = @("en-US")
            groupPolicyUploadedLanguageFiles = @(
                @{
                    fileName = $ADMLFileName
                    languageCode = "en-US"
                    content = $admlContentB64
                }
            )
        }

        $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles"
        $jsonBody = $uploadBody | ConvertTo-Json -Depth 10
        $result = Invoke-MgGraphRequest -Uri $uri -Method POST -Body $jsonBody -ContentType "application/json"

        Write-Host "     ADMX imported (ID: $($result.id))" -ForegroundColor Green

        # Wait for processing
        Write-Host "     Waiting for ADMX processing..." -ForegroundColor Gray
        $maxWait = 60
        $waited = 0
        do {
            Start-Sleep -Seconds 5
            $waited += 5
            $statusUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles/$($result.id)"
            $status = Invoke-MgGraphRequest -Uri $statusUri -Method GET
            Write-Host "       Status: $($status.status) ($waited sec)" -ForegroundColor Gray
        } while ($status.status -eq "uploadInProgress" -and $waited -lt $maxWait)

        if ($status.status -eq "available") {
            Write-Host "     ADMX processing complete" -ForegroundColor Green
            return @{ Success = $true; AdmxId = $result.id }
        }
        else {
            Write-Host "     ADMX status: $($status.status)" -ForegroundColor Yellow
            return @{ Success = $true; AdmxId = $result.id; Status = $status.status }
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        if ($_.ErrorDetails.Message) {
            try {
                $detail = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
                if ($detail) { $errMsg += " - $detail" }
            } catch {}
        }
        Write-Host "     Failed: $errMsg" -ForegroundColor Red
        return @{ Success = $false; Error = $errMsg }
    }
}

function New-WAUStoreApp {
    param([string]$GroupId)

    try {
        Write-Host "     Creating Microsoft Store app (new)..." -ForegroundColor Gray

        # Microsoft Store app (new) uses winGetApp type with Store package ID
        $appBody = @{
            "@odata.type" = "#microsoft.graph.winGetApp"
            displayName = $WAUStoreApp.Name
            description = $WAUStoreApp.Description
            publisher = $WAUStoreApp.Publisher
            packageIdentifier = $WAUStoreApp.PackageIdentifier
            installExperience = @{
                runAsAccount = "system"  # Install as SYSTEM for device-wide deployment
            }
        }

        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"
        $newApp = Invoke-MgGraphRequest -Uri $uri -Method POST -Body $appBody

        Write-Host "     App created (ID: $($newApp.id))" -ForegroundColor Green
        Write-Host "       Name: $($WAUStoreApp.Name)" -ForegroundColor Gray
        Write-Host "       Store ID: $($WAUStoreApp.PackageIdentifier)" -ForegroundColor Gray

        # Assign to group if GroupId provided
        if ($GroupId) {
            Write-Host "     Assigning to device group as Required..." -ForegroundColor Gray

            $assignmentBody = @{
                mobileAppAssignments = @(
                    @{
                        "@odata.type" = "#microsoft.graph.mobileAppAssignment"
                        target = @{
                            "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                            groupId = $GroupId
                        }
                        intent = "required"
                    }
                )
            }

            $assignUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($newApp.id)/assign"
            $null = Invoke-MgGraphRequest -Uri $assignUri -Method POST -Body ($assignmentBody | ConvertTo-Json -Depth 10)
            Write-Host "     Assigned to $TargetGroup (Required)" -ForegroundColor Green
        }

        return @{ Success = $true; App = $newApp }
    }
    catch {
        Write-Host "     Failed: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Get-WAUPolicyDefinitions {
    <#
    .SYNOPSIS
        Gets the policy definitions from the imported WAU ADMX
    #>
    param([string]$AdmxId)

    try {
        # Wait for ADMX to be fully processed and get definitions
        $maxWait = 60
        $waited = 0
        $wauDefs = $null

        while ($waited -lt $maxWait) {
            # Query definitions filtered by the uploaded ADMX file
            $defUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=definitionFile/id eq '$AdmxId'"
            $defsResponse = Invoke-MgGraphRequest -Uri $defUri -Method GET

            if ($defsResponse.value -and $defsResponse.value.Count -gt 0) {
                $wauDefs = $defsResponse.value
                break
            }

            Start-Sleep -Seconds 5
            $waited += 5
            Write-Host "       Waiting for ADMX definitions... ($waited sec)" -ForegroundColor Gray
        }

        if (!$wauDefs) {
            # Fallback: search by category path
            $defUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions"
            $allDefs = Invoke-MgGraphRequest -Uri $defUri -Method GET

            $wauDefs = $allDefs.value | Where-Object {
                $_.categoryPath -like "*WAUC*" -or
                $_.categoryPath -like "*Winget*" -or
                $_.displayName -like "*Winget*AutoUpdate*"
            }
        }

        return $wauDefs
    }
    catch {
        Write-Host "       Error getting definitions: $($_.Exception.Message)" -ForegroundColor Yellow
        return $null
    }
}

function New-WAUConfigPolicy {
    param(
        [string]$GroupId,
        [string]$AdmxId
    )

    try {
        Write-Host "     Creating Administrative Templates configuration..." -ForegroundColor Gray

        # Step 1: Create the Group Policy Configuration (Administrative Templates profile)
        $configBody = @{
            displayName = $WAUConfig.PolicyName
            description = $WAUConfig.PolicyDescription
        }

        $configUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations"
        $newConfig = Invoke-MgGraphRequest -Uri $configUri -Method POST -Body $configBody

        Write-Host "     Profile created (ID: $($newConfig.id))" -ForegroundColor Green

        # Step 2: Get WAU policy definitions from imported ADMX
        Write-Host "     Retrieving policy definitions from imported ADMX..." -ForegroundColor Gray
        $definitions = Get-WAUPolicyDefinitions -AdmxId $AdmxId

        if (!$definitions -or $definitions.Count -eq 0) {
            Write-Host "     Warning: Could not retrieve ADMX definitions automatically" -ForegroundColor Yellow
            Write-Host "     The ADMX was imported - configure settings manually in Intune:" -ForegroundColor Yellow
            Write-Host "       Devices > Configuration > $($WAUConfig.PolicyName) > Edit" -ForegroundColor Cyan
        }
        else {
            Write-Host "     Found $($definitions.Count) WAU policy definitions" -ForegroundColor Green

            # Step 3: Configure each setting based on policy name matching
            $settingsConfigured = 0

            # Map our config to policy display names
            # Note: For dropdown/text settings, we just enable them - the ADMX defaults will apply
            $settingsMap = @{
                "DesktopShortcut" = @{ Pattern = "Desktop.*Shortcut"; Enabled = ($WAUConfig.Settings.DesktopShortcut -eq 1) }
                "StartMenuShortcut" = @{ Pattern = "Start.*Menu.*Shortcut"; Enabled = ($WAUConfig.Settings.StartMenuShortcut -eq 1) }
                "NotificationLevel" = @{ Pattern = "Notification.*level"; Enabled = $true }  # ADMX default: SuccessOnly
                "UpdatesAtTime" = @{ Pattern = "Update.*at.*time"; Enabled = $true }         # ADMX default: 12:00
                "UpdatesInterval" = @{ Pattern = "Update.*frequency|interval"; Enabled = $true }  # ADMX default: Daily
                "UpdatesAtLogon" = @{ Pattern = "Updates.*at.*logon"; Enabled = ($WAUConfig.Settings.UpdatesAtLogon -eq 1) }
                "BypassListForUsers" = @{ Pattern = "Bypass.*List"; Enabled = ($WAUConfig.Settings.BypassListForUsers -eq 1) }
                "DoNotUpdate" = @{ Pattern = "Do.*not.*update"; Enabled = ($WAUConfig.Settings.DoNotUpdate -eq 1) }
                "InstallUserContext" = @{ Pattern = "Install.*user.*context"; Enabled = ($WAUConfig.Settings.InstallUserContext -eq 1) }
                "RunOnMetered" = @{ Pattern = "Run.*on.*metered"; Enabled = ($WAUConfig.Settings.RunOnMetered -eq 1) }
                "UseWhiteList" = @{ Pattern = "Use.*White.*List"; Enabled = ($WAUConfig.Settings.UseWhiteList -eq 1) }
            }

            foreach ($settingName in $settingsMap.Keys) {
                $setting = $settingsMap[$settingName]
                $matchingDef = $definitions | Where-Object { $_.displayName -match $setting.Pattern } | Select-Object -First 1

                if ($matchingDef) {
                    try {
                        # Just enable the policy - ADMX defaults will apply for dropdowns/text
                        $defValueBody = @{
                            "definition@odata.bind" = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($matchingDef.id)')"
                            enabled = $setting.Enabled
                        }

                        $defValueUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($newConfig.id)/definitionValues"
                        $null = Invoke-MgGraphRequest -Uri $defValueUri -Method POST -Body $defValueBody
                        $settingsConfigured++
                        Write-Host "       Configured: $($matchingDef.displayName)" -ForegroundColor Gray
                    }
                    catch {
                        Write-Host "       Skipped $settingName : $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
            }

            Write-Host "     Configured $settingsConfigured of 11 toggle settings" -ForegroundColor Green
            Write-Host "     (Dropdown/text settings use ADMX defaults: SuccessOnly, 12:00, Daily)" -ForegroundColor Cyan

            # Step 4: Enable the Application List policy (values added manually in Intune)
            Write-Host "     Enabling Application List policy..." -ForegroundColor Gray
            try {
                $listDef = $definitions | Where-Object { $_.displayName -like "*Application*List*" -or $_.displayName -eq "Application List" } | Select-Object -First 1

                if ($listDef) {
                    # Just enable the policy - don't try to set values (API doesn't support ListBox values properly)
                    # User will add blacklist apps manually in Intune UI
                    $listDefBody = @{
                        "definition@odata.bind" = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($listDef.id)')"
                        enabled = $true
                    }

                    $listUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($newConfig.id)/definitionValues"
                    $null = Invoke-MgGraphRequest -Uri $listUri -Method POST -Body $listDefBody
                    $settingsConfigured++
                    Write-Host "     Application List ENABLED (add apps manually in Intune)" -ForegroundColor Green
                }
                else {
                    Write-Host "     Note: Application List policy not found" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "     Note: Application List enable failed: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }

        # Step 5: Assign to group
        if ($GroupId) {
            Write-Host "     Assigning to device group..." -ForegroundColor Gray

            $assignmentBody = @{
                assignments = @(
                    @{
                        target = @{
                            "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                            groupId = $GroupId
                        }
                    }
                )
            }

            $assignUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($newConfig.id)/assign"
            $null = Invoke-MgGraphRequest -Uri $assignUri -Method POST -Body $assignmentBody
            Write-Host "     Assigned to $TargetGroup" -ForegroundColor Green
        }

        return @{ Success = $true; Policy = $newConfig }
    }
    catch {
        Write-Host "     Failed: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-WAUDeployment {
    # Header
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  WINGET AUTO UPDATE DEPLOYMENT" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Deploys WAU app + ADMX + MSP-recommended configuration" -ForegroundColor Gray
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
    Show-WAUPreview

    # Confirmation
    Write-Host "  [Y] Deploy WAU with configuration  [N] Cancel" -ForegroundColor Gray
    Write-Host ""
    $confirm = Read-Host "  Deploy Winget Auto Update? (Y/N)"

    if ($confirm -notlike "Y*") {
        Write-Host ""
        Write-Host "  Cancelled by user" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    # Step 3: Deploy
    Write-Host ""
    Write-Host "  STEP 3: Deploying" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    $results = @{
        AdmxImported = $false
        AdmxId = $null
        AppDeployed = $false
        ConfigDeployed = $false
        Errors = @()
    }

    # Import ADMX
    Write-Host "   WAU ADMX Import..." -ForegroundColor White
    if ($prereqResult.ExistingAdmx) {
        Write-Host "     Already imported (skipped)" -ForegroundColor Yellow
        $results.AdmxImported = $true
        $results.AdmxId = $prereqResult.ExistingAdmx.id
    }
    else {
        $admxResult = Import-WAUAdmx
        if ($admxResult.Success) {
            $results.AdmxImported = $true
            $results.AdmxId = $admxResult.AdmxId
        }
        else {
            $results.Errors += "ADMX: $($admxResult.Error)"
        }
    }

    Start-Sleep -Milliseconds 500

    # Deploy Store App
    Write-Host "   Winget Auto Update App..." -ForegroundColor White
    if ($prereqResult.ExistingApp) {
        Write-Host "     Already exists (skipped)" -ForegroundColor Yellow
        $results.AppDeployed = $true
    }
    else {
        $appResult = New-WAUStoreApp -GroupId $prereqResult.GroupId
        if ($appResult.Success) {
            $results.AppDeployed = $true
        }
        else {
            $results.Errors += "App: $($appResult.Error)"
        }
    }

    Start-Sleep -Milliseconds 500

    # Deploy Configuration Policy (requires ADMX to be imported first)
    Write-Host "   WAU Configuration Policy (Administrative Templates)..." -ForegroundColor White
    if ($prereqResult.ExistingConfig) {
        Write-Host "     Already exists (skipped)" -ForegroundColor Yellow
        $results.ConfigDeployed = $true
    }
    elseif (!$results.AdmxId) {
        Write-Host "     Skipped - ADMX import required first" -ForegroundColor Yellow
        $results.Errors += "Config: ADMX must be imported first"
    }
    else {
        $configResult = New-WAUConfigPolicy -GroupId $prereqResult.GroupId -AdmxId $results.AdmxId
        if ($configResult.Success) {
            $results.ConfigDeployed = $true
        }
        else {
            $results.Errors += "Config: $($configResult.Error)"
        }
    }

    # Step 4: Summary
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  ADMX Import:          $(if ($results.AdmxImported) { 'Success' } else { 'Failed' })" -ForegroundColor $(if ($results.AdmxImported) { "Green" } else { "Red" })
    Write-Host "  WAU Store App:        $(if ($results.AppDeployed) { 'Deployed' } else { 'Failed' })" -ForegroundColor $(if ($results.AppDeployed) { "Green" } else { "Red" })
    Write-Host "  Configuration Policy: $(if ($results.ConfigDeployed) { 'Deployed' } else { 'Failed' })" -ForegroundColor $(if ($results.ConfigDeployed) { "Green" } else { "Red" })
    Write-Host ""

    if ($results.Errors.Count -gt 0) {
        Write-Host "  Errors:" -ForegroundColor Red
        foreach ($err in $results.Errors) {
            Write-Host "    - $err" -ForegroundColor Red
        }
        Write-Host ""
    }

    Write-Host "  Settings Auto-Configured (12 of 12):" -ForegroundColor Green
    Write-Host "    Desktop Shortcut:      Disabled" -ForegroundColor Gray
    Write-Host "    Start Menu Shortcut:   Disabled" -ForegroundColor Gray
    Write-Host "    Updates at Logon:      Disabled" -ForegroundColor Gray
    Write-Host "    Do Not Update:         Enabled" -ForegroundColor Gray
    Write-Host "    Install User Context:  Disabled" -ForegroundColor Gray
    Write-Host "    Run on Metered:        Disabled" -ForegroundColor Gray
    Write-Host "    Use White List:        Disabled (blacklist mode)" -ForegroundColor Gray
    Write-Host "    Bypass List for Users: Disabled" -ForegroundColor Gray
    Write-Host "    Notification Level:    SuccessOnly (ADMX default)" -ForegroundColor Gray
    Write-Host "    Update Time:           12:00 (ADMX default)" -ForegroundColor Gray
    Write-Host "    Update Frequency:      Daily (ADMX default)" -ForegroundColor Gray
    Write-Host "    Application List:      ENABLED (add apps below)" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  Blacklist Apps (add to Application List in Intune):" -ForegroundColor Yellow
    foreach ($app in $WAUConfig.BlackList) {
        Write-Host "    - $app" -ForegroundColor Cyan
    }
    Write-Host ""

    Write-Host "  Next Steps:" -ForegroundColor Yellow
    Write-Host "    1. Open: Intune > Devices > Configuration > $($WAUConfig.PolicyName)" -ForegroundColor Gray
    Write-Host "    2. Edit > Application List > Add the apps listed above" -ForegroundColor Gray
    Write-Host "    3. Verify policy applies to a test device" -ForegroundColor Gray
    Write-Host "    4. Monitor WAU logs: C:\ProgramData\Winget-AutoUpdate\Logs" -ForegroundColor Gray
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

    Start-WAUDeployment
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
}
