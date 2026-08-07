#Requires -Version 7.0

<#
.SYNOPSIS
    Creates Intune App Protection (MAM) policies for Android and iOS BYOD devices
.DESCRIPTION
    Creates Android and iOS app protection policies scoped to the core Microsoft
    365 mobile apps (Outlook, Teams, OneDrive, Word, Excel, PowerPoint,
    SharePoint), assigned to All Users with the NoMFA Exclusion Group excluded
    (break-glass accounts). These are what makes entra/CA-Policies.ps1's C009
    (BYOD Android and iOS App Protection) actually enforceable — C009's
    "require app protection policy" grant control only evaluates true for an
    app covered by a real app protection policy; without one, that control can
    never be satisfied.
.AUTHOR
    BITS
.VERSION
    1.0 - Initial version: Android + iOS app protection policies, targeted
          apps, and All Users (minus NoMFA group) assignment.
.PARAMETER NonInteractive
    Run unattended: skip the Y/N confirmation and all "press any key" pauses.
    Used by CI E2E tests.
.PARAMETER ConfigFile
    Optional JSON file overriding run behaviour. Supported keys:
      NamePrefix      (string) prefixed to every policy's displayName, e.g.
                      "E2E-" — lets E2E tests create/verify/delete only
                      throwaway prefixed policies
      GroupNamePrefix (string) prefixed to the NoMFA Exclusion Group name this
                      script looks up for the assignment exclusion
.PARAMETER ResultPath
    Optional path to write a JSON results summary, so a CI runner can assert
    on the outcome.
#>

param(
    [switch] $NonInteractive,
    [string] $ConfigFile,
    [string] $ResultPath
)

# ============================================================================
# CONFIGURATION
# ============================================================================

$script:NonInteractive = [bool]$NonInteractive

# Run-behaviour config — overridable via -ConfigFile JSON
$script:RunConfig = @{
    NamePrefix      = ''
    GroupNamePrefix = ''
}

if ($ConfigFile) {
    if (!(Test-Path $ConfigFile)) {
        Write-Host "Config file not found: $ConfigFile" -ForegroundColor Red
        if ($script:NonInteractive) { exit 2 } else { return }
    }
    try {
        $userConfig = Get-Content $ConfigFile -Raw | ConvertFrom-Json -AsHashtable
        foreach ($key in @($script:RunConfig.Keys)) {
            if ($userConfig.ContainsKey($key)) { $script:RunConfig[$key] = $userConfig[$key] }
        }
        Write-Host "Loaded config from $ConfigFile" -ForegroundColor Gray
    }
    catch {
        Write-Host "Failed to parse config file: $($_.Exception.Message)" -ForegroundColor Red
        if ($script:NonInteractive) { exit 2 } else { return }
    }
}

$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Identity.DirectoryManagement'
)

$RequiredScopes = @(
    'DeviceManagementApps.ReadWrite.All',
    'Group.Read.All',
    'Directory.Read.All'
)

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
        Verify Graph connectivity/permissions and resolve the (optional)
        NoMFA Exclusion Group used as the assignment exclusion. Missing NoMFA
        group is a warning, not a blocker — policies are still created and
        assigned to All Users, just without a break-glass exclusion until the
        group exists.
    #>

    Write-Host ""
    Write-Host "   PREREQUISITES CHECK" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 40) -ForegroundColor Gray

    Write-Host "   Checking Microsoft Graph connection..." -ForegroundColor Gray
    $context = Get-MgContext
    if (!$context) {
        Write-Host "   Not connected to Microsoft Graph" -ForegroundColor Red
        Write-Host "   Please connect using the main menu first" -ForegroundColor Yellow
        return @{ Success = $false }
    }
    Write-Host "   Connected as: $($context.Account)" -ForegroundColor Green

    Write-Host "   Checking required permissions..." -ForegroundColor Gray
    # @() wrap: Where-Object returns $null when nothing matches and a bare
    # scalar (no .Count) when exactly one item matches — either case throws
    # under Set-StrictMode
    $missingScopes = @($RequiredScopes | Where-Object { $_ -notin $context.Scopes })

    if ($missingScopes.Count -gt 0) {
        if ($context.AuthType -eq 'AppOnly' -or $script:NonInteractive) {
            Write-Host "   Missing scopes (continuing unattended): $($missingScopes -join ', ')" -ForegroundColor Yellow
        }
        else {
            Write-Host "   Missing scopes: $($missingScopes -join ', ')" -ForegroundColor Yellow
            Write-Host "   Attempting to request additional permissions..." -ForegroundColor Yellow
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
    }
    else {
        Write-Host "   All required permissions present" -ForegroundColor Green
    }

    Write-Host "   Checking for NoMFA Exclusion Group (optional)..." -ForegroundColor Gray
    $groupPrefix = $script:RunConfig.GroupNamePrefix
    $noMfaGroup = Get-MgGroup -Filter "displayName eq '${groupPrefix}NoMFA Exclusion Group'" -ErrorAction SilentlyContinue
    $noMfaGroupId = $null
    if ($noMfaGroup) {
        Write-Host "   ${groupPrefix}NoMFA Exclusion Group found (ID: $($noMfaGroup.Id))" -ForegroundColor Green
        $noMfaGroupId = $noMfaGroup.Id
    }
    else {
        Write-Host "   ${groupPrefix}NoMFA Exclusion Group not found - policies will be assigned to All Users with no break-glass exclusion" -ForegroundColor Yellow
    }

    Write-Host ""
    return @{ Success = $true; NoMfaGroupId = $noMfaGroupId }
}

# ============================================================================
# DATA FUNCTIONS
# ============================================================================

function Get-TenantInfo {
    try {
        $org = Get-MgOrganization | Select-Object -First 1
        return @{
            TenantId         = $org.Id
            OrganizationName = $org.DisplayName
        }
    }
    catch {
        Write-Host "   Failed to get tenant info: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Get-PolicyDefinitions {
    <#
    .SYNOPSIS
        Android + iOS app protection policy definitions, each scoped to the
        core Microsoft 365 mobile apps and a conservative BYOD-appropriate
        settings baseline (app-level PIN, managed-app-only data transfer,
        blocked backup/save-as/print, 90-day offline wipe). Deliberately
        stops short of enumerating every optional MAM setting — matches this
        repo's existing pattern of a defensible baseline over an exhaustive
        one (e.g. the trimmed Windows compliance policy in
        Compliance-Policies.ps1).
    #>
    param([string]$NamePrefix = '')

    $androidApps = @(
        @{ mobileAppIdentifier = @{ '@odata.type' = '#microsoft.graph.androidMobileAppIdentifier'; packageId = 'com.microsoft.office.outlook' } }
        @{ mobileAppIdentifier = @{ '@odata.type' = '#microsoft.graph.androidMobileAppIdentifier'; packageId = 'com.microsoft.teams' } }
        @{ mobileAppIdentifier = @{ '@odata.type' = '#microsoft.graph.androidMobileAppIdentifier'; packageId = 'com.microsoft.skydrive' } }
        @{ mobileAppIdentifier = @{ '@odata.type' = '#microsoft.graph.androidMobileAppIdentifier'; packageId = 'com.microsoft.office.word' } }
        @{ mobileAppIdentifier = @{ '@odata.type' = '#microsoft.graph.androidMobileAppIdentifier'; packageId = 'com.microsoft.office.excel' } }
        @{ mobileAppIdentifier = @{ '@odata.type' = '#microsoft.graph.androidMobileAppIdentifier'; packageId = 'com.microsoft.office.powerpoint' } }
        @{ mobileAppIdentifier = @{ '@odata.type' = '#microsoft.graph.androidMobileAppIdentifier'; packageId = 'com.microsoft.sharepoint' } }
    )
    $iosApps = @(
        @{ mobileAppIdentifier = @{ '@odata.type' = '#microsoft.graph.iosMobileAppIdentifier'; bundleId = 'com.microsoft.Office.Outlook' } }
        @{ mobileAppIdentifier = @{ '@odata.type' = '#microsoft.graph.iosMobileAppIdentifier'; bundleId = 'com.microsoft.skype.teams' } }
        @{ mobileAppIdentifier = @{ '@odata.type' = '#microsoft.graph.iosMobileAppIdentifier'; bundleId = 'com.microsoft.skydrive' } }
        @{ mobileAppIdentifier = @{ '@odata.type' = '#microsoft.graph.iosMobileAppIdentifier'; bundleId = 'com.microsoft.Office.Word' } }
        @{ mobileAppIdentifier = @{ '@odata.type' = '#microsoft.graph.iosMobileAppIdentifier'; bundleId = 'com.microsoft.Office.Excel' } }
        @{ mobileAppIdentifier = @{ '@odata.type' = '#microsoft.graph.iosMobileAppIdentifier'; bundleId = 'com.microsoft.Office.Powerpoint' } }
        @{ mobileAppIdentifier = @{ '@odata.type' = '#microsoft.graph.iosMobileAppIdentifier'; bundleId = 'com.microsoft.sharepoint' } }
    )

    # Settings shared by both platform schemas
    $commonSettings = @{
        periodOfflineBeforeAccessCheck                 = 'PT12H'
        periodOnlineBeforeAccessCheck                  = 'PT30M'
        allowedInboundDataTransferSources              = 'managedApps'
        allowedOutboundDataTransferDestinations        = 'managedApps'
        organizationalCredentialsRequired              = $false
        allowedOutboundClipboardSharingLevel           = 'managedAppsWithPasteIn'
        allowedOutboundClipboardSharingExceptionLength = 0
        dataBackupBlocked                              = $true
        deviceComplianceRequired                       = $false
        managedBrowserToOpenLinksRequired              = $true
        saveAsBlocked                                  = $true
        periodOfflineBeforeWipeIsEnforced              = 'P90D'
        pinRequired                                    = $true
        maximumPinRetries                              = 5
        simplePinBlocked                               = $true
        minimumPinLength                               = 6
        disableAppPinIfDevicePinIsSet                  = $true
        contactSyncBlocked                             = $false
        printBlocked                                   = $true
        fingerprintBlocked                             = $false
        notificationRestriction                        = 'allow'
    }

    $androidPolicy = @{
        '@odata.type'        = '#microsoft.graph.androidManagedAppProtection'
        displayName          = "${NamePrefix}Android App Protection Policy"
        description          = 'BYOD app protection for Android - required for C009 (BYOD Android and iOS App Protection) "require app protection policy" grant control to be enforceable.'
        Platform             = 'Android'
        Apps                 = $androidApps
        screenCaptureBlocked = $true
    }
    foreach ($key in $commonSettings.Keys) { $androidPolicy[$key] = $commonSettings[$key] }

    $iosPolicy = @{
        '@odata.type'              = '#microsoft.graph.iosManagedAppProtection'
        displayName                = "${NamePrefix}iOS App Protection Policy"
        description                = 'BYOD app protection for iOS - required for C009 (BYOD Android and iOS App Protection) "require app protection policy" grant control to be enforceable.'
        Platform                   = 'iOS'
        Apps                       = $iosApps
        faceIdBlocked              = $false
        thirdPartyKeyboardsBlocked = $true
    }
    foreach ($key in $commonSettings.Keys) { $iosPolicy[$key] = $commonSettings[$key] }

    return @($androidPolicy, $iosPolicy)
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
    Write-Host "  PREVIEW: App Protection Policies" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  The following $($Policies.Count) app protection policies will be created:" -ForegroundColor White
    Write-Host ""

    Write-Host "  # | Policy Name                      | Platform | Apps" -ForegroundColor Yellow
    Write-Host "  --|-----------------------------------|----------|------" -ForegroundColor Gray

    $index = 1
    foreach ($policy in $Policies) {
        $name = $policy.displayName
        if ($name.Length -gt 33) { $name = $name.Substring(0, 30) + "..." }
        Write-Host ("  {0,2} | {1,-33} | {2,-8} | {3}" -f $index, $name, $policy.Platform, $policy.Apps.Count) -ForegroundColor White
        $index++
    }

    Write-Host ""
    Write-Host "  All policies will:" -ForegroundColor Yellow
    Write-Host "    - Be assigned to All Users" -ForegroundColor Gray
    if ($NoMfaGroupId) {
        Write-Host "    - Exclude the NoMFA Exclusion Group (break-glass accounts)" -ForegroundColor Gray
    }
    else {
        Write-Host "    - Have NO break-glass exclusion (NoMFA Exclusion Group not found)" -ForegroundColor Red
    }
    Write-Host "    - Require an app-level PIN and block backup/save-as/print" -ForegroundColor Gray
    Write-Host ""
}

# ============================================================================
# POLICY CREATION
# ============================================================================

function New-AppProtectionPolicy {
    param(
        [hashtable]$PolicyDefinition,
        [string]$NoMfaGroupId
    )

    $policyName = $PolicyDefinition.displayName
    $endpoint = if ($PolicyDefinition.Platform -eq 'Android') { 'androidManagedAppProtections' } else { 'iosManagedAppProtections' }
    $baseUri = "https://graph.microsoft.com/beta/deviceAppManagement/$endpoint"

    try {
        $existingPolicies = Invoke-MgGraphRequest -Uri $baseUri -Method GET -ErrorAction Stop
        $existingPolicy = $existingPolicies.value | Where-Object { $_.displayName -eq $policyName }

        # Clean policy definition - strip our own bookkeeping keys (Platform,
        # Apps) plus any server-managed fields before sending to Graph
        $cleanPolicy = $PolicyDefinition.Clone()
        $fieldsToRemove = @('Platform', 'Apps', 'id', 'createdDateTime', 'lastModifiedDateTime', 'version', '@odata.context')
        foreach ($field in $fieldsToRemove) {
            if ($cleanPolicy.ContainsKey($field)) { $cleanPolicy.Remove($field) }
        }

        $policyId = $null
        $skipped = $false
        if ($existingPolicy) {
            # Reconcile settings on an already-existing policy so a repo
            # change actually reaches tenants that already had it created —
            # same convention as Compliance-Policies.ps1's New-CompliancePolicy.
            # Assignment is deliberately left untouched.
            try {
                $null = Invoke-MgGraphRequest -Uri "$baseUri('$($existingPolicy.id)')" -Method PATCH -Body ($cleanPolicy | ConvertTo-Json -Depth 20) -ErrorAction Stop
                Write-Host "     Already exists - settings reconciled (assignment unchanged)" -ForegroundColor Yellow
            }
            catch {
                Write-Host "     Already exists - could not reconcile settings: $($_.Exception.Message)" -ForegroundColor Yellow
            }
            $policyId = $existingPolicy.id
            $skipped = $true
        }
        else {
            $newPolicy = Invoke-MgGraphRequest -Uri $baseUri -Method POST -Body ($cleanPolicy | ConvertTo-Json -Depth 20) -ErrorAction Stop
            Write-Host "     Created successfully (ID: $($newPolicy.id))" -ForegroundColor Green
            $policyId = $newPolicy.id
        }

        # Reconcile targeted apps every run (idempotent replace) - which apps
        # a policy protects is treated as a setting, same as everything else
        if ($PolicyDefinition.Apps.Count -gt 0) {
            try {
                $targetAppsBody = @{ apps = @($PolicyDefinition.Apps) } | ConvertTo-Json -Depth 10
                $null = Invoke-MgGraphRequest -Uri "$baseUri('$policyId')/targetApps" -Method POST -Body $targetAppsBody -ErrorAction Stop
                Write-Host "     Targeted $($PolicyDefinition.Apps.Count) app(s)" -ForegroundColor Green
            }
            catch {
                Write-Host "     Failed to target apps: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }

        if (!$skipped) {
            # Assign: All Users, excluding the NoMFA Exclusion Group if it exists.
            # Each assignment entry needs its own @odata.type discriminator
            # (targetedManagedAppPolicyAssignment) - Graph rejects the request
            # with a bare 400 if it's left off, since assignments is a
            # polymorphic collection (confirmed live).
            $assignments = @(@{
                '@odata.type' = '#microsoft.graph.targetedManagedAppPolicyAssignment'
                target        = @{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' }
            })
            if ($NoMfaGroupId) {
                $assignments += @{
                    '@odata.type' = '#microsoft.graph.targetedManagedAppPolicyAssignment'
                    target        = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = $NoMfaGroupId }
                }
            }
            try {
                $null = Invoke-MgGraphRequest -Uri "$baseUri('$policyId')/assign" -Method POST -Body (@{ assignments = $assignments } | ConvertTo-Json -Depth 10) -ErrorAction Stop
                Write-Host "     Assigned to All Users$(if ($NoMfaGroupId) { ' (NoMFA Exclusion Group excluded)' })" -ForegroundColor Green
            }
            catch {
                # Guard with -and, not just `if ($_.ErrorDetails.Message)` -
                # dot access on a $null ErrorDetails throws under
                # Set-StrictMode (confirmed live: Invoke-MgGraphRequest's
                # exception here has a $null ErrorDetails, not merely one
                # with an empty Message). The inner catch must not reference
                # $_ either - it would be rebound to the ConvertFrom-Json
                # failure, not the original request exception.
                $errorMessage = $_.Exception.Message
                if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                    try {
                        $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json
                        if ($errorDetails.error.message) { $errorMessage = "$errorMessage - $($errorDetails.error.message)" }
                    }
                    catch { }
                }
                elseif ($_.Exception.InnerException) {
                    $errorMessage = "$errorMessage - inner: $($_.Exception.InnerException.Message)"
                }
                Write-Host "     Assignment failed: $errorMessage" -ForegroundColor Yellow
            }
        }

        return @{ Success = $true; PolicyId = $policyId; Skipped = $skipped }
    }
    catch {
        Write-Host "     Failed: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-AppProtectionPolicyCreation {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  INTUNE APP PROTECTION POLICIES" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Creates Android/iOS MAM policies for BYOD app protection" -ForegroundColor Gray
    Write-Host ""

    # Step 1: Prerequisites
    Write-Host "  STEP 1: Prerequisites" -ForegroundColor Yellow
    $prereqResult = Test-Prerequisites
    if (!$prereqResult.Success) {
        Write-Host ""
        Write-Host "  Prerequisites not met. Please resolve issues and try again." -ForegroundColor Red
        if ($ResultPath) {
            @{ Success = $false; Error = 'Prerequisites not met' } | ConvertTo-Json | Set-Content -Path $ResultPath -Encoding UTF8
        }
        if (!$script:NonInteractive) {
            Write-Host ""
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        }
        return
    }
    $noMfaGroupId = $prereqResult.NoMfaGroupId

    # Step 2: Load data
    Write-Host "  STEP 2: Loading Data" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 40) -ForegroundColor Gray

    $tenantInfo = Get-TenantInfo
    if (!$tenantInfo) {
        Write-Host "   Failed to get tenant information" -ForegroundColor Red
        if ($ResultPath) {
            @{ Success = $false; Error = 'Failed to get tenant information' } | ConvertTo-Json | Set-Content -Path $ResultPath -Encoding UTF8
        }
        if (!$script:NonInteractive) {
            Write-Host ""
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        }
        return
    }
    Write-Host "   Tenant: $($tenantInfo.OrganizationName)" -ForegroundColor Green

    $policies = Get-PolicyDefinitions -NamePrefix $script:RunConfig.NamePrefix
    Write-Host "   Loaded $($policies.Count) policy definitions" -ForegroundColor Green

    # Step 3: Preview
    Write-Host ""
    Write-Host "  STEP 3: Preview" -ForegroundColor Yellow
    Show-PolicyPreview -Policies $policies -NoMfaGroupId $noMfaGroupId

    # Confirmation (skipped in unattended mode)
    if ($script:NonInteractive) {
        Write-Host "  Non-interactive mode: proceeding without confirmation" -ForegroundColor Gray
    }
    else {
        Write-Host "  [Y] Proceed with creation  [N] Cancel" -ForegroundColor Gray
        Write-Host ""
        $confirm = Read-Host "  Create these app protection policies? (Y/N)"

        if ($confirm -notlike "Y*") {
            Write-Host ""
            Write-Host "  Cancelled by user" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
            return
        }
    }

    # Step 4: Execute
    Write-Host ""
    Write-Host "  STEP 4: Creating Policies" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 40) -ForegroundColor Gray

    $results = @{
        Created = @()
        Skipped = @()
        Failed  = @()
    }

    foreach ($policy in $policies) {
        Write-Host "   $($policy.displayName)..." -ForegroundColor White

        $result = New-AppProtectionPolicy -PolicyDefinition $policy -NoMfaGroupId $noMfaGroupId

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

    if (!$noMfaGroupId) {
        Write-Host "  IMPORTANT:" -ForegroundColor Red
        Write-Host "    - No NoMFA Exclusion Group found - policies apply to ALL users with no break-glass exclusion" -ForegroundColor Yellow
        Write-Host "    - Create the group and re-run this script to add the exclusion" -ForegroundColor Yellow
        Write-Host ""
    }

    Write-Host "  Next Steps:" -ForegroundColor Yellow
    Write-Host "    1. Verify policies in Intune admin center (Apps > App protection policies)" -ForegroundColor Gray
    Write-Host "    2. Run entra/CA-Policies.ps1 if C009 (BYOD Android and iOS App Protection) isn't created yet" -ForegroundColor Gray
    Write-Host "    3. Test on a pilot Android/iOS device enrolled in company portal" -ForegroundColor Gray
    Write-Host ""

    # Machine-readable results for CI runners
    if ($ResultPath) {
        @{
            Success = ($results.Failed.Count -eq 0)
            Created = @($results.Created)
            Skipped = @($results.Skipped)
            Failed  = @($results.Failed)
        } | ConvertTo-Json -Depth 5 | Set-Content -Path $ResultPath -Encoding UTF8
        Write-Host "  Results written to $ResultPath" -ForegroundColor Gray
    }

    if (!$script:NonInteractive) {
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
    }
}

# ============================================================================
# ENTRY POINT
# ============================================================================

try {
    if (!(Initialize-ScriptModules)) {
        Write-Host "Failed to initialize required modules. Exiting." -ForegroundColor Red
        return
    }

    Start-AppProtectionPolicyCreation
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
}
