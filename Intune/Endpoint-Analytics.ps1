#Requires -Version 7.0

<#
.SYNOPSIS
    Enables the device/app performance data Endpoint analytics needs to report on
.DESCRIPTION
    Endpoint analytics (Startup Performance, Device/App reliability, Resource
    Performance) has no API "on" switch of its own — the reports populate once
    enrolled Windows devices are reporting diagnostic data at the right level.
    This script deploys the one Settings Catalog policy that unlocks it:
      - Diagnostic data level -> Required (minimum level Endpoint analytics reads)
      - Allow device name in diagnostic data -> Enabled (devices show by name in
        the reports instead of an anonymous GUID)
    and assigns it to the same device group the other Intune policies use.
.AUTHOR
    BITS
.VERSION
    1.0
.PARAMETER NonInteractive
    Run unattended: skip the Y/N confirmation and all "press any key" pauses.
    Used by CI E2E tests.
.PARAMETER ConfigFile
    Optional JSON file overriding run behaviour. Supported keys:
      NamePrefix      (string) prefixed to the policy's name, e.g. "E2E-" —
                      lets E2E tests create/verify/delete only a throwaway
                      prefixed policy
      GroupNamePrefix (string) prefixed to the device group name this script
                      assigns the policy to — lets E2E tests point at a
                      throwaway prefixed group created by a prior
                      Device-Groups E2E run
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

$script:PolicyName = "$($script:RunConfig.NamePrefix)Endpoint Analytics - Diagnostic Data"
$script:TargetGroupName = "$($script:RunConfig.GroupNamePrefix)Windows Devices (Autopilot)"

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

# Windows Policy CSP System/AllowTelemetry: 0=Security, 1=Required(Basic),
# 3=Optional(Full) — level 2 (Enhanced) is deprecated on current Windows
# builds. Endpoint analytics needs at least Required; Optional additionally
# unlocks App Reliability / Resource Performance (public preview).
function Get-EndpointAnalyticsPolicyDefinition {
    return @{
        name        = $script:PolicyName
        description = 'Sets Windows diagnostic data to the minimum level Endpoint analytics (Reports > Endpoint analytics) needs to populate Startup Performance and Work From Anywhere scores, and enables device names in that data so devices show by name instead of GUID.'
        platforms   = 'windows10'
        technologies = 'mdm'
        templateReference = @{
            templateId          = ''
            templateDisplayName = $null
            templateFamily      = 'none'
            templateDisplayVersion = $null
        }
        settings = @(
            @{
                id = '0'
                settingInstance = @{
                    '@odata.type'      = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                    settingDefinitionId = 'device_vendor_msft_policy_config_system_allowtelemetry'
                    settingInstanceTemplateReference = $null
                    choiceSettingValue = @{
                        value = 'device_vendor_msft_policy_config_system_allowtelemetry_1'
                        children = @()
                        settingValueTemplateReference = $null
                    }
                }
            },
            @{
                id = '1'
                settingInstance = @{
                    '@odata.type'      = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                    settingDefinitionId = 'device_vendor_msft_policy_config_system_allowdevicenameindiagnosticdata'
                    settingInstanceTemplateReference = $null
                    choiceSettingValue = @{
                        value = 'device_vendor_msft_policy_config_system_allowdevicenameindiagnosticdata_1'
                        children = @()
                        settingValueTemplateReference = $null
                    }
                }
            }
        )
    }
}

function Get-TenantInfo {
    try {
        $org = Get-MgOrganization | Select-Object -First 1
        return @{
            TenantId         = $org.Id
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
    Write-Host ''
    Write-Host '   PREREQUISITES CHECK' -ForegroundColor Yellow
    Write-Host ('   ' + ('-' * 50)) -ForegroundColor Gray

    Write-Host '   Checking Microsoft Graph connection...' -ForegroundColor Gray
    $context = Get-MgContext
    if (!$context) {
        Write-Host '   Not connected to Microsoft Graph' -ForegroundColor Red
        Write-Host '   Please connect using the main menu first' -ForegroundColor Yellow
        return @{ Success = $false }
    }
    Write-Host "   Connected as: $($context.Account)" -ForegroundColor Green

    Write-Host '   Checking required permissions...' -ForegroundColor Gray
    # @() wrap: Where-Object returns $null when nothing matches and a bare scalar
    # (no .Count) when exactly one item matches — either case throws under
    # Set-StrictMode
    $missingScopes = @($RequiredScopes | Where-Object { $_ -notin $context.Scopes })

    if ($missingScopes.Count -gt 0) {
        if ($context.AuthType -eq 'AppOnly' -or $script:NonInteractive) {
            Write-Host "   Missing scopes (continuing unattended): $($missingScopes -join ', ')" -ForegroundColor Yellow
        }
        else {
            Write-Host "   Missing scopes: $($missingScopes -join ', ')" -ForegroundColor Yellow
            Write-Host '   Requesting additional permissions...' -ForegroundColor Yellow
            try {
                $allScopes = ($context.Scopes + $missingScopes) | Select-Object -Unique
                Connect-MgGraph -Scopes $allScopes -NoWelcome -ErrorAction Stop
                Write-Host '   Permissions updated' -ForegroundColor Green
            }
            catch {
                Write-Host "   Could not get required permissions: $($_.Exception.Message)" -ForegroundColor Red
                return @{ Success = $false }
            }
        }
    }
    else {
        Write-Host '   All required permissions present' -ForegroundColor Green
    }

    Write-Host '   Getting tenant information...' -ForegroundColor Gray
    $tenantInfo = Get-TenantInfo
    if (!$tenantInfo) {
        Write-Host '   Failed to get tenant information' -ForegroundColor Red
        return @{ Success = $false }
    }
    Write-Host "   Tenant: $($tenantInfo.OrganizationName)" -ForegroundColor Green

    Write-Host '   Checking device group...' -ForegroundColor Gray
    $group = Get-MgGroup -Filter "displayName eq '$script:TargetGroupName'" -ErrorAction SilentlyContinue
    if (!$group) {
        Write-Host "   Missing group: $script:TargetGroupName" -ForegroundColor Yellow
        Write-Host '   Run Device Groups script first' -ForegroundColor Yellow
    }
    else {
        Write-Host '   Device group found' -ForegroundColor Green
    }

    Write-Host ''
    return @{
        Success    = $true
        TenantInfo = $tenantInfo
        GroupId    = if ($group) { $group.Id } else { $null }
    }
}

# ============================================================================
# PREVIEW MODE
# ============================================================================

function Show-PolicyPreview {
    param([hashtable]$TenantInfo, [bool]$GroupFound)

    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host '  PREVIEW: Endpoint Analytics - Diagnostic Data' -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host ''
    Write-Host "  Tenant: $($TenantInfo.OrganizationName)" -ForegroundColor White
    Write-Host ''
    Write-Host '  Settings Catalog policy to be created:' -ForegroundColor White
    Write-Host "    Name: $script:PolicyName" -ForegroundColor Gray
    Write-Host '    - Diagnostic data: Required (Basic)' -ForegroundColor Gray
    Write-Host '    - Allow device name in diagnostic data: Enabled' -ForegroundColor Gray
    Write-Host ''
    Write-Host "  Assignment: $script:TargetGroupName $(if (!$GroupFound) { '(NOT FOUND — assignment will be skipped)' })" -ForegroundColor $(if ($GroupFound) { 'White' } else { 'Yellow' })
    Write-Host ''
}

# ============================================================================
# POLICY CREATION
# ============================================================================

function New-EndpointAnalyticsPolicy {
    param([string]$GroupId)

    # Every return path sets Error (to $null on success) so the caller's
    # $result.Error works under Set-StrictMode -Version Latest (used by the
    # E2E harness) — a hashtable missing a key throws there, it doesn't just
    # return $null (confirmed live).
    try {
        $existingPolicies = Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies' -Method GET
        $existingPolicy = $existingPolicies.value | Where-Object { $_.name -eq $script:PolicyName }

        if ($existingPolicy) {
            Write-Host '     Already exists (skipped)' -ForegroundColor Yellow
            return @{ Success = $true; Skipped = $true; Policy = $existingPolicy; Error = $null }
        }

        $policyDefinition = Get-EndpointAnalyticsPolicyDefinition
        $newPolicy = Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies' -Method POST -Body ($policyDefinition | ConvertTo-Json -Depth 20)

        if ($GroupId) {
            $assignmentBody = @{
                assignments = @(
                    @{
                        target = @{
                            '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                            groupId       = $GroupId
                        }
                    }
                )
            }
            $null = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($newPolicy.id)')/assign" -Method POST -Body ($assignmentBody | ConvertTo-Json -Depth 10)
        }

        Write-Host "     Created (ID: $($newPolicy.id))" -ForegroundColor Green
        return @{ Success = $true; Skipped = $false; Policy = $newPolicy; Error = $null }
    }
    catch {
        $errorMessage = $_.Exception.Message
        # Capture ErrorDetails.Message into a local variable first — $_ inside the
        # nested catch below refers to the ConvertFrom-Json failure, not this outer
        # exception, so referencing $_.ErrorDetails there throws under strict mode
        # (confirmed live, see Configuration-Policies.ps1).
        $rawDetails = $_.ErrorDetails.Message
        if ($rawDetails) {
            try {
                $errorDetails = $rawDetails | ConvertFrom-Json
                if ($errorDetails.error.message) {
                    $errorMessage = "$errorMessage - $($errorDetails.error.message)"
                }
                else {
                    $errorMessage = "$errorMessage - RAW: $rawDetails"
                }
            }
            catch {
                $errorMessage = "$errorMessage - RAW(unparsed): $rawDetails"
            }
        }
        Write-Host "     Failed: $errorMessage" -ForegroundColor Red
        return @{ Success = $false; Error = $errorMessage }
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-EndpointAnalyticsSetup {
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host '  ENDPOINT ANALYTICS' -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host '  Deploys the diagnostic data policy Endpoint analytics needs' -ForegroundColor Gray
    Write-Host ''

    Write-Host '  STEP 1: Prerequisites' -ForegroundColor Yellow
    $prereqResult = Test-Prerequisites

    if (!$prereqResult.Success) {
        Write-Host ''
        Write-Host '  Prerequisites not met. Please resolve issues and try again.' -ForegroundColor Red
        if ($ResultPath) {
            @{ Success = $false; Error = 'Prerequisites not met' } | ConvertTo-Json | Set-Content -Path $ResultPath -Encoding UTF8
        }
        if (!$script:NonInteractive) {
            Write-Host ''
            Write-Host '  Press any key to return to menu...' -ForegroundColor Gray
            try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { Start-Sleep -Seconds 2 }
        }
        return
    }

    Write-Host ''
    Write-Host '  STEP 2: Preview' -ForegroundColor Yellow
    Show-PolicyPreview -TenantInfo $prereqResult.TenantInfo -GroupFound ([bool]$prereqResult.GroupId)

    if ($script:NonInteractive) {
        Write-Host '  Non-interactive mode: proceeding without confirmation' -ForegroundColor Gray
    }
    else {
        Write-Host '  [Y] Proceed with creation  [N] Cancel' -ForegroundColor Gray
        Write-Host ''
        $confirm = Read-Host '  Create this policy? (Y/N)'
        if ($confirm -notlike 'Y*') {
            Write-Host ''
            Write-Host '  Cancelled by user' -ForegroundColor Yellow
            Write-Host ''
            Write-Host '  Press any key to return to menu...' -ForegroundColor Gray
            try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { Start-Sleep -Seconds 2 }
            return
        }
    }

    Write-Host ''
    Write-Host '  STEP 3: Creating Policy' -ForegroundColor Yellow
    Write-Host ('   ' + ('-' * 50)) -ForegroundColor Gray
    Write-Host "   $script:PolicyName..." -ForegroundColor White

    $result = New-EndpointAnalyticsPolicy -GroupId $prereqResult.GroupId

    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host '  SUMMARY' -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host ''

    if ($result.Success) {
        Write-Host "  $(if ($result.Skipped) { 'Already existed' } else { 'Created' }): $script:PolicyName" -ForegroundColor Green
    }
    else {
        Write-Host "  Failed: $($result.Error)" -ForegroundColor Red
    }
    Write-Host ''

    Write-Host '  What happens next (no further setup needed):' -ForegroundColor Yellow
    Write-Host '    - Startup Performance and Work From Anywhere scores populate' -ForegroundColor Gray
    Write-Host '      automatically once enrolled devices sync this policy and report' -ForegroundColor Gray
    Write-Host '      in (Reports > Endpoint analytics), usually within 24-48 hours.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  Still manual — cannot be automated via this script:' -ForegroundColor Yellow
    Write-Host '    - App Reliability / Resource Performance (public preview): requires' -ForegroundColor Gray
    Write-Host '      connecting an Azure Log Analytics workspace in Endpoint analytics >' -ForegroundColor Gray
    Write-Host '      Settings > Data Collection (billable Azure resource).' -ForegroundColor Gray
    Write-Host '    - Baseline regression: needs a nominated baseline device group' -ForegroundColor Gray
    Write-Host '      chosen manually once enough devices have reported data.' -ForegroundColor Gray
    Write-Host '    - Proactive remediations: create script pairs separately under' -ForegroundColor Gray
    Write-Host '      Reports > Endpoint analytics > Proactive remediations.' -ForegroundColor Gray
    Write-Host ''

    if ($ResultPath) {
        @{
            Success = $result.Success
            Skipped = [bool]$result.Skipped
            Error   = $result.Error
        } | ConvertTo-Json -Depth 5 | Set-Content -Path $ResultPath -Encoding UTF8
        Write-Host "  Results written to $ResultPath" -ForegroundColor Gray
    }

    if (!$script:NonInteractive) {
        Write-Host ''
        Write-Host '  Press any key to return to menu...' -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { Start-Sleep -Seconds 2 }
    }
}

# ============================================================================
# ENTRY POINT
# ============================================================================

try {
    if (!(Initialize-ScriptModules)) {
        Write-Host 'Failed to initialize required modules. Exiting.' -ForegroundColor Red
        return
    }

    Start-EndpointAnalyticsSetup
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
}
