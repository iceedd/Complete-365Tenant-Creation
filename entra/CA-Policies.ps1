#Requires -Version 7.0

<#
.SYNOPSIS
    Creates Conditional Access policies for fresh tenant security
.DESCRIPTION
    Disables Security Defaults and creates comprehensive CA policies with proper exclusions.
    Includes auto-fix for prerequisites like Security Defaults and missing groups.
.AUTHOR
    BITS
.VERSION
    2.4 - Per-policy enforcement mode: the operator (or -ConfigFile) now
          chooses Report-only vs Enabled independently for each CA policy,
          instead of one global mode applied to all of them. PolicyMode
          remains as the default for any policy without its own override.
    2.3 - Fix C004: retarget from high to medium user risk. C001 already
          blocks high user risk outright, and a block from any applicable CA
          policy always wins over other policies' grant controls, so a
          second high-user-risk policy was dead code — it could never be
          reached.
    2.2 - Auto-create the UK named location when the CA-GEO groups exist (so
          C007 geo-blocking is actually provisioned instead of silently
          skipped) and add C008 - Block Device Code Flow.
    2.1 - Non-interactive mode (-NonInteractive/-ConfigFile) for unattended
          E2E testing. 2.0 standardized UX with preview mode and auto-fix.
.PARAMETER NonInteractive
    Run unattended: skip all Y/N confirmations and "press any key" pauses,
    never attempt interactive re-consent, and never prompt for each policy's
    enforcement mode (uses the ConfigFile's PolicyModes/PolicyMode instead).
    Used by CI E2E tests.
.PARAMETER ConfigFile
    Optional JSON file overriding run behaviour. Supported keys:
      NamePrefix                  (string) prefixed to every policy displayName
      GroupNamePrefix             (string) prefixed to the group names this
                                   script looks up (NoMFA Exclusion Group,
                                   CA-GEO-UK, CA-GEO-International)
      PolicyMode                  ("ReportOnly"|"Enabled") default ReportOnly —
                                   the fallback used for any policy not given
                                   its own entry in PolicyModes below. E2E
                                   tests must never use Enabled: most policies
                                   target "All" users in a shared tenant, so
                                   Enabled would actually enforce block/MFA
                                   rules for real traffic
      PolicyModes                 (object) optional per-policy override, keyed
                                   by policy code, e.g.
                                   { "C001": "Enabled", "C004": "ReportOnly" }.
                                   Policies not listed here use PolicyMode.
      AutoDisableSecurityDefaults (bool) default true — required to make any
                                   progress, since CA policies cannot be
                                   created while Security Defaults is enabled
      AutoCreateNoMfaGroup        (bool) default true
.PARAMETER ResultPath
    Optional path to write a JSON results summary (created/skipped/failed),
    so a CI runner can assert on the outcome.
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
    NamePrefix                  = ''
    GroupNamePrefix             = ''
    PolicyMode                  = 'ReportOnly'
    PolicyModes                 = @{}
    AutoDisableSecurityDefaults = $true
    AutoCreateNoMfaGroup        = $true
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
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Groups'
)

$RequiredScopes = @(
    "Policy.ReadWrite.ConditionalAccess",
    "Policy.ReadWrite.SecurityDefaults",
    "Group.ReadWrite.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory"
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
# PREREQUISITES WITH AUTO-FIX
# ============================================================================

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Verify all prerequisites and offer to auto-fix issues
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
    # @() wrap: Where-Object returns $null when nothing matches and a bare scalar
    # (no .Count) when exactly one item matches — either case throws under
    # Set-StrictMode, which the E2E test harness enables
    $missingScopes = @($RequiredScopes | Where-Object { $_ -notin $context.Scopes })

    if ($missingScopes.Count -gt 0) {
        # App-only tokens carry fixed app-role permissions and unattended runs
        # can't consent interactively — warn and continue; individual operations
        # that lack permission will fail with their own clear errors.
        if ($context.AuthType -eq 'AppOnly' -or $script:NonInteractive) {
            Write-Host "   Missing scopes (continuing unattended): $($missingScopes -join ', ')" -ForegroundColor Yellow
        }
        else {
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
    }
    else {
        Write-Host "   All required permissions present" -ForegroundColor Green
    }

    # Check Security Defaults status
    Write-Host "   Checking Security Defaults status..." -ForegroundColor Gray
    $securityDefaultsResult = Test-SecurityDefaults

    if (!$securityDefaultsResult.Success) {
        return @{ Success = $false }
    }

    # Check for NoMFA Exclusion Group
    Write-Host "   Checking for NoMFA Exclusion Group..." -ForegroundColor Gray
    $noMfaGroupResult = Test-NoMfaGroup

    if (!$noMfaGroupResult.Success) {
        return @{ Success = $false }
    }

    # Check for geo-based CA groups (optional — C007 skipped if missing)
    Write-Host "   Checking for geo-based CA groups (optional)..." -ForegroundColor Gray
    $groupPrefix = $script:RunConfig.GroupNamePrefix
    $geoUkGroup = Get-MgGroup -Filter "displayName eq '${groupPrefix}CA-GEO-UK'" -ErrorAction SilentlyContinue
    $geoIntlGroup = Get-MgGroup -Filter "displayName eq '${groupPrefix}CA-GEO-International'" -ErrorAction SilentlyContinue

    if ($geoUkGroup -and $geoIntlGroup) {
        Write-Host "   CA-GEO-UK found (ID: $($geoUkGroup.Id))" -ForegroundColor Green
        Write-Host "   CA-GEO-International found (ID: $($geoIntlGroup.Id))" -ForegroundColor Green
    }
    else {
        Write-Host "   Geo groups not found - C007 (Block Outside UK) will be skipped" -ForegroundColor Yellow
    }

    # Check for UK named location — created automatically when the geo groups
    # exist but the location doesn't, so C007 no longer silently depends on a
    # manual prerequisite. Prefix-aware so E2E runs create/clean "E2E-UK"
    # while production (empty prefix) gets "UK".
    Write-Host "   Checking for UK named location..." -ForegroundColor Gray
    $locationName = "$($script:RunConfig.NamePrefix)UK"
    $ukLocation = $null
    try {
        $locations = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" `
            -ErrorAction Stop
        $ukLocation = $locations.value | Where-Object { $_.displayName -eq $locationName } | Select-Object -First 1
    }
    catch { }

    if ($ukLocation) {
        Write-Host "   UK named location found (ID: $($ukLocation.id))" -ForegroundColor Green
    }
    elseif ($geoUkGroup -and $geoIntlGroup) {
        Write-Host "   Creating named location '$locationName' (United Kingdom)..." -ForegroundColor Gray
        try {
            $ukLocation = Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" `
                -ContentType 'application/json' `
                -Body (@{
                    '@odata.type'                     = '#microsoft.graph.countryNamedLocation'
                    displayName                       = $locationName
                    countriesAndRegions               = @('GB')
                    includeUnknownCountriesAndRegions = $false
                } | ConvertTo-Json) -ErrorAction Stop
            Write-Host "   Created named location '$locationName' (ID: $($ukLocation.id))" -ForegroundColor Green
        }
        catch {
            Write-Host "   Could not create named location: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "   C007 will be skipped" -ForegroundColor Yellow
            $ukLocation = $null
        }
    }
    else {
        Write-Host "   Geo groups absent - named location not needed, C007 will be skipped" -ForegroundColor Yellow
    }

    Write-Host ""
    # Explicit if/else rather than ?. — under Set-StrictMode (as the E2E test
    # harness enables), $geoUkGroup?.Id is parsed as a variable literally named
    # "geoUkGroup?", which was never set, and throws instead of returning $null
    return @{
        Success                  = $true
        NoMfaGroupId             = $noMfaGroupResult.GroupId
        SecurityDefaultsDisabled = $securityDefaultsResult.IsDisabled
        GeoUkGroupId             = if ($geoUkGroup) { $geoUkGroup.Id } else { $null }
        GeoIntlGroupId           = if ($geoIntlGroup) { $geoIntlGroup.Id } else { $null }
        UkLocationId             = if ($ukLocation) { $ukLocation.id } else { $null }
    }
}

function Test-SecurityDefaults {
    <#
    .SYNOPSIS
        Check Security Defaults and offer to disable if enabled
    #>

    try {
        $policy = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop

        if ($policy.IsEnabled -eq $true) {
            Write-Host "   Security Defaults is ENABLED" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "   Conditional Access policies CANNOT be created while Security Defaults is enabled." -ForegroundColor Yellow
            Write-Host "   Security Defaults must be disabled first." -ForegroundColor Yellow
            Write-Host ""

            if ($script:NonInteractive) {
                if (!$script:RunConfig.AutoDisableSecurityDefaults) {
                    Write-Host "   AutoDisableSecurityDefaults is false - cannot proceed" -ForegroundColor Yellow
                    return @{ Success = $false; IsDisabled = $false }
                }
                Write-Host "   Non-interactive mode: disabling Security Defaults automatically" -ForegroundColor Gray
            }
            else {
                Write-Host "   [Y] Disable Security Defaults now  [N] Cancel" -ForegroundColor Gray
                $confirm = Read-Host "   Disable Security Defaults? (Y/N)"

                if ($confirm -notlike "Y*") {
                    Write-Host "   Cancelled - Security Defaults remains enabled" -ForegroundColor Yellow
                    return @{ Success = $false; IsDisabled = $false }
                }
            }

            # Disable Security Defaults via REST (more reliable than cmdlet)
            Write-Host "   Disabling Security Defaults..." -ForegroundColor Yellow
            $null = Invoke-MgGraphRequest -Method PATCH `
                -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy" `
                -Body (@{ isEnabled = $false } | ConvertTo-Json) `
                -ErrorAction Stop

            # Verify with retry - Graph API changes can take a few seconds to propagate
            $verified = $false
            for ($i = 1; $i -le 5; $i++) {
                Start-Sleep -Seconds 3
                $verification = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
                if ($verification.isEnabled -eq $false) {
                    $verified = $true
                    break
                }
                Write-Host "   Waiting for change to propagate... ($i/5)" -ForegroundColor Gray
            }

            if ($verified) {
                Write-Host "   Security Defaults disabled successfully" -ForegroundColor Green
                return @{ Success = $true; IsDisabled = $true }
            }
            else {
                # Update was sent - proceed even if verification timed out
                Write-Host "   Security Defaults update sent - proceeding" -ForegroundColor Yellow
                return @{ Success = $true; IsDisabled = $true }
            }
        }
        else {
            Write-Host "   Security Defaults already disabled" -ForegroundColor Green
            return @{ Success = $true; IsDisabled = $true }
        }
    }
    catch {
        Write-Host "   Error checking Security Defaults: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "   Try manual disable: Entra admin center > Identity > Overview > Properties" -ForegroundColor Yellow
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Test-NoMfaGroup {
    <#
    .SYNOPSIS
        Check for NoMFA Exclusion Group and offer to create if missing
    #>

    try {
        $groupPrefix = $script:RunConfig.GroupNamePrefix
        $groupName = "${groupPrefix}NoMFA Exclusion Group"
        $group = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue

        if ($group) {
            Write-Host "   $groupName found (ID: $($group.Id))" -ForegroundColor Green
            return @{ Success = $true; GroupId = $group.Id }
        }

        # Group doesn't exist - offer to create
        Write-Host "   $groupName not found" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "   This group is required to exclude break-glass accounts from MFA policies." -ForegroundColor Yellow
        Write-Host ""

        if ($script:NonInteractive) {
            if (!$script:RunConfig.AutoCreateNoMfaGroup) {
                Write-Host "   AutoCreateNoMfaGroup is false - cannot proceed" -ForegroundColor Yellow
                return @{ Success = $false }
            }
            Write-Host "   Non-interactive mode: creating $groupName automatically" -ForegroundColor Gray
        }
        else {
            Write-Host "   [Y] Create $groupName now  [N] Cancel" -ForegroundColor Gray
            $confirm = Read-Host "   Create the group? (Y/N)"

            if ($confirm -notlike "Y*") {
                Write-Host "   Cancelled - run Security Groups script first" -ForegroundColor Yellow
                return @{ Success = $false }
            }
        }

        # Create the group
        Write-Host "   Creating $groupName..." -ForegroundColor Yellow

        $groupParams = @{
            DisplayName = $groupName
            Description = "Members excluded from MFA requirements - USE FOR BREAK-GLASS ACCOUNTS ONLY"
            MailEnabled = $false
            MailNickname = ($groupName -replace '[^a-zA-Z0-9]', '')
            SecurityEnabled = $true
        }

        $newGroup = New-MgGroup -BodyParameter $groupParams -ErrorAction Stop
        Write-Host "   Created $groupName (ID: $($newGroup.Id))" -ForegroundColor Green
        Write-Host "   IMPORTANT: Add break-glass accounts to this group!" -ForegroundColor Yellow

        return @{ Success = $true; GroupId = $newGroup.Id; Created = $true }
    }
    catch {
        Write-Host "   Error with NoMFA group: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ============================================================================
# DATA FUNCTIONS
# ============================================================================

function Get-TenantInfo {
    try {
        $org = Get-MgOrganization | Select-Object -First 1
        $domain = $org.VerifiedDomains | Where-Object { $_.IsDefault -eq $true } | Select-Object -ExpandProperty Name
        $companyInitials = ($domain -split '\.')[0].ToUpper()

        return @{
            Domain = $domain
            CompanyInitials = $companyInitials
            TenantId = $org.Id
            OrganizationName = $org.DisplayName
        }
    }
    catch {
        Write-Host "   Failed to get tenant info: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Get-PolicyDefinitions {
    param(
        [string]$NoMfaGroupId,
        [string]$PolicyState = "enabled",
        [string]$GeoUkGroupId,
        [string]$GeoIntlGroupId,
        [string]$UkLocationId
    )

    $namePrefix = $script:RunConfig.NamePrefix

    $policies = @(
        @{
            displayName = "C001 - Block High Risk Users"
            state = $PolicyState
            conditions = @{
                applications = @{ includeApplications = @("All") }
                clientAppTypes = @("all")
                userRiskLevels = @("high")
                users = @{
                    includeUsers = @("All")
                    excludeGroups = @($NoMfaGroupId)
                }
            }
            grantControls = @{
                builtInControls = @("block")
                operator = "OR"
            }
        },
        @{
            displayName = "C002 - MFA Required for All Users"
            state = $PolicyState
            conditions = @{
                applications = @{ includeApplications = @("All") }
                clientAppTypes = @("browser", "mobileAppsAndDesktopClients")
                users = @{
                    includeUsers = @("All")
                    excludeGroups = @($NoMfaGroupId)
                }
            }
            grantControls = @{
                builtInControls = @("mfa")
                operator = "OR"
            }
        },
        @{
            displayName = "C003 - Block Non Corporate Devices"
            state = $PolicyState
            conditions = @{
                applications = @{ includeApplications = @("All") }
                clientAppTypes = @("all")
                users = @{
                    includeUsers = @("All")
                    excludeGroups = @($NoMfaGroupId)
                    excludeRoles = @("d29b2b05-8046-44ba-8758-1e26182fcf32")
                }
            }
            grantControls = @{
                builtInControls = @("compliantDevice", "domainJoinedDevice")
                operator = "OR"
            }
        },
        @{
            # Medium, not high: C001 already blocks high user risk outright, and
            # since a block always wins when multiple CA policies apply, a
            # second high-user-risk policy here would never be reachable. MFA
            # alone does NOT remediate user risk (only a password change does),
            # so this pairs both — completing them clears the risk event and
            # this won't re-trigger until a genuinely new risk signal appears.
            displayName = "C004 - Require MFA and Password Change for Medium Risk Users"
            state = $PolicyState
            conditions = @{
                applications = @{ includeApplications = @("All") }
                clientAppTypes = @("all")
                userRiskLevels = @("medium")
                users = @{
                    includeUsers = @("All")
                    excludeGroups = @($NoMfaGroupId)
                }
            }
            grantControls = @{
                builtInControls = @("mfa", "passwordChange")
                operator = "AND"
            }
        },
        @{
            displayName = "C005 - Require MFA for Risky Sign-Ins"
            state = $PolicyState
            conditions = @{
                applications = @{ includeApplications = @("All") }
                clientAppTypes = @("all")
                signInRiskLevels = @("high", "medium")
                users = @{
                    includeUsers = @("All")
                    excludeGroups = @($NoMfaGroupId)
                }
            }
            grantControls = @{
                builtInControls = @("mfa")
                operator = "OR"
            }
        },
        @{
            displayName = "C006 - Block Legacy Authentication"
            state = $PolicyState
            conditions = @{
                applications = @{ includeApplications = @("All") }
                clientAppTypes = @("exchangeActiveSync", "other")
                users = @{
                    includeUsers = @("All")
                    excludeGroups = @($NoMfaGroupId)
                }
            }
            grantControls = @{
                builtInControls = @("block")
                operator = "OR"
            }
        },
        @{
            displayName = "C008 - Block Device Code Flow"
            state = $PolicyState
            conditions = @{
                applications = @{ includeApplications = @("All") }
                clientAppTypes = @("all")
                # Device code flow is a common phishing vector and legitimate
                # use is rare. Safe for this repo's own tooling: interactive
                # runs sign in via browser (never device code — verified: no
                # script uses -UseDeviceCode/-DeviceCode), and CI uses
                # app-only certificate auth, which is not a user sign-in and
                # is never evaluated by user-scoped CA policies.
                authenticationFlows = @{ transferMethods = "deviceCodeFlow" }
                users = @{
                    includeUsers = @("All")
                    excludeGroups = @($NoMfaGroupId)
                }
            }
            grantControls = @{
                builtInControls = @("block")
                operator = "OR"
            }
        }
    ) + $(
        # C007 only added if geo groups and UK named location exist in this tenant
        if ($GeoUkGroupId -and $GeoIntlGroupId -and $UkLocationId) {
            @(
                @{
                    displayName = "C007 - Block Sign-In Outside UK (UK Users)"
                    state       = $PolicyState
                    conditions  = @{
                        applications   = @{ includeApplications = @("All") }
                        clientAppTypes = @("all")
                        users          = @{
                            includeGroups = @($GeoUkGroupId)
                            excludeGroups = @($NoMfaGroupId, $GeoIntlGroupId)
                        }
                        locations      = @{
                            includeLocations = @("All")
                            excludeLocations = @($UkLocationId, "AllTrusted")
                        }
                    }
                    grantControls = @{
                        builtInControls = @("block")
                        operator        = "OR"
                    }
                }
            )
        }
        else { @() }
    )

    if ($namePrefix) {
        foreach ($policy in $policies) {
            $policy.displayName = "$namePrefix$($policy.displayName)"
        }
    }

    return $policies
}

# ============================================================================
# PER-POLICY ENFORCEMENT MODE
# ============================================================================

function Get-PolicyCode {
    <#
    .SYNOPSIS
        Extracts the short policy code (e.g. "C004") from a displayName, so
        it still matches even when NamePrefix has been prepended (the prefix
        has no fixed separator, so a fixed-position substring wouldn't work).
    #>
    param([string]$DisplayName)

    $match = [regex]::Match($DisplayName, 'C\d{3}')
    if ($match.Success) { return $match.Value }
    return $DisplayName
}

function Set-PolicyStates {
    <#
    .SYNOPSIS
        Resolves and applies an enforcement state to each policy
        individually, mutating each policy's .state in place — Report-only
        vs Enabled is no longer one global choice for the whole run.
    .DESCRIPTION
        Interactive: prompts once per policy.
        Non-interactive: reads $script:RunConfig.PolicyModes[<code>] for a
        per-policy override, falling back to the global
        $script:RunConfig.PolicyMode default for any policy without one.
    #>
    param([array]$Policies)

    foreach ($policy in $Policies) {
        if ($script:NonInteractive) {
            $code = Get-PolicyCode -DisplayName $policy.displayName
            $mode = if ($script:RunConfig.PolicyModes.ContainsKey($code)) {
                $script:RunConfig.PolicyModes[$code]
            }
            else {
                $script:RunConfig.PolicyMode
            }
            $policy.state = if ($mode -eq 'Enabled') { 'enabled' } else { 'enabledForReportingButNotEnforced' }
        }
        else {
            Write-Host ""
            Write-Host "   $($policy.displayName)" -ForegroundColor White
            Write-Host "   [1] Report-only  [2] Enabled" -ForegroundColor Gray
            $choice = Read-Host "   Select mode (1 or 2)"

            if ($choice -eq "2") {
                $policy.state = 'enabled'
                Write-Host "     -> Enabled (enforcing)" -ForegroundColor Yellow
            }
            else {
                if ($choice -ne "1") {
                    Write-Host "     Invalid selection - defaulting to Report-only for safety." -ForegroundColor Yellow
                }
                $policy.state = 'enabledForReportingButNotEnforced'
                Write-Host "     -> Report-only" -ForegroundColor Cyan
            }
        }
    }
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
    Write-Host "  PREVIEW: Conditional Access Policies" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  The following $($Policies.Count) CA policies will be created:" -ForegroundColor White
    Write-Host ""

    # Header
    Write-Host "  # | Policy Name                                  | State       | Grant" -ForegroundColor Yellow
    Write-Host "  --|----------------------------------------------|-------------|------------------" -ForegroundColor Gray

    $index = 1
    foreach ($policy in $Policies) {
        $name = $policy.displayName
        if ($name.Length -gt 44) { $name = $name.Substring(0, 41) + "..." }

        $grant = ($policy.grantControls.builtInControls -join "+")
        if ($grant.Length -gt 16) { $grant = $grant.Substring(0, 13) + "..." }

        $stateLabel = if ($policy.state -eq 'enabled') { 'Enabled' } else { 'Report-only' }
        Write-Host ("  {0,2} | {1,-44} | {2,-11} | {3}" -f $index, $name, $stateLabel, $grant) -ForegroundColor White
        $index++
    }

    Write-Host ""
    Write-Host "  All policies will:" -ForegroundColor Yellow
    Write-Host "    - Exclude NoMFA Exclusion Group (break-glass accounts)" -ForegroundColor Gray
    Write-Host "    - Be created immediately, in the mode shown above (per policy)" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  NoMFA Exclusion Group ID: $NoMfaGroupId" -ForegroundColor Gray
    Write-Host ""
}

# ============================================================================
# POLICY CREATION
# ============================================================================

function New-ConditionalAccessPolicy {
    param(
        [hashtable]$PolicyConfig,
        [string]$NoMfaGroupId
    )

    $policyName = $PolicyConfig.displayName

    try {
        # Check if policy already exists
        $existingPolicy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$policyName'" -ErrorAction SilentlyContinue

        if ($existingPolicy) {
            Write-Host "     Already exists (skipped)" -ForegroundColor Yellow
            return @{ Success = $true; Policy = $existingPolicy; Skipped = $true }
        }

        # Ensure NoMFA group is in exclusions — append rather than overwrite so
        # policies with additional exclude groups (e.g. C007's geo group) keep them
        if ($NoMfaGroupId -and $PolicyConfig.conditions.users.excludeGroups -notcontains $NoMfaGroupId) {
            $existingExcludes = @($PolicyConfig.conditions.users.excludeGroups) | Where-Object { $_ }
            $PolicyConfig.conditions.users.excludeGroups = @($existingExcludes) + $NoMfaGroupId
        }

        # Create policy
        $newPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicyConfig -ErrorAction Stop

        Write-Host "     Created successfully (ID: $($newPolicy.Id))" -ForegroundColor Green
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

function Start-CAPolicyCreation {
    # Header
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  CONDITIONAL ACCESS POLICIES" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Creates security policies for identity protection" -ForegroundColor Gray
    Write-Host ""

    # Step 1: Prerequisites (with auto-fix)
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

    $noMfaGroupId    = $prereqResult.NoMfaGroupId
    $geoUkGroupId    = $prereqResult.GeoUkGroupId
    $geoIntlGroupId  = $prereqResult.GeoIntlGroupId
    $ukLocationId    = $prereqResult.UkLocationId

    # Step 2: Load data
    Write-Host "  STEP 2: Loading Data" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    $tenantInfo = Get-TenantInfo
    if (!$tenantInfo) {
        Write-Host "   Failed to get tenant information" -ForegroundColor Red
        return
    }
    Write-Host "   Tenant: $($tenantInfo.OrganizationName)" -ForegroundColor Green

    # -PolicyState here is just a placeholder seed — Set-PolicyStates (Step 3)
    # overwrites every policy's actual state individually right after this.
    $policies = Get-PolicyDefinitions -NoMfaGroupId $noMfaGroupId -PolicyState "enabledForReportingButNotEnforced" `
        -GeoUkGroupId $geoUkGroupId -GeoIntlGroupId $geoIntlGroupId -UkLocationId $ukLocationId
    Write-Host "   Loaded $($policies.Count) policy definitions" -ForegroundColor Green

    # Step 3: Choose enforcement mode, per policy
    Write-Host ""
    Write-Host "  STEP 3: Policy Mode (per policy)" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray
    if ($script:NonInteractive) {
        Write-Host "   Non-interactive mode: resolving each policy's mode from PolicyModes/PolicyMode" -ForegroundColor Gray
    }
    else {
        Write-Host "   Report-only logs but does NOT enforce (recommended for new tenants)." -ForegroundColor Cyan
        Write-Host "   Enabled enforces immediately. Choose independently for each policy below." -ForegroundColor Yellow
    }
    Set-PolicyStates -Policies $policies

    # Step 4: Preview
    Write-Host ""
    Write-Host "  STEP 4: Preview" -ForegroundColor Yellow
    Show-PolicyPreview -Policies $policies -NoMfaGroupId $noMfaGroupId

    # Confirmation (skipped in unattended mode)
    if ($script:NonInteractive) {
        Write-Host "  Non-interactive mode: proceeding without confirmation" -ForegroundColor Gray
    }
    else {
        Write-Host "  [Y] Proceed with creation  [N] Cancel" -ForegroundColor Gray
        Write-Host ""
        $confirm = Read-Host "  Create these CA policies? (Y/N)"

        if ($confirm -notlike "Y*") {
            Write-Host ""
            Write-Host "  Cancelled by user" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
            return
        }
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
        Write-Host "   $($policy.DisplayName)..." -ForegroundColor White

        $result = New-ConditionalAccessPolicy -PolicyConfig $policy -NoMfaGroupId $noMfaGroupId

        if ($result.Success) {
            if ($result.Skipped) {
                $results.Skipped += $policy.DisplayName
            }
            else {
                $results.Created += $policy.DisplayName
            }
        }
        else {
            $results.Failed += @{ Name = $policy.DisplayName; Error = $result.Error }
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

    # Important warnings
    $enabledNow = @($policies | Where-Object { $_.state -eq 'enabled' } | ForEach-Object { $_.displayName })
    Write-Host "  IMPORTANT:" -ForegroundColor Red
    if ($enabledNow.Count -gt 0) {
        Write-Host "    - These policies are ENFORCING immediately: $($enabledNow -join ', ')" -ForegroundColor Yellow
    }
    else {
        Write-Host "    - All policies were created in Report-only mode (no enforcement yet)" -ForegroundColor Yellow
    }
    Write-Host "    - Add break-glass accounts to NoMFA Exclusion Group NOW" -ForegroundColor Yellow
    Write-Host "    - Test with pilot users before full deployment" -ForegroundColor Yellow
    Write-Host ""

    Write-Host "  Next Steps:" -ForegroundColor Yellow
    Write-Host "    1. Add break-glass accounts to NoMFA Exclusion Group" -ForegroundColor Gray
    Write-Host "    2. Verify policies in Entra admin center" -ForegroundColor Gray
    Write-Host "    3. Monitor sign-in logs for policy impact" -ForegroundColor Gray
    Write-Host "    4. Test with pilot users" -ForegroundColor Gray
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

    Start-CAPolicyCreation
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
}
