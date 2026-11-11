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
    3.0 - Read-only comparison with the tenant, for tenants that already have
          Conditional Access policies:
          * An interactive run now starts by asking whether to COMPARE ONLY
            or to compare and then create/update. Compare-only (also
            -CompareOnly, or CompareOnly in the config file) reads the
            tenant and reports, per policy, Missing / Matches / Differs with
            each difference from the script's design, plus which groups, the
            UK named location and emergency access account are missing. It
            creates and changes nothing - not even the groups or Security
            Defaults a normal run would fix first.
          * A normal run shows the same per-policy comparison before the
            preview, so what already exists is seen before anything is made.
          Enabled / Report-only is shown but never counted as a difference.
          Extra exclusions added by hand are noted, not flagged.
    2.9 - An existing C007 that is not in the current design can be brought
          up to date. The script detects a C007 that still carries its old
          name, is scoped to a group instead of all users, or excludes
          "AllTrusted" (the state the portal hides and drops on save), and
          offers to update it (UpdateExistingC007 in non-interactive runs):
          all users, the UK named location as the only kind of excluded
          location ("Selected networks and locations"), the standard and
          partner exclusions, the current name, and Report-only. It is
          always put into Report-only because the change makes it apply to
          people it did not apply to before. Exclusions already on the
          policy are kept; nothing is removed except "AllTrusted" and the
          old include group.
    2.8 - Two more failsafes for the emergency access account:
          * The run now STOPS before creating anything when there is no
            emergency access account (empty NoMFA Exclusion Group and no
            account given at the prompt / in EmergencyAccessUpns). It used
            to carry on with a warning.
          * Policies that already exist are still not recreated, but each
            one is checked for the NoMFA Exclusion Group and the emergency
            access account. Any that lack them are listed and the script
            offers to add them (UpdateExistingExclusions in non-interactive
            runs). Only those two exclusions are added; nothing else on the
            policy is changed.
    2.7 - Lockout safeguards, after C007 locked a whole tenant out:
          * C007 (Block Sign-In Outside UK) now applies to ALL users, guests
            included, instead of the hand-maintained CA-GEO-UK group. People
            are taken out by exception: CA-GEO-International, CA-UK-Travel-
            Exclusion, and partner (GDAP) sign-ins. Renamed to drop
            "(UK Users)"; a tenant holding it under the old name is skipped,
            not duplicated. The UK named location is always created.
          * Emergency access accounts: the user members of the NoMFA
            Exclusion Group are now also listed directly on every policy
            (excludeUsers), and an EMPTY group is no longer silently
            accepted - the script asks for the account (or reads
            EmergencyAccessUpns) and adds it.
          * C003 (compliant device) excludes the BITS Admin Users group and
            partner (GDAP) sign-ins, neither of which can hold a compliant
            device in the customer's tenant.
          * Policies that can block a sign-in (block, compliant device,
            protected app: C001, C003, C006, C007, C008, C009, C011) are
            ALWAYS created Report-only. There is no prompt for them and a
            config asking for Enabled is ignored.
          * Policies are listed in code order (C007 before C008), and an
            existing policy whose excluded locations the portal would
            silently drop is flagged when it is found.
    2.6 - C007 (Block Sign-In Outside UK) now excludes only the UK named
          location, instead of the UK location plus "AllTrusted". The portal
          can't display a named location and "All trusted" together, so a
          portal save silently dropped the UK exclusion and the policy then
          blocked UK sign-ins. Excluding the UK location alone is shown and
          kept by the portal. Existing tenants are not changed (policies that
          already exist are skipped): check their C007 excluded locations.
    2.5 - Add four new CA policies based on real-world BYOD/Guest scenarios:
          C009 - BYOD Android & iOS (MFA + require app protection policy),
          C010 - Windows BYOD (Browser Access) (MFA, browser-only session with
          app-enforced restrictions), C011 - Windows BYOD (Block Native Apps)
          (blocks desktop/mobile client apps for the same Windows BYOD
          population), C012 - Guest Access (MFA + daily sign-in frequency +
          app-enforced restrictions for guests/external users, excluding
          mobile/mac/linux). Also enhances C007 (Block Sign-In Outside UK)
          with an optional UK travel exclusion group. Two new prerequisite
          groups (Windows-BYOD, UK-Travel-Exclusion) auto-create empty,
          mirroring the existing NoMFA Exclusion Group pattern, and are
          optional: the policies that depend on them are skipped (not the
          whole run) if creation fails or is declined.
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
.PARAMETER CompareOnly
    Read-only run: compare the tenant's Conditional Access policies with
    this script's design and report the differences. Nothing is created or
    changed. Can also be set as CompareOnly in the ConfigFile.
.PARAMETER ConfigFile
    Optional JSON file overriding run behaviour. Supported keys:
      NamePrefix                  (string) prefixed to every policy displayName
      GroupNamePrefix             (string) prefixed to the group names this
                                   script looks up (NoMFA Exclusion Group,
                                   BITS Admin Users, CA-GEO-International)
      PolicyMode                  ("ReportOnly"|"Enabled") default ReportOnly —
                                   the fallback used for any policy not given
                                   its own entry in PolicyModes below. E2E
                                   tests must never use Enabled: most policies
                                   target "All" users in a shared tenant, so
                                   Enabled would actually enforce MFA rules
                                   for real traffic
      PolicyModes                 (object) optional per-policy override, keyed
                                   by policy code, e.g.
                                   { "C002": "Enabled", "C004": "ReportOnly" }.
                                   Policies not listed here use PolicyMode.
                                   NOTE: neither setting can enable a policy
                                   that can block a sign-in (C001, C003, C006,
                                   C007, C008, C009, C011). Those are always
                                   Report-only; "Enabled" is ignored for them.
      PartnerTenantIds            (string[]) tenant IDs of the partner(s) with
                                   delegated admin (GDAP) access. Their
                                   service-provider sign-ins are excluded from
                                   C003 and C007. Defaults to the BITS tenant;
                                   set [] to exclude none.
      EmergencyAccessUpns         (string[]) UPN(s) of the emergency access
                                   (break-glass) account to add to the NoMFA
                                   Exclusion Group when that group is empty.
                                   Only read in non-interactive runs; an
                                   interactive run asks instead. With no
                                   account the run stops.
      UpdateExistingExclusions    (bool) default false. Non-interactive only:
                                   add the NoMFA Exclusion Group and the
                                   emergency access account to policies that
                                   already exist and lack them. An interactive
                                   run asks instead.
      CompareOnly                 (bool) default false. Same as -CompareOnly:
                                   report differences and change nothing.
      UpdateExistingC007          (bool) default false. Non-interactive only:
                                   bring an existing C007 up to the current
                                   design (all users, UK location only,
                                   Report-only). An interactive run asks.
      AutoDisableSecurityDefaults (bool) default true — required to make any
                                   progress, since CA policies cannot be
                                   created while Security Defaults is enabled
      AutoCreateNoMfaGroup        (bool) default true
      AutoCreateBYODGroups        (bool) default true — covers the Windows
                                   BYOD group (C010/C011) and the UK travel
                                   exclusion group (C007). Unlike the NoMFA
                                   group these are optional: if creation is
                                   declined/disabled/fails, C010/C011 are
                                   skipped and C007 is created without the
                                   travel exemption, rather than blocking the
                                   whole run.
.PARAMETER ResultPath
    Optional path to write a JSON results summary (created/skipped/failed),
    so a CI runner can assert on the outcome.
#>

param(
    [switch] $NonInteractive,
    [switch] $CompareOnly,
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
    AutoCreateBYODGroups        = $true
    # Partner (service provider / GDAP) tenants whose delegated-admin sign-ins
    # are excluded from C003 and C007. 23212a04-... is the BITS tenant.
    PartnerTenantIds            = @('23212a04-40b3-4ade-8101-f6804f754ab6')
    # Non-interactive only: account(s) to add to an EMPTY NoMFA Exclusion Group
    EmergencyAccessUpns         = @()
    # Non-interactive only: add the standard exclusions to EXISTING policies
    # that lack them (an interactive run asks)
    UpdateExistingExclusions    = $false
    # Non-interactive only: bring an existing C007 up to the current design
    UpdateExistingC007          = $false
    # Read-only run: report differences from the design, change nothing
    CompareOnly                 = $false
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

$script:CompareOnly = [bool]$CompareOnly -or [bool]$script:RunConfig.CompareOnly

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

    # Emergency access (break-glass) accounts: the user members of the NoMFA
    # Exclusion Group. Every policy excludes the group AND lists these
    # accounts directly, so one of them can always sign in to undo a bad
    # policy. An empty group is the state that turns a policy mistake into a
    # tenant-wide lockout, so it is checked (and can be fixed) here rather
    # than left as an "add them afterwards" reminder.
    Write-Host "   Checking emergency access accounts (NoMFA Exclusion Group members)..." -ForegroundColor Gray
    $emergencyAccess = Resolve-EmergencyAccessAccounts -NoMfaGroupId $noMfaGroupResult.GroupId

    # No emergency access account = nobody who can undo a bad policy. Stop
    # here, before anything is created, rather than carry on with a warning.
    if (@($emergencyAccess.UserIds).Count -eq 0) {
        Write-Host ""
        Write-Host "   STOPPED: no emergency access (break-glass) account." -ForegroundColor Red
        Write-Host "   No policies were created or changed. Create or choose the account kept for" -ForegroundColor Red
        Write-Host "   emergencies, then run this again and enter its UPN when asked" -ForegroundColor Red
        Write-Host "   (non-interactive: set EmergencyAccessUpns in the config file)." -ForegroundColor Red
        return @{ Success = $false; Error = 'No emergency access account' }
    }

    # Admin group (optional — excluded from C003 only)
    Write-Host "   Checking for BITS Admin Users group (optional)..." -ForegroundColor Gray
    $adminGroupResult = Resolve-AdminGroup

    # Partner (service provider / GDAP) tenants excluded from C003 and C007
    $partnerTenantIds = @(Get-PartnerTenantIds -CurrentTenantId $context.TenantId)
    if ($partnerTenantIds.Count -gt 0) {
        Write-Host "   Partner (GDAP) tenants excluded from C003/C007: $($partnerTenantIds -join ', ')" -ForegroundColor Green
    }
    else {
        Write-Host "   No partner (GDAP) tenants configured - delegated admin sign-ins are not excluded from C003/C007" -ForegroundColor Yellow
    }

    # Check for the Windows BYOD group (optional — C010/C011 skipped if missing)
    Write-Host "   Checking for CA-BYOD-Windows group (optional)..." -ForegroundColor Gray
    $byodWindowsResult = Test-BYODWindowsGroup
    $byodWindowsGroupId = if ($byodWindowsResult.Success) { $byodWindowsResult.GroupId } else { $null }
    if (!$byodWindowsGroupId) {
        Write-Host "   CA-BYOD-Windows unavailable - C010/C011 (Windows BYOD) will be skipped" -ForegroundColor Yellow
    }

    # CA-GEO-International (optional) — an EXCLUSION from C007, not its scope.
    # C007 applies to all users; this group holds the users (or guests) who
    # are based outside the UK. C007 is still created without it.
    Write-Host "   Checking for CA-GEO-International group (optional)..." -ForegroundColor Gray
    $groupPrefix = $script:RunConfig.GroupNamePrefix
    $geoIntlGroup = Get-MgGroup -Filter "displayName eq '${groupPrefix}CA-GEO-International'" -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($geoIntlGroup) {
        Write-Host "   CA-GEO-International found (ID: $($geoIntlGroup.Id))" -ForegroundColor Green
    }
    else {
        Write-Host "   CA-GEO-International not found - C007 will be created without it (Security Groups creates it)" -ForegroundColor Yellow
    }

    # Check for UK named location — C007 excludes it, so it is created
    # automatically when missing. Prefix-aware so E2E runs create/clean
    # "E2E-UK" while production (empty prefix) gets "UK".
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
    else {
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

    # Check for the UK travel exclusion group — only relevant if C007 itself
    # is going to be created. Optional: if it can't be resolved, C007 is
    # still created, just without the travel exemption.
    $ukTravelExclusionGroupId = $null
    if ($ukLocation) {
        Write-Host "   Checking for CA-UK-Travel-Exclusion group (optional)..." -ForegroundColor Gray
        $travelExclusionResult = Test-UkTravelExclusionGroup
        if ($travelExclusionResult.Success) {
            $ukTravelExclusionGroupId = $travelExclusionResult.GroupId
        }
        else {
            Write-Host "   CA-UK-Travel-Exclusion unavailable - C007 will be created without a travel exemption" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    # Explicit if/else rather than ?. — under Set-StrictMode (as the E2E test
    # harness enables), $geoIntlGroup?.Id is parsed as a variable literally named
    # "geoIntlGroup?", which was never set, and throws instead of returning $null
    return @{
        Success                  = $true
        NoMfaGroupId             = $noMfaGroupResult.GroupId
        SecurityDefaultsDisabled = $securityDefaultsResult.IsDisabled
        GeoIntlGroupId           = if ($geoIntlGroup) { $geoIntlGroup.Id } else { $null }
        UkLocationId             = if ($ukLocation) { $ukLocation.id } else { $null }
        ByodWindowsGroupId       = $byodWindowsGroupId
        UkTravelExclusionGroupId = $ukTravelExclusionGroupId
        EmergencyAccessUserIds   = @($emergencyAccess.UserIds)
        EmergencyAccessUpns      = @($emergencyAccess.Upns)
        AdminGroupId             = $adminGroupResult.GroupId
        AdminGroupHasMembers     = [bool]$adminGroupResult.HasMembers
        PartnerTenantIds         = @($partnerTenantIds)
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

function Test-OrCreateCAGroup {
    <#
    .SYNOPSIS
        Looks up a security group by (prefixed) name and offers/attempts to
        create it empty if missing — shared by every group-backed CA policy
        prerequisite (NoMFA Exclusion Group, Windows BYOD, UK travel
        exclusion). Interactive: prompts Y/N. Non-interactive: creates
        automatically unless $AutoCreate is $false.
    #>
    param(
        [Parameter(Mandatory)][string]$GroupName,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$RequiredForText,
        [bool]$AutoCreate = $true
    )

    try {
        $group = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue

        if ($group) {
            Write-Host "   $GroupName found (ID: $($group.Id))" -ForegroundColor Green
            return @{ Success = $true; GroupId = $group.Id }
        }

        # Group doesn't exist - offer to create
        Write-Host "   $GroupName not found" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "   $RequiredForText" -ForegroundColor Yellow
        Write-Host ""

        if ($script:NonInteractive) {
            if (!$AutoCreate) {
                Write-Host "   Auto-create disabled for $GroupName - cannot proceed" -ForegroundColor Yellow
                return @{ Success = $false }
            }
            Write-Host "   Non-interactive mode: creating $GroupName automatically" -ForegroundColor Gray
        }
        else {
            Write-Host "   [Y] Create $GroupName now  [N] Skip" -ForegroundColor Gray
            $confirm = Read-Host "   Create the group? (Y/N)"

            if ($confirm -notlike "Y*") {
                Write-Host "   Skipped - create $GroupName manually first if you need it" -ForegroundColor Yellow
                return @{ Success = $false }
            }
        }

        # Create the group
        Write-Host "   Creating $GroupName..." -ForegroundColor Yellow

        $groupParams = @{
            DisplayName = $GroupName
            Description = $Description
            MailEnabled = $false
            MailNickname = ($GroupName -replace '[^a-zA-Z0-9]', '')
            SecurityEnabled = $true
        }

        $newGroup = New-MgGroup -BodyParameter $groupParams -ErrorAction Stop
        Write-Host "   Created $GroupName (ID: $($newGroup.Id))" -ForegroundColor Green
        Write-Host "   IMPORTANT: populate this group's membership as appropriate!" -ForegroundColor Yellow

        return @{ Success = $true; GroupId = $newGroup.Id; Created = $true }
    }
    catch {
        Write-Host "   Error with ${GroupName}: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Test-NoMfaGroup {
    <#
    .SYNOPSIS
        Check for NoMFA Exclusion Group and offer to create if missing.
        Unlike the other group prerequisites below, this one is REQUIRED —
        every policy excludes it for break-glass safety, so a failure here
        blocks the whole run (see Test-Prerequisites).
    #>
    $groupPrefix = $script:RunConfig.GroupNamePrefix
    return Test-OrCreateCAGroup -GroupName "${groupPrefix}NoMFA Exclusion Group" `
        -Description "Members excluded from MFA requirements - USE FOR BREAK-GLASS ACCOUNTS ONLY" `
        -RequiredForText "This group is required to exclude break-glass accounts from MFA policies." `
        -AutoCreate $script:RunConfig.AutoCreateNoMfaGroup
}

function Get-GroupUserMembers {
    <#
    .SYNOPSIS
        Returns the direct USER members of a group as hashtables (id,
        userPrincipalName, displayName). Other member types (devices, nested
        groups, service principals) are ignored.
    #>
    param([Parameter(Mandatory)][string]$GroupId)

    $members = @()
    $uri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members?`$select=id,userPrincipalName,displayName&`$top=100"
    while ($uri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        foreach ($member in @($page['value'])) {
            if ($member -and $member['@odata.type'] -eq '#microsoft.graph.user') { $members += $member }
        }
        $uri = if ($page.ContainsKey('@odata.nextLink')) { $page['@odata.nextLink'] } else { $null }
    }
    return $members
}

function Find-UserByUpn {
    <#
    .SYNOPSIS
        Looks a user up by UPN. Returns a hashtable (id, userPrincipalName,
        displayName) or $null when there is no such user.
    #>
    param([Parameter(Mandatory)][string]$Upn)

    try {
        $encoded = [uri]::EscapeDataString($Upn)
        $user = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/users/${encoded}?`$select=id,userPrincipalName,displayName" `
            -ErrorAction Stop
        if ($user -and $user['id']) { return $user }
    }
    catch { }
    return $null
}

function Resolve-EmergencyAccessAccounts {
    <#
    .SYNOPSIS
        Works out which accounts are the tenant's emergency access
        (break-glass) accounts, and makes sure there is at least one.
    .DESCRIPTION
        The emergency access accounts are the user members of the NoMFA
        Exclusion Group ("USE FOR BREAK-GLASS ACCOUNTS ONLY"). In a tenant
        built by Admin-Creation.ps1 that is BITS-Admin-BG02. In an older
        tenant the accounts have other names and nothing put them in the
        group, which leaves every policy with an exclusion that protects
        nobody. So when the group is empty this asks for the account
        (interactive) or reads EmergencyAccessUpns from the config
        (non-interactive) and adds it to the group.

        Returns the accounts' object IDs so each policy can also list them
        directly (see Add-StandardExclusions). An empty result is returned
        as-is; Test-Prerequisites stops the run when it gets one.
    #>
    param([Parameter(Mandatory)][string]$NoMfaGroupId)

    $groupName = "$($script:RunConfig.GroupNamePrefix)NoMFA Exclusion Group"
    $accounts = @()
    try {
        $accounts = @(Get-GroupUserMembers -GroupId $NoMfaGroupId)
    }
    catch {
        Write-Host "   Could not read $groupName members: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    if ($accounts.Count -eq 0) {
        Write-Host "   $groupName has NO members" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "   Every policy excludes this group so that one emergency access (break-glass)" -ForegroundColor Yellow
        Write-Host "   account can always sign in and undo a bad policy. While the group is empty," -ForegroundColor Yellow
        Write-Host "   no account is protected from a lockout." -ForegroundColor Yellow
        Write-Host ""

        $upnsToAdd = @()
        if ($script:NonInteractive) {
            $upnsToAdd = @($script:RunConfig.EmergencyAccessUpns | Where-Object { $_ })
            if ($upnsToAdd.Count -eq 0) {
                Write-Host "   Non-interactive mode: no EmergencyAccessUpns configured" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "   Enter the account kept for emergencies only (long random password, no MFA)," -ForegroundColor Gray
            Write-Host "   for example BITS-Admin-BG02@yourdomain. It will be added to $groupName." -ForegroundColor Gray
            for ($attempt = 1; $attempt -le 3; $attempt++) {
                $entered = Read-Host "   Emergency access account UPN (blank to stop)"
                $entered = if ($entered) { $entered.Trim() } else { '' }
                if (!$entered) { break }
                if (Find-UserByUpn -Upn $entered) { $upnsToAdd = @($entered); break }
                Write-Host "   No user found with UPN '$entered'" -ForegroundColor Yellow
            }
        }

        foreach ($upn in $upnsToAdd) {
            $user = Find-UserByUpn -Upn ([string]$upn)
            if (!$user) {
                Write-Host "   Emergency access account not found: $upn" -ForegroundColor Yellow
                continue
            }
            try {
                $null = Invoke-MgGraphRequest -Method POST `
                    -Uri "https://graph.microsoft.com/v1.0/groups/$NoMfaGroupId/members/`$ref" `
                    -ContentType 'application/json' `
                    -Body (@{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($user['id'])" } | ConvertTo-Json) `
                    -ErrorAction Stop
                Write-Host "   Added $($user['userPrincipalName']) to $groupName" -ForegroundColor Green
                $accounts += $user
            }
            catch {
                if ($_.Exception.Message -match 'already exist') {
                    $accounts += $user
                }
                else {
                    Write-Host "   Could not add $upn to ${groupName}: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
    }

    if ($accounts.Count -gt 0) {
        foreach ($account in $accounts) {
            Write-Host "   Emergency access account: $($account['userPrincipalName'])" -ForegroundColor Green
        }
    }
    else {
        Write-Host "   No emergency access account was found or given" -ForegroundColor Red
    }

    return @{
        UserIds = @($accounts | ForEach-Object { $_['id'] })
        Upns    = @($accounts | ForEach-Object { $_['userPrincipalName'] })
    }
}

function Resolve-AdminGroup {
    <#
    .SYNOPSIS
        Looks up the BITS Admin Users group, which C003 (compliant device)
        excludes: admin accounts sign in from the partner's own devices,
        which can never be compliant in the customer's tenant. Optional — if
        the group is missing, C003 is created without it.
    .DESCRIPTION
        The group is dynamic and matches names containing "BITS-Admin". In a
        tenant whose admin accounts use a different naming convention it
        stays empty and excludes nobody, so an empty group is called out
        here instead of being discovered when C003 is enabled.
    #>
    $groupName = "$($script:RunConfig.GroupNamePrefix)BITS Admin Users"
    $group = $null
    try {
        $group = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction Stop | Select-Object -First 1
    }
    catch { }

    if (!$group) {
        Write-Host "   $groupName not found - admin accounts will NOT be excluded from C003" -ForegroundColor Yellow
        Write-Host "   (Security Groups creates it; otherwise exclude your admin accounts from C003 before enabling it)" -ForegroundColor Yellow
        return @{ GroupId = $null; HasMembers = $false }
    }

    $hasMembers = $false
    try {
        $page = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/groups/$($group.Id)/members?`$select=id&`$top=1" `
            -ErrorAction Stop
        $hasMembers = @($page['value']).Count -gt 0
    }
    catch { }

    Write-Host "   $groupName found (ID: $($group.Id)) - excluded from C003" -ForegroundColor Green
    if (!$hasMembers) {
        Write-Host "   WARNING: $groupName has no members." -ForegroundColor Yellow
        Write-Host "   It is a dynamic group matching names that contain 'BITS-Admin'. A new group can take a" -ForegroundColor Yellow
        Write-Host "   few minutes to fill. If it stays empty, this tenant's admin accounts use different names" -ForegroundColor Yellow
        Write-Host "   and C003 would block them once enabled. Check its members before enabling C003." -ForegroundColor Yellow
    }

    return @{ GroupId = $group.Id; HasMembers = $hasMembers }
}

function Get-PartnerTenantIds {
    <#
    .SYNOPSIS
        Returns the configured partner (service provider / GDAP) tenant IDs,
        validated as GUIDs and de-duplicated. The tenant being configured is
        dropped from the list: a tenant is never an external partner of
        itself.
    #>
    param([string]$CurrentTenantId)

    $ids = @()
    foreach ($candidate in @($script:RunConfig.PartnerTenantIds)) {
        if (!$candidate) { continue }
        $parsed = [guid]::Empty
        if (![guid]::TryParse([string]$candidate, [ref]$parsed)) {
            Write-Host "   Ignoring PartnerTenantIds entry that is not a tenant ID (GUID): $candidate" -ForegroundColor Yellow
            continue
        }
        $id = $parsed.ToString()
        if ($CurrentTenantId -and $id -eq ([string]$CurrentTenantId).ToLowerInvariant()) { continue }
        if ($ids -notcontains $id) { $ids += $id }
    }
    return $ids
}

function Test-BYODWindowsGroup {
    <#
    .SYNOPSIS
        Check for the Windows BYOD group (C010/C011's scope) and offer to
        create if missing. Optional — unlike NoMFA, a failure here just
        skips C010/C011 rather than blocking the whole run, since an empty
        or missing group only means "no Windows BYOD policies yet", not an
        unsafe state.
    #>
    $groupPrefix = $script:RunConfig.GroupNamePrefix
    return Test-OrCreateCAGroup -GroupName "${groupPrefix}CA-BYOD-Windows" `
        -Description "Users in scope for Windows BYOD Conditional Access: browser access only (MFA required), native/desktop apps blocked" `
        -RequiredForText "This group scopes C010/C011 (Windows BYOD policies) — skipped if it can't be resolved." `
        -AutoCreate $script:RunConfig.AutoCreateBYODGroups
}

function Test-UkTravelExclusionGroup {
    <#
    .SYNOPSIS
        Check for the UK travel exclusion group (an additional C007
        exclusion, for staff temporarily travelling outside the UK) and
        offer to create if missing. Optional — a failure here just means
        C007 is created without the travel exclusion, not blocked entirely.
    #>
    $groupPrefix = $script:RunConfig.GroupNamePrefix
    return Test-OrCreateCAGroup -GroupName "${groupPrefix}CA-UK-Travel-Exclusion" `
        -Description "Users temporarily exempted from C007 (Block Sign-In Outside UK) while travelling — add/remove as needed, do not leave populated long-term" `
        -RequiredForText "This group lets C007 (Block Sign-In Outside UK) exempt travelling staff — skipped if it can't be resolved." `
        -AutoCreate $script:RunConfig.AutoCreateBYODGroups
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

function New-ServiceProviderExclusion {
    <#
    .SYNOPSIS
        Builds the "Guest or external users" exclusion that exempts partner
        (service provider / GDAP) sign-ins from a policy, limited to the
        given partner tenant IDs. Returns $null when no tenant IDs are given,
        so callers can simply skip the key.
    .DESCRIPTION
        Partner staff signing in through GDAP have no account in the customer
        tenant, so they cannot be exempted through a group — the service
        provider user type scoped to the partner's tenant ID is the method
        Microsoft documents for this. A fresh hashtable is returned on every
        call so two policies never share one object.
    #>
    param([string[]]$TenantIds)

    $ids = @($TenantIds | Where-Object { $_ })
    if ($ids.Count -eq 0) { return $null }

    return @{
        guestOrExternalUserTypes = 'serviceProvider'
        externalTenants          = @{
            '@odata.type'  = '#microsoft.graph.conditionalAccessEnumeratedExternalTenants'
            membershipKind = 'enumerated'
            members        = @($ids)
        }
    }
}

function Get-PolicyDefinitions {
    param(
        [string]$NoMfaGroupId,
        [string]$PolicyState = "enabledForReportingButNotEnforced",
        [string]$GeoIntlGroupId,
        [string]$UkLocationId,
        [string]$ByodWindowsGroupId,
        [string]$UkTravelExclusionGroupId,
        [string]$AdminGroupId,
        [string[]]$PartnerTenantIds
    )

    $namePrefix = $script:RunConfig.NamePrefix

    # ---- C003 users: everyone, minus the accounts that can never hold a
    # compliant device in THIS tenant ---------------------------------------
    # - Admin group (BITS Admin Users): admin accounts are used from the
    #   partner's own devices, which are not enrolled in the customer's Intune.
    # - Partner (GDAP) sign-ins: same reason, and they have no account here to
    #   put in a group.
    # - excludeRoles d29b2b05-... is the built-in "Directory Synchronization
    #   Accounts" role (the Entra Connect sync account) — it is NOT Global
    #   Administrator. Administrators are covered by the admin group above.
    $c003ExcludeGroups = @($NoMfaGroupId)
    if ($AdminGroupId) { $c003ExcludeGroups += $AdminGroupId }
    $c003Users = @{
        includeUsers  = @("All")
        excludeGroups = @($c003ExcludeGroups)
        excludeRoles  = @("d29b2b05-8046-44ba-8758-1e26182fcf32")
    }
    $c003PartnerExclusion = New-ServiceProviderExclusion -TenantIds $PartnerTenantIds
    if ($c003PartnerExclusion) { $c003Users['excludeGuestsOrExternalUsers'] = $c003PartnerExclusion }

    # ---- C007 users: ALL users (guests included), not a hand-maintained
    # group ------------------------------------------------------------------
    # Scoping this to a manual "UK users" group meant a user was only
    # protected if someone remembered to add them. It now applies to everyone
    # and people are taken OUT by exception instead:
    # - CA-GEO-International: users (or guests) based outside the UK
    # - CA-UK-Travel-Exclusion: temporary travel
    # - Partner (GDAP) sign-ins: no account here to put in a group, and
    #   delegated admin access is a way back in if this policy misbehaves.
    # Both groups are optional: the policy is still created without them.
    $c007ExcludeGroups = @($NoMfaGroupId)
    if ($GeoIntlGroupId) { $c007ExcludeGroups += $GeoIntlGroupId }
    if ($UkTravelExclusionGroupId) { $c007ExcludeGroups += $UkTravelExclusionGroupId }
    $c007Users = @{
        includeUsers  = @("All")
        excludeGroups = @($c007ExcludeGroups)
    }
    $c007PartnerExclusion = New-ServiceProviderExclusion -TenantIds $PartnerTenantIds
    if ($c007PartnerExclusion) { $c007Users['excludeGuestsOrExternalUsers'] = $c007PartnerExclusion }

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
                users = $c003Users
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
        }
    ) + $(
        # C007: needs only the UK named location (auto-created in
        # Test-Prerequisites). Applies to ALL users, guests included — see the
        # $c007Users block above for who is taken out by exception.
        if ($UkLocationId) {
            @(
                @{
                    displayName = "C007 - Block Sign-In Outside UK"
                    state       = $PolicyState
                    conditions  = @{
                        applications   = @{ includeApplications = @("All") }
                        clientAppTypes = @("all")
                        users          = $c007Users
                        # Exclude the UK named location ONLY ("Selected networks and
                        # locations" in the portal). Do NOT also add "AllTrusted":
                        # the portal's Network blade can't show a named location and
                        # "All trusted" together, so it displays only "All trusted",
                        # and the next portal save of this policy (e.g. widening its
                        # users) silently drops the UK exclusion — which turns this
                        # into a block on every UK sign-in. A named-location-only
                        # exclusion is displayed and preserved by the portal.
                        locations      = @{
                            includeLocations = @("All")
                            excludeLocations = @($UkLocationId)
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
    ) + @(
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
        # C009: BYOD Android/iOS — unconditional (no group prerequisite; reuses
        # the NoMFA group for break-glass, same as every other policy, rather
        # than a bespoke exclusion group — Android/iOS has no device-compliance
        # coverage elsewhere (C003 is Windows/macOS only), so this covers that
        # gap via app protection instead of device compliance.
        @(
            @{
                displayName = "C009 - BYOD Android and iOS App Protection"
                state       = $PolicyState
                conditions  = @{
                    applications   = @{ includeApplications = @("Office365") }
                    clientAppTypes = @("all")
                    users          = @{
                        includeUsers  = @("All")
                        excludeGroups = @($NoMfaGroupId)
                    }
                    platforms      = @{ includePlatforms = @("android", "iOS") }
                }
                grantControls = @{
                    builtInControls = @("mfa", "compliantApplication")
                    operator        = "AND"
                }
            }
        )
    ) + $(
        # C010/C011: Windows BYOD pair — both scoped to the same include
        # group, only added if that group could be resolved (see
        # Test-BYODWindowsGroup). Together: browser access is allowed (MFA +
        # app-enforced session restrictions), native/desktop apps are
        # blocked outright — this is what actually forces BYOD Windows
        # users onto the restricted browser path instead of e.g. the
        # desktop Outlook/OneDrive sync client.
        if ($ByodWindowsGroupId) {
            @(
                @{
                    displayName = "C010 - Windows BYOD (Browser Access)"
                    state       = $PolicyState
                    conditions  = @{
                        applications   = @{ includeApplications = @("Office365") }
                        clientAppTypes = @("browser")
                        users          = @{ includeGroups = @($ByodWindowsGroupId) }
                        platforms      = @{ includePlatforms = @("windows") }
                    }
                    grantControls = @{
                        builtInControls = @("mfa")
                        operator        = "OR"
                    }
                    sessionControls = @{
                        applicationEnforcedRestrictions = @{ isEnabled = $true }
                    }
                },
                @{
                    displayName = "C011 - Windows BYOD (Block Native Apps)"
                    state       = $PolicyState
                    conditions  = @{
                        applications   = @{ includeApplications = @("Office365") }
                        clientAppTypes = @("mobileAppsAndDesktopClients")
                        users          = @{ includeGroups = @($ByodWindowsGroupId) }
                        platforms      = @{ includePlatforms = @("windows") }
                    }
                    grantControls = @{
                        builtInControls = @("block")
                        operator        = "OR"
                    }
                }
            )
        }
        else { @() }
    ) + $(
        # C012: Guest Access — targets guests/external users specifically via
        # the built-in directory condition (not a security group), so no
        # prerequisite needed. Excludes mobile/mac/linux platforms on
        # purpose, matching the reference tenant: this covers Windows +
        # unknown/other platforms only.
        @(
            @{
                displayName = "C012 - Guest Access"
                state       = $PolicyState
                conditions  = @{
                    applications   = @{ includeApplications = @("Office365") }
                    clientAppTypes = @("all")
                    users          = @{
                        includeGuestsOrExternalUsers = @{
                            guestOrExternalUserTypes = "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,otherExternalUser"
                            externalTenants           = @{
                                '@odata.type'  = '#microsoft.graph.conditionalAccessAllExternalTenants'
                                membershipKind = 'all'
                            }
                        }
                    }
                    platforms      = @{
                        includePlatforms = @("all")
                        excludePlatforms = @("android", "iOS", "macOS", "linux")
                    }
                }
                grantControls = @{
                    builtInControls = @("mfa")
                    operator        = "OR"
                }
                sessionControls = @{
                    applicationEnforcedRestrictions = @{ isEnabled = $true }
                    signInFrequency = @{
                        value               = 1
                        type                = "days"
                        authenticationType  = "primaryAndSecondaryAuthentication"
                        frequencyInterval   = "timeBased"
                        isEnabled           = $true
                    }
                }
            }
        )
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

function Test-PolicyCanBlockSignIn {
    <#
    .SYNOPSIS
        True when a policy can stop a sign-in outright with nothing the user
        can do about it at the prompt: it blocks, or it demands a compliant /
        domain-joined device or a protected app.
    .DESCRIPTION
        These are the policies that lock people out when their conditions or
        exclusions are wrong, so the script never creates them Enabled (see
        Set-PolicyStates). MFA and password-change policies are not included:
        a user who meets them is let straight through, and one who doesn't is
        walked through fixing it there and then.

        Derived from the grant controls rather than a list of policy codes,
        so a policy added later is covered without anyone remembering to
        register it.
    #>
    param([hashtable]$Policy)

    $controls = @($Policy.grantControls.builtInControls)
    foreach ($control in @('block', 'compliantDevice', 'domainJoinedDevice', 'compliantApplication', 'approvedApplication')) {
        if ($controls -contains $control) { return $true }
    }
    return $false
}

function Set-PolicyStates {
    <#
    .SYNOPSIS
        Resolves and applies an enforcement state to each policy
        individually, mutating each policy's .state in place — Report-only
        vs Enabled is no longer one global choice for the whole run.
    .DESCRIPTION
        Policies that can block a sign-in (Test-PolicyCanBlockSignIn) are
        ALWAYS Report-only: there is no prompt for them, and a config that
        asks for Enabled is ignored with a warning. They are meant to be
        reviewed in Report-only for about a week and then enabled, one at a
        time, in the Entra admin center.

        For every other policy —
        Interactive: prompts once per policy.
        Non-interactive: reads $script:RunConfig.PolicyModes[<code>] for a
        per-policy override, falling back to the global
        $script:RunConfig.PolicyMode default for any policy without one.
    #>
    param([array]$Policies)

    foreach ($policy in $Policies) {
        $code = Get-PolicyCode -DisplayName $policy.displayName
        $requestedMode = if ($script:RunConfig.PolicyModes.ContainsKey($code)) {
            $script:RunConfig.PolicyModes[$code]
        }
        else {
            $script:RunConfig.PolicyMode
        }

        if (Test-PolicyCanBlockSignIn -Policy $policy) {
            $policy.state = 'enabledForReportingButNotEnforced'
            if ($script:NonInteractive) {
                if ($requestedMode -eq 'Enabled') {
                    Write-Host "   ${code}: config asked for Enabled - ignored. This policy can block sign-ins, so it is always created Report-only." -ForegroundColor Yellow
                }
            }
            else {
                Write-Host ""
                Write-Host "   $($policy.displayName)" -ForegroundColor White
                Write-Host "     -> Report-only (fixed: this policy can block sign-ins)" -ForegroundColor Cyan
            }
            continue
        }

        if ($script:NonInteractive) {
            $policy.state = if ($requestedMode -eq 'Enabled') { 'enabled' } else { 'enabledForReportingButNotEnforced' }
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
        [string]$NoMfaGroupId,
        [string[]]$EmergencyAccessUpns,
        [string[]]$PartnerTenantIds,
        [bool]$AdminGroupFound,
        [bool]$AdminGroupHasMembers
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

    $fixedCodes = @($Policies | Where-Object { Test-PolicyCanBlockSignIn -Policy $_ } | ForEach-Object { Get-PolicyCode -DisplayName $_.displayName })
    $emergencyUpns = @($EmergencyAccessUpns | Where-Object { $_ })
    $partnerIds = @($PartnerTenantIds | Where-Object { $_ })

    Write-Host ""
    Write-Host "  Every policy excludes:" -ForegroundColor Yellow
    Write-Host "    - NoMFA Exclusion Group (ID: $NoMfaGroupId)" -ForegroundColor Gray
    if ($emergencyUpns.Count -gt 0) {
        Write-Host "    - Emergency access accounts, also listed directly: $($emergencyUpns -join ', ')" -ForegroundColor Gray
    }
    else {
        Write-Host "    - NO emergency access account: the NoMFA Exclusion Group is empty" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "  C003 (compliant device) also excludes:" -ForegroundColor Yellow
    if ($AdminGroupFound) {
        $adminNote = if ($AdminGroupHasMembers) { '' } else { ' - currently EMPTY, check before enabling C003' }
        Write-Host "    - BITS Admin Users group$adminNote" -ForegroundColor $(if ($AdminGroupHasMembers) { 'Gray' } else { 'Yellow' })
    }
    else {
        Write-Host "    - (BITS Admin Users group not found - admin accounts are NOT excluded)" -ForegroundColor Yellow
    }
    if ($partnerIds.Count -gt 0) {
        Write-Host "    - Partner (GDAP) sign-ins from: $($partnerIds -join ', ')" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "  C007 (outside UK) applies to ALL users, including guests, and also excludes:" -ForegroundColor Yellow
    Write-Host "    - CA-GEO-International and CA-UK-Travel-Exclusion groups (where they exist)" -ForegroundColor Gray
    if ($partnerIds.Count -gt 0) {
        Write-Host "    - Partner (GDAP) sign-ins from: $($partnerIds -join ', ')" -ForegroundColor Gray
    }
    Write-Host ""
    if ($fixedCodes.Count -gt 0) {
        Write-Host "  Always Report-only (can block sign-ins): $($fixedCodes -join ', ')" -ForegroundColor Yellow
        Write-Host "    Review their results for about a week, then enable them one at a time in the portal." -ForegroundColor Gray
        Write-Host ""
    }
}

# ============================================================================
# POLICY CREATION
# ============================================================================

# Display names earlier versions of this script gave a policy. A tenant that
# already holds a policy under one of these names is treated as already having
# it (skipped, not duplicated under the new name).
$script:LegacyPolicyNames = @{
    'C007' = @('C007 - Block Sign-In Outside UK (UK Users)')
}

function Add-StandardExclusions {
    <#
    .SYNOPSIS
        Applies the two exclusions EVERY policy carries, mutating the policy's
        users block in place:
          1. the NoMFA Exclusion Group (excludeGroups), and
          2. each emergency access account by its own object ID
             (excludeUsers) — a "direct" exclusion.
    .DESCRIPTION
        Both are applied on purpose. The group is what an operator maintains;
        the direct entry is what still protects the account if the group is
        emptied, renamed, deleted or (as happened) never populated.

        Appends rather than overwrites, so policies with their own exclusions
        (C003's admin group, C007's travel groups) keep them. Bracket /
        ContainsKey access throughout: some policies (C010, C011, C012) don't
        define an excludeGroups key at all (they scope via includeGroups or
        includeGuestsOrExternalUsers instead), and dot access on a missing
        hashtable key throws under Set-StrictMode.
    #>
    param(
        [hashtable]$PolicyConfig,
        [string]$NoMfaGroupId,
        [string[]]$EmergencyAccessUserIds
    )

    $usersBlock = $PolicyConfig.conditions.users

    $currentGroups = if ($usersBlock.ContainsKey('excludeGroups')) {
        @($usersBlock['excludeGroups']) | Where-Object { $_ }
    } else { @() }
    if ($NoMfaGroupId -and $currentGroups -notcontains $NoMfaGroupId) {
        $usersBlock['excludeGroups'] = @($currentGroups) + $NoMfaGroupId
    }

    $emergencyIds = @($EmergencyAccessUserIds | Where-Object { $_ })
    if ($emergencyIds.Count -gt 0) {
        $currentUsers = if ($usersBlock.ContainsKey('excludeUsers')) {
            @($usersBlock['excludeUsers']) | Where-Object { $_ }
        } else { @() }
        $usersBlock['excludeUsers'] = @(@($currentUsers) + $emergencyIds | Select-Object -Unique)
    }

    return $PolicyConfig
}

function Get-MissingStandardExclusions {
    <#
    .SYNOPSIS
        Says which of the two standard exclusions (NoMFA Exclusion Group,
        emergency access accounts) a policy that ALREADY EXISTS lacks.
    .DESCRIPTION
        Read-only. Property lookups go through PSObject.Properties so a
        policy object without a Users block doesn't throw under StrictMode.
    #>
    param(
        $ExistingPolicy,
        [string]$NoMfaGroupId,
        [string[]]$EmergencyAccessUserIds
    )

    $excludedGroups = @()
    $excludedUsers = @()
    $conditions = if ($ExistingPolicy -and $ExistingPolicy.PSObject.Properties['Conditions']) { $ExistingPolicy.Conditions } else { $null }
    $users = if ($conditions -and $conditions.PSObject.Properties['Users']) { $conditions.Users } else { $null }
    if ($users) {
        if ($users.PSObject.Properties['ExcludeGroups']) { $excludedGroups = @($users.ExcludeGroups | Where-Object { $_ }) }
        if ($users.PSObject.Properties['ExcludeUsers']) { $excludedUsers = @($users.ExcludeUsers | Where-Object { $_ }) }
    }

    $groupMissing = [bool]$NoMfaGroupId -and ($excludedGroups -notcontains $NoMfaGroupId)
    $missingUserIds = @($EmergencyAccessUserIds | Where-Object { $_ -and ($excludedUsers -notcontains $_) })

    return @{
        GroupMissing = $groupMissing
        UserIds      = $missingUserIds
        Any          = ($groupMissing -or $missingUserIds.Count -gt 0)
    }
}

function Add-StandardExclusionsToExistingPolicy {
    <#
    .SYNOPSIS
        Adds the NoMFA Exclusion Group and the emergency access accounts to
        a policy that already exists. Nothing else on the policy is changed.
    .DESCRIPTION
        Reads the policy's users block as it stands, appends the two
        exclusions (Add-StandardExclusions, so existing exclusions are kept
        and nothing is duplicated) and writes the whole users block back.
        The whole block is sent, not just the two lists, so the result is
        the same whether Graph merges or replaces the block on update. The
        policy's state, locations, apps and grant controls are not sent.
    #>
    param(
        [string]$PolicyId,
        [string]$NoMfaGroupId,
        [string[]]$EmergencyAccessUserIds
    )

    $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$PolicyId"
    try {
        $current = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        $usersBlock = $current['conditions']['users']
        $wrapper = @{ conditions = @{ users = $usersBlock } }
        $null = Add-StandardExclusions -PolicyConfig $wrapper -NoMfaGroupId $NoMfaGroupId `
            -EmergencyAccessUserIds $EmergencyAccessUserIds

        $null = Invoke-MgGraphRequest -Method PATCH -Uri $uri -ContentType 'application/json' `
            -Body ($wrapper | ConvertTo-Json -Depth 10) -ErrorAction Stop
        return @{ Success = $true }
    }
    catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Test-ExistingC007NeedsUpdate {
    <#
    .SYNOPSIS
        True when a C007 that already exists is not in the current design:
        it has an older name, is not scoped to all users, or its excluded
        locations hold "AllTrusted" or no named location at all.
    .DESCRIPTION
        Read-only. Its state (Enabled / Report-only) is deliberately not
        part of the test: a C007 already in the current design that someone
        has enabled after review must be left alone.
    #>
    param(
        $ExistingPolicy,
        [string]$ExpectedName
    )

    if ([string]$ExistingPolicy.DisplayName -ne $ExpectedName) { return $true }

    $includeUsers = @()
    $excludeLocations = @()
    $conditions = if ($ExistingPolicy.PSObject.Properties['Conditions']) { $ExistingPolicy.Conditions } else { $null }
    if ($conditions) {
        $users = if ($conditions.PSObject.Properties['Users']) { $conditions.Users } else { $null }
        if ($users -and $users.PSObject.Properties['IncludeUsers']) { $includeUsers = @($users.IncludeUsers | Where-Object { $_ }) }
        $locations = if ($conditions.PSObject.Properties['Locations']) { $conditions.Locations } else { $null }
        if ($locations -and $locations.PSObject.Properties['ExcludeLocations']) { $excludeLocations = @($locations.ExcludeLocations | Where-Object { $_ }) }
    }

    if ($includeUsers -notcontains 'All') { return $true }
    if ($excludeLocations -contains 'AllTrusted') { return $true }
    if ($excludeLocations.Count -eq 0) { return $true }
    return $false
}

function Update-ExistingC007 {
    <#
    .SYNOPSIS
        Brings a C007 that already exists up to the current design.
    .DESCRIPTION
        Sets, on the existing policy:
          - the current name
          - Report-only (always: the change makes the policy apply to people
            it did not apply to before, so it must be reviewed before it
            enforces again)
          - all users, with the old include group removed
          - excluded locations = the named location(s) only, never
            "AllTrusted" ("Selected networks and locations" in the portal)
          - the definition's excluded groups and partner (GDAP) exclusion,
            plus the NoMFA Exclusion Group and emergency access accounts
        Exclusions already on the policy (users, groups, roles, named
        locations) are kept. Apps, client app types and grant controls are
        not sent, so they stay as they are.
    #>
    param(
        [string]$PolicyId,
        [hashtable]$PolicyConfig,
        [string]$NoMfaGroupId,
        [string[]]$EmergencyAccessUserIds
    )

    $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$PolicyId"
    try {
        $current = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        $usersBlock = $current['conditions']['users']
        $targetUsers = $PolicyConfig.conditions.users

        $usersBlock['includeUsers'] = @('All')
        $usersBlock['includeGroups'] = @()
        $usersBlock['includeRoles'] = @()
        $usersBlock['includeGuestsOrExternalUsers'] = $null

        $currentGroups = if ($usersBlock.ContainsKey('excludeGroups')) { @($usersBlock['excludeGroups'] | Where-Object { $_ }) } else { @() }
        $targetGroups = if ($targetUsers.ContainsKey('excludeGroups')) { @($targetUsers['excludeGroups'] | Where-Object { $_ }) } else { @() }
        $usersBlock['excludeGroups'] = @(@($currentGroups) + @($targetGroups) | Select-Object -Unique)

        if ($targetUsers.ContainsKey('excludeGuestsOrExternalUsers') -and $targetUsers['excludeGuestsOrExternalUsers']) {
            $usersBlock['excludeGuestsOrExternalUsers'] = $targetUsers['excludeGuestsOrExternalUsers']
        }

        $wrapper = @{ conditions = @{ users = $usersBlock } }
        $null = Add-StandardExclusions -PolicyConfig $wrapper -NoMfaGroupId $NoMfaGroupId `
            -EmergencyAccessUserIds $EmergencyAccessUserIds

        # Named locations already excluded are kept; "AllTrusted" is dropped
        $currentLocations = @()
        $currentLocationBlock = $current['conditions']['locations']
        if ($currentLocationBlock -and $currentLocationBlock.ContainsKey('excludeLocations')) {
            $currentLocations = @($currentLocationBlock['excludeLocations'] | Where-Object { $_ -and $_ -ne 'AllTrusted' })
        }
        $targetLocations = @($PolicyConfig.conditions.locations.excludeLocations | Where-Object { $_ })
        $excludeLocations = @(@($currentLocations) + @($targetLocations) | Select-Object -Unique)
        if ($excludeLocations.Count -eq 0) { throw 'No UK named location to exclude' }

        $body = @{
            displayName = $PolicyConfig.displayName
            state       = 'enabledForReportingButNotEnforced'
            conditions  = @{
                users     = $usersBlock
                locations = @{
                    includeLocations = @('All')
                    excludeLocations = $excludeLocations
                }
            }
        }
        $null = Invoke-MgGraphRequest -Method PATCH -Uri $uri -ContentType 'application/json' `
            -Body ($body | ConvertTo-Json -Depth 10) -ErrorAction Stop
        return @{ Success = $true; WasEnabled = ([string]$current['state'] -eq 'enabled') }
    }
    catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Test-LocationExclusionHiddenByPortal {
    <#
    .SYNOPSIS
        True when a policy's excluded locations hold "AllTrusted" TOGETHER
        with a named location — the combination older versions of this script
        gave C007.
    .DESCRIPTION
        The Entra portal cannot show both: it displays only "All trusted
        networks and locations", and saving the policy from the portal keeps
        only that, silently dropping the named location. For C007 that
        removes the UK exclusion and blocks every UK sign-in.
    #>
    param([string[]]$ExcludeLocations)

    $locations = @($ExcludeLocations | Where-Object { $_ })
    return ($locations -contains 'AllTrusted') -and (@($locations | Where-Object { $_ -ne 'AllTrusted' }).Count -gt 0)
}

function New-ConditionalAccessPolicy {
    param(
        [hashtable]$PolicyConfig,
        [string]$NoMfaGroupId,
        [string[]]$EmergencyAccessUserIds
    )

    $policyName = $PolicyConfig.displayName

    try {
        # Check if policy already exists — under its current name, or under a
        # name an earlier version of this script used for the same policy
        $existingPolicy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$policyName'" -ErrorAction SilentlyContinue | Select-Object -First 1

        if (!$existingPolicy) {
            $code = Get-PolicyCode -DisplayName $policyName
            if ($script:LegacyPolicyNames.ContainsKey($code)) {
                foreach ($legacyName in $script:LegacyPolicyNames[$code]) {
                    $fullLegacyName = "$($script:RunConfig.NamePrefix)$legacyName"
                    $existingPolicy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$fullLegacyName'" -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($existingPolicy) {
                        Write-Host "     Found under its previous name: $fullLegacyName" -ForegroundColor Yellow
                        break
                    }
                }
            }
        }

        if ($existingPolicy) {
            Write-Host "     Already exists (skipped)" -ForegroundColor Yellow

            # Existing policies are not modified here. Two things are checked
            # and reported back: a known-dangerous location state, and whether
            # the standard exclusions are missing (the caller offers to add
            # those once every policy has been looked at).
            $existingLocations = @()
            if ($existingPolicy.Conditions -and $existingPolicy.Conditions.Locations) {
                $existingLocations = @($existingPolicy.Conditions.Locations.ExcludeLocations)
            }
            $warning = $null
            if (Test-LocationExclusionHiddenByPortal -ExcludeLocations $existingLocations) {
                $warning = "$($existingPolicy.DisplayName) excludes a named location together with 'All trusted'. The portal shows only 'All trusted', and saving the policy from the portal drops the named location (for C007, that blocks every UK sign-in). Do NOT save it from the portal; set its excluded locations to the named location only."
                Write-Host "     WARNING: this policy excludes a named location together with 'All trusted'." -ForegroundColor Red
                Write-Host "     The portal shows only 'All trusted', and saving the policy from the portal drops" -ForegroundColor Red
                Write-Host "     the named location - for C007 that blocks every UK sign-in. Do NOT save it from" -ForegroundColor Red
                Write-Host "     the portal. Set its excluded locations to the named location only." -ForegroundColor Red
            }
            $missing = Get-MissingStandardExclusions -ExistingPolicy $existingPolicy -NoMfaGroupId $NoMfaGroupId `
                -EmergencyAccessUserIds $EmergencyAccessUserIds
            if ($missing.Any) {
                Write-Host "     Does not exclude the emergency access account / NoMFA Exclusion Group" -ForegroundColor Yellow
            }
            $needsUpdate = $false
            if ((Get-PolicyCode -DisplayName $policyName) -eq 'C007') {
                $needsUpdate = Test-ExistingC007NeedsUpdate -ExistingPolicy $existingPolicy -ExpectedName $policyName
                if ($needsUpdate) {
                    Write-Host "     Not in the current C007 design (name, all users, UK location only)" -ForegroundColor Yellow
                }
            }
            return @{ Success = $true; Policy = $existingPolicy; Skipped = $true; Warning = $warning; MissingExclusions = $missing.Any; NeedsUpdate = $needsUpdate }
        }

        # NoMFA group + emergency access accounts, on every policy
        $null = Add-StandardExclusions -PolicyConfig $PolicyConfig -NoMfaGroupId $NoMfaGroupId `
            -EmergencyAccessUserIds $EmergencyAccessUserIds

        # Create policy
        $newPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicyConfig -ErrorAction Stop

        Write-Host "     Created successfully (ID: $($newPolicy.Id))" -ForegroundColor Green
        return @{ Success = $true; Policy = $newPolicy; Skipped = $false; Warning = $null; MissingExclusions = $false; NeedsUpdate = $false }
    }
    catch {
        Write-Host "     Failed: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ============================================================================
# COMPARISON WITH THE TENANT (read-only)
# ============================================================================

function Get-ComparisonValue {
    <#
    .SYNOPSIS
        Walks nested hashtables by key path; $null when any step is missing.
    #>
    param($Table, [string[]]$Path)

    $node = $Table
    foreach ($key in $Path) {
        if ($null -eq $node -or $node -isnot [System.Collections.IDictionary] -or !$node.Contains($key)) { return $null }
        $node = $node[$key]
    }
    return $node
}

function ConvertTo-ComparisonSet {
    <#
    .SYNOPSIS
        Normalises a policy value (array, single string, comma-separated
        string or $null) to a sorted, lower-case, de-duplicated string array
        so two values can be compared whatever shape Graph returned them in.
        "None" (what Graph stores for an empty include list) counts as empty.
    #>
    param($Value)

    $items = @()
    foreach ($entry in @($Value)) {
        if ($null -eq $entry) { continue }
        foreach ($part in ([string]$entry -split ',')) {
            $text = $part.Trim().ToLowerInvariant()
            if ($text -and $text -ne 'none' -and $items -notcontains $text) { $items += $text }
        }
    }
    return @($items | Sort-Object)
}

function Format-ComparisonSet {
    <#
    .SYNOPSIS
        Renders a normalised set for the report, swapping object IDs for
        the names in $Labels where known.
    #>
    param([string[]]$Set, [hashtable]$Labels = @{})

    $items = @($Set | Where-Object { $_ })
    if ($items.Count -eq 0) { return '(none)' }
    return (@($items | ForEach-Object { if ($Labels.ContainsKey($_)) { $Labels[$_] } else { $_ } }) -join ', ')
}

function Compare-PolicyToDefinition {
    <#
    .SYNOPSIS
        Compares one policy as it exists in the tenant (raw Graph hashtable)
        with this script's definition of it. Read-only.
    .DESCRIPTION
        Returns Differences (settings where the tenant's policy is not what
        the script would create) and Notes (things worth knowing that are
        not wrong, such as extra exclusions added by hand).

        Included/targeted settings must equal the definition. Exclusions
        only have to CONTAIN the definition's: extra exclusions are noted,
        not treated as a difference. The policy's state (Enabled /
        Report-only) is reported separately by the caller and is never a
        difference, because enabling a policy after review is expected.

        The definition passed in must already carry the standard exclusions
        (Add-StandardExclusions).
    #>
    param(
        [hashtable]$Definition,
        $Existing,
        [hashtable]$Labels = @{}
    )

    $differences = @()
    $notes = @()

    if ([string]$Existing['displayName'] -ne [string]$Definition.displayName) {
        $differences += "Name: tenant has '$($Existing['displayName'])', design has '$($Definition.displayName)'"
    }

    # Settings that must be the same on both sides
    $exactChecks = @(
        @{ Label = 'Applies to users';        Path = @('conditions', 'users', 'includeUsers') }
        @{ Label = 'Applies to groups';       Path = @('conditions', 'users', 'includeGroups') }
        @{ Label = 'Applies to roles';        Path = @('conditions', 'users', 'includeRoles') }
        @{ Label = 'Applies to guest types';  Path = @('conditions', 'users', 'includeGuestsOrExternalUsers', 'guestOrExternalUserTypes') }
        @{ Label = 'Target resources';        Path = @('conditions', 'applications', 'includeApplications') }
        @{ Label = 'Excluded resources';      Path = @('conditions', 'applications', 'excludeApplications') }
        @{ Label = 'Client app types';        Path = @('conditions', 'clientAppTypes') }
        @{ Label = 'Included platforms';      Path = @('conditions', 'platforms', 'includePlatforms') }
        @{ Label = 'Excluded platforms';      Path = @('conditions', 'platforms', 'excludePlatforms') }
        @{ Label = 'Included locations';      Path = @('conditions', 'locations', 'includeLocations') }
        @{ Label = 'User risk levels';        Path = @('conditions', 'userRiskLevels') }
        @{ Label = 'Sign-in risk levels';     Path = @('conditions', 'signInRiskLevels') }
        @{ Label = 'Authentication flows';    Path = @('conditions', 'authenticationFlows', 'transferMethods') }
        @{ Label = 'Grant controls';          Path = @('grantControls', 'builtInControls') }
    )
    foreach ($check in $exactChecks) {
        $want = @(ConvertTo-ComparisonSet (Get-ComparisonValue -Table $Definition -Path $check.Path))
        $have = @(ConvertTo-ComparisonSet (Get-ComparisonValue -Table $Existing -Path $check.Path))
        if (($want -join '|') -ne ($have -join '|')) {
            $differences += "$($check.Label): tenant has $(Format-ComparisonSet -Set $have -Labels $Labels), design has $(Format-ComparisonSet -Set $want -Labels $Labels)"
        }
    }

    # "Require one / require all" only means something with several controls
    $wantControls = @(ConvertTo-ComparisonSet (Get-ComparisonValue -Table $Definition -Path @('grantControls', 'builtInControls')))
    if ($wantControls.Count -gt 1) {
        $wantOperator = ([string](Get-ComparisonValue -Table $Definition -Path @('grantControls', 'operator'))).ToUpperInvariant()
        $haveOperator = ([string](Get-ComparisonValue -Table $Existing -Path @('grantControls', 'operator'))).ToUpperInvariant()
        if ($wantOperator -and $wantOperator -ne $haveOperator) {
            $differences += "Grant operator: tenant has $(if ($haveOperator) { $haveOperator } else { '(none)' }), design has $wantOperator"
        }
    }

    # Exclusions: the tenant's policy must contain the definition's
    $subsetChecks = @(
        @{ Missing = 'Does not exclude group';    Extra = 'other group(s)';   Path = @('conditions', 'users', 'excludeGroups') }
        @{ Missing = 'Does not exclude account';  Extra = 'other user(s)';    Path = @('conditions', 'users', 'excludeUsers') }
        @{ Missing = 'Does not exclude role';     Extra = 'other role(s)';    Path = @('conditions', 'users', 'excludeRoles') }
        @{ Missing = 'Does not exclude location'; Extra = 'other location(s)'; Path = @('conditions', 'locations', 'excludeLocations') }
    )
    foreach ($check in $subsetChecks) {
        $want = @(ConvertTo-ComparisonSet (Get-ComparisonValue -Table $Definition -Path $check.Path))
        $have = @(ConvertTo-ComparisonSet (Get-ComparisonValue -Table $Existing -Path $check.Path))
        foreach ($item in $want) {
            if ($have -notcontains $item) {
                $differences += "$($check.Missing): $(Format-ComparisonSet -Set @($item) -Labels $Labels)"
            }
        }
        $extra = @($have | Where-Object { $want -notcontains $_ })
        if ($extra -contains 'alltrusted') {
            $differences += "Excludes 'All trusted networks and locations': the portal then hides any named location next to it and drops it when the policy is saved"
            $extra = @($extra | Where-Object { $_ -ne 'alltrusted' })
        }
        if ($extra.Count -gt 0) {
            $notes += "Also excludes $($extra.Count) $($check.Extra): $(Format-ComparisonSet -Set $extra -Labels $Labels)"
        }
    }

    # Partner (service provider / GDAP) tenants
    $wantTenants = @(ConvertTo-ComparisonSet (Get-ComparisonValue -Table $Definition -Path @('conditions', 'users', 'excludeGuestsOrExternalUsers', 'externalTenants', 'members')))
    if ($wantTenants.Count -gt 0) {
        $haveTypes = @(ConvertTo-ComparisonSet (Get-ComparisonValue -Table $Existing -Path @('conditions', 'users', 'excludeGuestsOrExternalUsers', 'guestOrExternalUserTypes')))
        $haveTenants = @()
        if ($haveTypes -contains 'serviceprovider') {
            $haveTenants = @(ConvertTo-ComparisonSet (Get-ComparisonValue -Table $Existing -Path @('conditions', 'users', 'excludeGuestsOrExternalUsers', 'externalTenants', 'members')))
        }
        foreach ($tenant in $wantTenants) {
            if ($haveTenants -notcontains $tenant) {
                $differences += "Does not exclude partner (GDAP) sign-ins from tenant $tenant"
            }
        }
    }

    # Session controls: every setting the definition makes must be the same
    $wantSession = Get-ComparisonValue -Table $Definition -Path @('sessionControls')
    if ($wantSession -is [System.Collections.IDictionary]) {
        foreach ($controlName in @($wantSession.Keys)) {
            $wantControl = $wantSession[$controlName]
            if ($wantControl -isnot [System.Collections.IDictionary]) { continue }
            foreach ($settingName in @($wantControl.Keys)) {
                if ([string]$settingName -like '@*') { continue }
                $wantSetting = [string]$wantControl[$settingName]
                $haveSetting = [string](Get-ComparisonValue -Table $Existing -Path @('sessionControls', [string]$controlName, [string]$settingName))
                if ($wantSetting -ne $haveSetting) {
                    $differences += "Session control $controlName.${settingName}: tenant has $(if ($haveSetting) { $haveSetting } else { '(none)' }), design has $wantSetting"
                }
            }
        }
    }

    return @{ Differences = @($differences); Notes = @($notes) }
}

function Get-ExistingPoliciesRaw {
    <#
    .SYNOPSIS
        Every Conditional Access policy in the tenant, as raw Graph
        hashtables. Read-only.
    #>
    $policies = @()
    $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
    while ($uri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        foreach ($policy in @($page['value'])) { if ($policy) { $policies += $policy } }
        $uri = if ($page.ContainsKey('@odata.nextLink')) { $page['@odata.nextLink'] } else { $null }
    }
    return $policies
}

function Get-TenantComparison {
    <#
    .SYNOPSIS
        Compares every policy definition with the tenant. Read-only.
    .DESCRIPTION
        One entry per definition: Status is Missing (not in the tenant),
        Matches, or Differs (with the list of differences). A policy is
        found under its current name or a name an earlier version used.
        The definitions passed in must already carry the standard
        exclusions.
    #>
    param(
        [hashtable[]]$Policies,
        [hashtable]$Labels = @{},
        $ExistingPolicies
    )

    $stateNames = @{
        'enabled'                           = 'Enabled'
        'enabledForReportingButNotEnforced' = 'Report-only'
        'disabled'                          = 'Off'
    }

    $comparison = @()
    foreach ($definition in $Policies) {
        $name = [string]$definition.displayName
        $code = Get-PolicyCode -DisplayName $name
        $names = @($name)
        if ($script:LegacyPolicyNames.ContainsKey($code)) {
            $names += @($script:LegacyPolicyNames[$code] | ForEach-Object { "$($script:RunConfig.NamePrefix)$_" })
        }

        $existing = $null
        foreach ($candidate in $names) {
            $existing = @($ExistingPolicies | Where-Object { $_ -and [string]$_['displayName'] -eq $candidate }) | Select-Object -First 1
            if ($existing) { break }
        }

        if (!$existing) {
            $comparison += @{ Code = $code; Name = $name; Status = 'Missing'; State = ''; Differences = @(); Notes = @() }
            continue
        }

        $detail = Compare-PolicyToDefinition -Definition $definition -Existing $existing -Labels $Labels
        $state = [string]$existing['state']
        $comparison += @{
            Code        = $code
            Name        = $name
            Status      = if (@($detail.Differences).Count -gt 0) { 'Differs' } else { 'Matches' }
            State       = if ($stateNames.ContainsKey($state)) { $stateNames[$state] } else { $state }
            Differences = @($detail.Differences)
            Notes       = @($detail.Notes)
        }
    }
    return $comparison
}

function Show-TenantComparison {
    <#
    .SYNOPSIS
        Prints the comparison produced by Get-TenantComparison.
    #>
    param([hashtable[]]$Comparison)

    Write-Host ("   " + "-" * 50) -ForegroundColor Gray
    foreach ($entry in $Comparison) {
        switch ($entry.Status) {
            'Missing' { Write-Host "   MISSING  $($entry.Name)" -ForegroundColor Cyan }
            'Matches' { Write-Host "   MATCHES  $($entry.Name)  [$($entry.State)]" -ForegroundColor Green }
            default   { Write-Host "   DIFFERS  $($entry.Name)  [$($entry.State)]" -ForegroundColor Yellow }
        }
        foreach ($difference in @($entry.Differences)) {
            Write-Host "              - $difference" -ForegroundColor Yellow
        }
        foreach ($note in @($entry.Notes)) {
            Write-Host "              ($note)" -ForegroundColor Gray
        }
    }
    $missing = @($Comparison | Where-Object { $_.Status -eq 'Missing' }).Count
    $matching = @($Comparison | Where-Object { $_.Status -eq 'Matches' }).Count
    $differs = @($Comparison | Where-Object { $_.Status -eq 'Differs' }).Count
    Write-Host ""
    Write-Host "   Missing: $missing   Matches: $matching   Differs: $differs" -ForegroundColor White
    Write-Host "   Missing = not in this tenant. Differs = in the tenant but not as this script" -ForegroundColor Gray
    Write-Host "   would create it. Enabled / Report-only is shown but is not counted as a difference." -ForegroundColor Gray
}

function Get-TenantStateReadOnly {
    <#
    .SYNOPSIS
        Looks up everything the policies depend on WITHOUT creating or
        changing anything: the groups, the UK named location, the emergency
        access accounts and Security Defaults.
    .DESCRIPTION
        Used by the compare-only run. Test-Prerequisites does the same
        lookups for a normal run but fixes what is missing; this never does.
        A group that does not exist gets a placeholder ID so the policy
        definitions can still be built and compared.
    #>
    $groupPrefix = $script:RunConfig.GroupNamePrefix
    $groupNames = [ordered]@{
        NoMfa   = "${groupPrefix}NoMFA Exclusion Group"
        Admin   = "${groupPrefix}BITS Admin Users"
        GeoIntl = "${groupPrefix}CA-GEO-International"
        Travel  = "${groupPrefix}CA-UK-Travel-Exclusion"
        Byod    = "${groupPrefix}CA-BYOD-Windows"
    }

    $groups = @{}
    foreach ($key in $groupNames.Keys) {
        $name = $groupNames[$key]
        $found = $null
        try {
            $response = Invoke-MgGraphRequest -Method GET -ErrorAction Stop `
                -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$name'&`$select=id,displayName"
            $found = @($response['value']) | Where-Object { $_ } | Select-Object -First 1
        }
        catch {
            Write-Host "   Could not look up group ${name}: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        $groups[$key] = @{
            Name   = $name
            Exists = [bool]$found
            Id     = if ($found) { [string]$found['id'] } else { "missing-group:$name" }
        }
    }

    $emergencyAccounts = @()
    if ($groups['NoMfa'].Exists) {
        try { $emergencyAccounts = @(Get-GroupUserMembers -GroupId $groups['NoMfa'].Id) }
        catch { Write-Host "   Could not read $($groups['NoMfa'].Name) members: $($_.Exception.Message)" -ForegroundColor Yellow }
    }
    $adminMemberCount = 0
    if ($groups['Admin'].Exists) {
        try { $adminMemberCount = @(Get-GroupUserMembers -GroupId $groups['Admin'].Id).Count }
        catch { Write-Host "   Could not read $($groups['Admin'].Name) members: $($_.Exception.Message)" -ForegroundColor Yellow }
    }

    $locationName = "$($script:RunConfig.NamePrefix)UK"
    $ukLocation = $null
    try {
        $locations = Invoke-MgGraphRequest -Method GET -ErrorAction Stop `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"
        $ukLocation = @($locations['value']) | Where-Object { $_ -and $_['displayName'] -eq $locationName } | Select-Object -First 1
    }
    catch {
        Write-Host "   Could not read named locations: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    $securityDefaults = $null
    try {
        $defaults = Invoke-MgGraphRequest -Method GET -ErrorAction Stop `
            -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
        $securityDefaults = [bool]$defaults['isEnabled']
    }
    catch {
        Write-Host "   Could not read Security Defaults: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    return @{
        Groups                  = $groups
        EmergencyAccounts       = $emergencyAccounts
        AdminMemberCount        = $adminMemberCount
        UkLocationName          = $locationName
        UkLocationExists        = [bool]$ukLocation
        UkLocationId            = if ($ukLocation) { [string]$ukLocation['id'] } else { "missing-location:$locationName" }
        SecurityDefaultsEnabled = $securityDefaults
    }
}

function New-ComparisonLabels {
    <#
    .SYNOPSIS
        Builds the ID -> name table the report uses in place of object IDs.
    #>
    param([hashtable]$Entries)

    $labels = @{}
    foreach ($id in @($Entries.Keys)) {
        if ($id) { $labels[([string]$id).ToLowerInvariant()] = [string]$Entries[$id] }
    }
    # Directory Synchronization Accounts — the role C003 excludes
    $labels['d29b2b05-8046-44ba-8758-1e26182fcf32'] = 'Directory Synchronization Accounts'
    return $labels
}

function Start-CompareOnly {
    <#
    .SYNOPSIS
        The read-only run: reports what this tenant has against what the
        script would create, and changes nothing. No group, named location,
        policy or group membership is created or modified, and Security
        Defaults is left as it is.
    #>
    Write-Host ""
    Write-Host "  COMPARE ONLY - nothing in the tenant will be created or changed" -ForegroundColor Cyan
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    $context = Get-MgContext
    if (!$context) {
        Write-Host "   Not connected to Microsoft Graph. Please connect using the main menu first." -ForegroundColor Red
        if ($ResultPath) {
            @{ Success = $false; CompareOnly = $true; Error = 'Not connected to Microsoft Graph' } | ConvertTo-Json | Set-Content -Path $ResultPath -Encoding UTF8
        }
        return
    }

    $tenantState = Get-TenantStateReadOnly
    $groups = $tenantState.Groups
    $partnerTenantIds = @(Get-PartnerTenantIds -CurrentTenantId $context.TenantId)
    $emergencyIds = @($tenantState.EmergencyAccounts | ForEach-Object { $_['id'] })

    # What the policies depend on
    Write-Host ""
    Write-Host "  WHAT THE POLICIES DEPEND ON" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray
    $environment = @()
    foreach ($key in @('NoMfa', 'Admin', 'GeoIntl', 'Travel', 'Byod')) {
        $group = $groups[$key]
        $detail = ''
        if ($group.Exists -and $key -eq 'NoMfa') { $detail = "  ($(@($tenantState.EmergencyAccounts).Count) user member(s))" }
        if ($group.Exists -and $key -eq 'Admin') { $detail = "  ($($tenantState.AdminMemberCount) user member(s))" }
        Write-Host "   $(if ($group.Exists) { 'FOUND  ' } else { 'MISSING' })  Group: $($group.Name)$detail" `
            -ForegroundColor $(if ($group.Exists) { 'Green' } else { 'Yellow' })
        $environment += @{ Item = "Group: $($group.Name)"; Exists = $group.Exists }
    }
    Write-Host "   $(if ($tenantState.UkLocationExists) { 'FOUND  ' } else { 'MISSING' })  Named location: $($tenantState.UkLocationName)" `
        -ForegroundColor $(if ($tenantState.UkLocationExists) { 'Green' } else { 'Yellow' })
    $environment += @{ Item = "Named location: $($tenantState.UkLocationName)"; Exists = $tenantState.UkLocationExists }

    if (@($tenantState.EmergencyAccounts).Count -gt 0) {
        foreach ($account in $tenantState.EmergencyAccounts) {
            Write-Host "   FOUND    Emergency access account: $($account['userPrincipalName'])" -ForegroundColor Green
        }
    }
    else {
        Write-Host "   MISSING  Emergency access account: the NoMFA Exclusion Group has no user members" -ForegroundColor Red
    }
    $environment += @{ Item = 'Emergency access account'; Exists = (@($tenantState.EmergencyAccounts).Count -gt 0) }

    if ($groups['Admin'].Exists -and $tenantState.AdminMemberCount -eq 0) {
        Write-Host "   NOTE     BITS Admin Users has no members: no admin account is excluded from C003" -ForegroundColor Yellow
    }
    if ($partnerTenantIds.Count -gt 0) {
        Write-Host "   CONFIG   Partner (GDAP) tenants excluded from C003/C007: $($partnerTenantIds -join ', ')" -ForegroundColor Gray
    }
    if ($tenantState.SecurityDefaultsEnabled -eq $true) {
        Write-Host "   NOTE     Security Defaults is ON: a normal run turns it off before creating policies" -ForegroundColor Yellow
    }

    # The policies
    $policies = @(Get-PolicyDefinitions -NoMfaGroupId $groups['NoMfa'].Id -PolicyState 'enabledForReportingButNotEnforced' `
            -GeoIntlGroupId $groups['GeoIntl'].Id -UkLocationId $tenantState.UkLocationId `
            -ByodWindowsGroupId $groups['Byod'].Id -UkTravelExclusionGroupId $groups['Travel'].Id `
            -AdminGroupId $groups['Admin'].Id -PartnerTenantIds $partnerTenantIds)
    foreach ($policy in $policies) {
        $null = Add-StandardExclusions -PolicyConfig $policy -NoMfaGroupId $groups['NoMfa'].Id -EmergencyAccessUserIds $emergencyIds
    }

    $labelEntries = @{ $tenantState.UkLocationId = "$($tenantState.UkLocationName) named location" }
    foreach ($key in @($groups.Keys)) {
        $labelEntries[$groups[$key].Id] = if ($groups[$key].Exists) { $groups[$key].Name } else { "$($groups[$key].Name) (group does not exist)" }
    }
    foreach ($account in $tenantState.EmergencyAccounts) { $labelEntries[$account['id']] = [string]$account['userPrincipalName'] }
    $labels = New-ComparisonLabels -Entries $labelEntries

    Write-Host ""
    Write-Host "  POLICIES: THIS TENANT AGAINST THE SCRIPT'S DESIGN" -ForegroundColor Yellow
    $comparison = @()
    try {
        $comparison = @(Get-TenantComparison -Policies $policies -Labels $labels -ExistingPolicies @(Get-ExistingPoliciesRaw))
    }
    catch {
        Write-Host "   Could not read the tenant's policies: $($_.Exception.Message)" -ForegroundColor Red
        if ($ResultPath) {
            @{ Success = $false; CompareOnly = $true; Error = $_.Exception.Message } | ConvertTo-Json | Set-Content -Path $ResultPath -Encoding UTF8
        }
        return
    }
    Show-TenantComparison -Comparison $comparison

    Write-Host ""
    Write-Host "  Nothing was created or changed. Run again and choose to create and update" -ForegroundColor Cyan
    Write-Host "  when you want the missing policies created and the differences offered as fixes." -ForegroundColor Cyan
    Write-Host "  Only C007 and missing emergency-account exclusions are fixed by the script;" -ForegroundColor Gray
    Write-Host "  any other difference is for you to review and change by hand." -ForegroundColor Gray

    if ($ResultPath) {
        @{
            Success     = $true
            CompareOnly = $true
            Comparison  = @($comparison)
            Environment = @($environment)
        } | ConvertTo-Json -Depth 6 | Set-Content -Path $ResultPath -Encoding UTF8
        Write-Host "  Results written to $ResultPath" -ForegroundColor Gray
    }

    if (!$script:NonInteractive) {
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
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

    # Compare only, or compare and then create/update? Anything other than an
    # explicit "2" is the read-only run, so a stray Enter changes nothing.
    if (!$script:CompareOnly -and !$script:NonInteractive) {
        Write-Host "  [1] Compare only - report what this tenant has against the script's design." -ForegroundColor Gray
        Write-Host "      Creates and changes nothing." -ForegroundColor Gray
        Write-Host "  [2] Compare, then create missing policies and offer fixes" -ForegroundColor Gray
        Write-Host ""
        $modeChoice = Read-Host "  Choose 1 or 2 (default 1)"
        if ([string]$modeChoice -notmatch '^\s*2\s*$') { $script:CompareOnly = $true }
    }
    if ($script:CompareOnly) {
        Start-CompareOnly
        return
    }

    # Step 1: Prerequisites (with auto-fix)
    Write-Host "  STEP 1: Prerequisites" -ForegroundColor Yellow
    $prereqResult = Test-Prerequisites

    if (!$prereqResult.Success) {
        Write-Host ""
        Write-Host "  Prerequisites not met. Please resolve issues and try again." -ForegroundColor Red
        if ($ResultPath) {
            $prereqError = if ($prereqResult.ContainsKey('Error')) { $prereqResult.Error } else { 'Prerequisites not met' }
            @{ Success = $false; Error = $prereqError } | ConvertTo-Json | Set-Content -Path $ResultPath -Encoding UTF8
        }
        if (!$script:NonInteractive) {
            Write-Host ""
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        }
        return
    }

    $noMfaGroupId    = $prereqResult.NoMfaGroupId
    $geoIntlGroupId  = $prereqResult.GeoIntlGroupId
    $ukLocationId    = $prereqResult.UkLocationId
    $byodWindowsGroupId       = $prereqResult.ByodWindowsGroupId
    $ukTravelExclusionGroupId = $prereqResult.UkTravelExclusionGroupId
    $emergencyAccessUserIds   = @($prereqResult.EmergencyAccessUserIds)
    $emergencyAccessUpns      = @($prereqResult.EmergencyAccessUpns)
    $adminGroupId             = $prereqResult.AdminGroupId
    $adminGroupHasMembers     = [bool]$prereqResult.AdminGroupHasMembers
    $partnerTenantIds         = @($prereqResult.PartnerTenantIds)

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
        -GeoIntlGroupId $geoIntlGroupId -UkLocationId $ukLocationId `
        -ByodWindowsGroupId $byodWindowsGroupId -UkTravelExclusionGroupId $ukTravelExclusionGroupId `
        -AdminGroupId $adminGroupId -PartnerTenantIds $partnerTenantIds
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
        Write-Host "   Policies that can block sign-ins are always Report-only and are not asked about." -ForegroundColor Cyan
    }
    Set-PolicyStates -Policies $policies

    # Step 4: Compare with what the tenant already has (read-only)
    Write-Host ""
    Write-Host "  STEP 4: Comparison With This Tenant" -ForegroundColor Yellow
    $comparison = @()
    try {
        # The standard exclusions go on now so the comparison sees the policy
        # exactly as it would be created (applying them again later is a no-op)
        foreach ($policy in $policies) {
            $null = Add-StandardExclusions -PolicyConfig $policy -NoMfaGroupId $noMfaGroupId -EmergencyAccessUserIds $emergencyAccessUserIds
        }
        $labelEntries = @{}
        if ($noMfaGroupId) { $labelEntries[$noMfaGroupId] = 'NoMFA Exclusion Group' }
        if ($geoIntlGroupId) { $labelEntries[$geoIntlGroupId] = 'CA-GEO-International' }
        if ($ukTravelExclusionGroupId) { $labelEntries[$ukTravelExclusionGroupId] = 'CA-UK-Travel-Exclusion' }
        if ($byodWindowsGroupId) { $labelEntries[$byodWindowsGroupId] = 'CA-BYOD-Windows' }
        if ($adminGroupId) { $labelEntries[$adminGroupId] = 'BITS Admin Users' }
        if ($ukLocationId) { $labelEntries[$ukLocationId] = 'UK named location' }
        for ($i = 0; $i -lt $emergencyAccessUserIds.Count; $i++) {
            $labelEntries[$emergencyAccessUserIds[$i]] = if ($i -lt $emergencyAccessUpns.Count) { $emergencyAccessUpns[$i] } else { 'emergency access account' }
        }
        $comparison = @(Get-TenantComparison -Policies $policies -Labels (New-ComparisonLabels -Entries $labelEntries) `
                -ExistingPolicies @(Get-ExistingPoliciesRaw))
        Show-TenantComparison -Comparison $comparison
    }
    catch {
        Write-Host "   Could not compare with the tenant: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # Step 5: Preview
    Write-Host ""
    Write-Host "  STEP 5: Preview" -ForegroundColor Yellow
    Show-PolicyPreview -Policies $policies -NoMfaGroupId $noMfaGroupId `
        -EmergencyAccessUpns $emergencyAccessUpns -PartnerTenantIds $partnerTenantIds `
        -AdminGroupFound ([bool]$adminGroupId) -AdminGroupHasMembers $adminGroupHasMembers

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
    Write-Host "  STEP 6: Creating Policies" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    $results = @{
        Created = @()
        Skipped = @()
        Failed = @()
        Warnings = @()
        ExclusionsAdded = @()
        ExclusionsMissing = @()
        Updated = @()
        NotUpdated = @()
    }
    $needExclusions = @()
    $needUpdate = @()

    foreach ($policy in $policies) {
        Write-Host "   $($policy.DisplayName)..." -ForegroundColor White

        $result = New-ConditionalAccessPolicy -PolicyConfig $policy -NoMfaGroupId $noMfaGroupId `
            -EmergencyAccessUserIds $emergencyAccessUserIds

        if ($result.Success) {
            if ($result.Warning -and !$result.NeedsUpdate) { $results.Warnings += $result.Warning }
            if ($result.Skipped) {
                $results.Skipped += $policy.DisplayName
                if ($result.NeedsUpdate) {
                    $needUpdate += @{ Id = $result.Policy.Id; Name = $result.Policy.DisplayName; Config = $policy; Warning = $result.Warning }
                }
                elseif ($result.MissingExclusions) {
                    $needExclusions += @{ Id = $result.Policy.Id; Name = $result.Policy.DisplayName }
                }
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

    # An existing C007 that is not in the current design: offer to update it
    foreach ($item in $needUpdate) {
        Write-Host ""
        Write-Host "   $($item.Name) already exists and is NOT in the current design." -ForegroundColor Yellow
        Write-Host "   Updating it will:" -ForegroundColor Yellow
        Write-Host "     - rename it to $($item.Config.displayName)" -ForegroundColor Gray
        Write-Host "     - apply it to ALL users (guests included) instead of a group" -ForegroundColor Gray
        Write-Host "     - exclude the UK named location only (Selected networks and locations)," -ForegroundColor Gray
        Write-Host "       removing 'All trusted networks and locations'" -ForegroundColor Gray
        Write-Host "     - add the emergency access, NoMFA, international, travel and partner exclusions" -ForegroundColor Gray
        Write-Host "     - set it to REPORT-ONLY, even if it is Enabled now. It will stop blocking" -ForegroundColor Gray
        Write-Host "       sign-ins from outside the UK until you enable it again after review." -ForegroundColor Gray

        $doUpdate = $false
        if ($script:NonInteractive) {
            $doUpdate = [bool]$script:RunConfig.UpdateExistingC007
            if (!$doUpdate) {
                Write-Host "   Non-interactive mode: UpdateExistingC007 is off - left unchanged" -ForegroundColor Yellow
            }
        }
        else {
            $answer = Read-Host "   Update this policy now? (Y/N)"
            $doUpdate = $answer -like "Y*"
        }

        $update = if ($doUpdate) {
            Update-ExistingC007 -PolicyId $item.Id -PolicyConfig $item.Config -NoMfaGroupId $noMfaGroupId `
                -EmergencyAccessUserIds $emergencyAccessUserIds
        } else { $null }

        if ($update -and $update.Success) {
            Write-Host "   Updated: $($item.Config.displayName) (now Report-only)" -ForegroundColor Green
            $results.Updated += $item.Config.displayName
            if ($update.WasEnabled) {
                $results.Warnings += "$($item.Config.displayName) was Enabled and is now Report-only: it is NOT blocking sign-ins from outside the UK until you enable it again."
            }
        }
        else {
            if ($update) { Write-Host "   Could not update $($item.Name): $($update.Error)" -ForegroundColor Red }
            $results.NotUpdated += $item.Name
            if ($item.Warning) { $results.Warnings += $item.Warning }
            # Left as it was, so it still needs the standard exclusions checked
            $needExclusions += @{ Id = $item.Id; Name = $item.Name }
        }
    }

    # Existing policies that lack the standard exclusions: offer to add them
    if ($needExclusions.Count -gt 0) {
        Write-Host ""
        Write-Host "   These existing policies do NOT exclude the emergency access account and/or" -ForegroundColor Yellow
        Write-Host "   the NoMFA Exclusion Group:" -ForegroundColor Yellow
        foreach ($item in $needExclusions) {
            Write-Host "     - $($item.Name)" -ForegroundColor White
        }

        $addThem = $false
        if ($script:NonInteractive) {
            $addThem = [bool]$script:RunConfig.UpdateExistingExclusions
            if (!$addThem) {
                Write-Host "   Non-interactive mode: UpdateExistingExclusions is off - left unchanged" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "   Adding them changes only each policy's excluded users and groups." -ForegroundColor Gray
            $answer = Read-Host "   Add the emergency access account and NoMFA Exclusion Group to these policies? (Y/N)"
            $addThem = $answer -like "Y*"
        }

        foreach ($item in $needExclusions) {
            if (!$addThem) {
                $results.ExclusionsMissing += $item.Name
                continue
            }
            $update = Add-StandardExclusionsToExistingPolicy -PolicyId $item.Id -NoMfaGroupId $noMfaGroupId `
                -EmergencyAccessUserIds $emergencyAccessUserIds
            if ($update.Success) {
                Write-Host "   Exclusions added: $($item.Name)" -ForegroundColor Green
                $results.ExclusionsAdded += $item.Name
            }
            else {
                Write-Host "   Could not update $($item.Name): $($update.Error)" -ForegroundColor Red
                $results.ExclusionsMissing += $item.Name
            }
        }
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
    if ($emergencyAccessUpns.Count -gt 0) {
        Write-Host "    - Emergency access account(s) excluded from every new policy: $($emergencyAccessUpns -join ', ')" -ForegroundColor Yellow
    }
    if ($results.Updated.Count -gt 0) {
        Write-Host "    - Updated to the current design, now Report-only: $($results.Updated -join ', ')" -ForegroundColor Yellow
    }
    if ($results.NotUpdated.Count -gt 0) {
        Write-Host "    - NOT in the current design (left unchanged): $($results.NotUpdated -join ', ')" -ForegroundColor Red
        Write-Host "      Do NOT widen its users or save it from the portal until it is updated." -ForegroundColor Red
    }
    if ($results.ExclusionsAdded.Count -gt 0) {
        Write-Host "    - Exclusions added to $($results.ExclusionsAdded.Count) existing polic(y/ies): $($results.ExclusionsAdded -join ', ')" -ForegroundColor Yellow
    }
    if ($results.ExclusionsMissing.Count -gt 0) {
        Write-Host "    - These existing policies still do NOT exclude the emergency access account:" -ForegroundColor Red
        Write-Host "      $($results.ExclusionsMissing -join ', ')" -ForegroundColor Red
        Write-Host "      Do NOT enable or widen them until they do." -ForegroundColor Red
    }
    if ($adminGroupId -and !$adminGroupHasMembers) {
        Write-Host "    - BITS Admin Users is empty: check its members before enabling C003" -ForegroundColor Yellow
    }
    foreach ($warning in $results.Warnings) {
        Write-Host "    - $warning" -ForegroundColor Red
    }
    Write-Host "    - Policies that can block sign-ins are Report-only. Review their results for about a" -ForegroundColor Yellow
    Write-Host "      week before enabling them, one at a time." -ForegroundColor Yellow
    Write-Host ""

    Write-Host "  Next Steps:" -ForegroundColor Yellow
    Write-Host "    1. Test that an emergency access account can sign in" -ForegroundColor Gray
    Write-Host "    2. Review Report-only results: Entra admin center > Conditional Access > Insights and" -ForegroundColor Gray
    Write-Host "       reporting, or the Report-only tab of a sign-in in the sign-in logs" -ForegroundColor Gray
    Write-Host "    3. After about a week, enable the Report-only policies one at a time" -ForegroundColor Gray
    Write-Host "    4. After any portal change, check the policy's excluded users, groups and locations" -ForegroundColor Gray
    Write-Host ""

    # Machine-readable results for CI runners
    if ($ResultPath) {
        @{
            Success = ($results.Failed.Count -eq 0)
            Created = @($results.Created)
            Skipped = @($results.Skipped)
            Failed  = @($results.Failed)
            Warnings = @($results.Warnings)
            ExclusionsAdded = @($results.ExclusionsAdded)
            ExclusionsMissing = @($results.ExclusionsMissing)
            Updated = @($results.Updated)
            Comparison = @($comparison)
            NotUpdated = @($results.NotUpdated)
            EmergencyAccessUserIds = @($emergencyAccessUserIds)
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
