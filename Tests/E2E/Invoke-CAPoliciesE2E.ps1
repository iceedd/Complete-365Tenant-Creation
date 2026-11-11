#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs entra/CA-Policies.ps1 unattended against the
    dedicated M365 test tenant and verifies the Conditional Access policies
    it creates.
.DESCRIPTION
    Connects to Microsoft Graph with certificate-based app-only auth, then:
      1. Creates a disabled, throwaway user to stand in for the tenant's
         emergency access (break-glass) account
      2. Runs entra/Security-Groups.ps1 non-interactively (E2E- prefix) to
         create the prerequisite groups CA-Policies looks up (NoMFA
         Exclusion Group, BITS Admin Users, CA-GEO-International)
      3. Runs entra/CA-Policies.ps1 non-interactively (E2E- prefix,
         PolicyMode ReportOnly) — the real script, same file the menu calls.
         ReportOnly is mandatory here: most of these policies target "All"
         users, and this runs in a shared test tenant, so Enabled would
         actually enforce MFA rules for real traffic. The script auto-creates
         the (prefixed) UK named location, CA-BYOD-Windows and CA-UK-Travel-
         Exclusion groups, so all 12 policies are expected to be CREATED.
         The NoMFA Exclusion Group starts empty, so the script is expected
         to add the configured emergency access account to it.
      4. Verifies all 12 expected policies exist, are report-only (including
         one the config deliberately asks to be Enabled), exclude the E2E
         NoMFA group AND list the emergency access account directly; that
         C007 applies to all users, excludes only the UK named location, the
         international and travel groups and the partner (GDAP) tenant; that
         C003 excludes the admin group and the partner tenant; C008 blocks
         the device code flow; C009 targets Android/iOS with app protection;
         C010/C011 scope to the BYOD Windows group; C012 targets guests
      5. Re-runs the script to prove idempotency
      6. Deletes every E2E- prefixed CA policy, named location, and group,
         and the throwaway user, in a finally block that always runs, so
         cleanup happens even on failure

    Only objects whose displayName starts with the E2E prefix are ever
    deleted or asserted on.
.EXAMPLE
    ./Invoke-CAPoliciesE2E.ps1 -TenantId $env:M365_TENANT_ID -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $TenantId,
    [Parameter(Mandatory)] [string] $AppId,
    [Parameter(Mandatory)] [string] $CertificateThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot        = $PSScriptRoot | Split-Path | Split-Path
$GroupConfigPath = Join-Path $PSScriptRoot 'security-groups.e2e.json'
$CAConfigPath    = Join-Path $PSScriptRoot 'ca-policies.e2e.json'
$GroupResultPath = Join-Path ([IO.Path]::GetTempPath()) "sg-e2e-result-$([guid]::NewGuid().ToString('n')).json"
$CAResultPath    = Join-Path ([IO.Path]::GetTempPath()) "ca-e2e-result-$([guid]::NewGuid().ToString('n')).json"

$caConfig = Get-Content $CAConfigPath -Raw | ConvertFrom-Json
$E2EPrefix = $caConfig.NamePrefix
if (!$E2EPrefix) { throw "E2E config must set a NamePrefix — refusing to run without test isolation" }
if ($caConfig.PolicyMode -ne 'ReportOnly') { throw "E2E config must use PolicyMode ReportOnly — refusing to risk enforcing policies in a shared tenant" }

# The run-time config is the checked-in one plus three values set here:
#  - EmergencyAccessUpns: the throwaway user created below, whose UPN depends
#    on the tenant's default domain and so can't live in a static JSON file
#  - PartnerTenantIds: stated explicitly so the assertions below check what
#    this test passed, not whatever the script's default happens to be
#  - PolicyModes: asks for C001 to be ENABLED. C001 can block sign-ins, so the
#    script must ignore that and create it Report-only — this is the live
#    proof that the Report-only lock holds. C001 is used because, were the
#    lock ever broken, it would only affect users flagged as high risk for
#    the minute or two before cleanup.
$RunConfigPath   = Join-Path ([IO.Path]::GetTempPath()) "ca-e2e-config-$([guid]::NewGuid().ToString('n')).json"
$PartnerTenantId = '23212a04-40b3-4ade-8101-f6804f754ab6'
$EmergencyUserId = $null
$EmergencyUpn    = $null

# All 12 policies CA-Policies.ps1 creates. C007 needs only the UK named
# location, which the script auto-creates. C010/C011 depend on the
# CA-BYOD-Windows group, which the script also auto-creates
# (AutoCreateBYODGroups defaults true). C009 and C012 have no group
# prerequisite at all.
$ExpectedPolicyNames = @(
    'C001 - Block High Risk Users'
    'C002 - MFA Required for All Users'
    'C003 - Block Non Corporate Devices'
    'C004 - Require MFA and Password Change for Medium Risk Users'
    'C005 - Require MFA for Risky Sign-Ins'
    'C006 - Block Legacy Authentication'
    'C007 - Block Sign-In Outside UK'
    'C008 - Block Device Code Flow'
    'C009 - BYOD Android and iOS App Protection'
    'C010 - Windows BYOD (Browser Access)'
    'C011 - Windows BYOD (Block Native Apps)'
    'C012 - Guest Access'
)

$failures = 0

function Write-Result {
    param([bool]$Pass, [string]$Message)
    if ($Pass) { Write-Host "  PASS  $Message" -ForegroundColor Green }
    else       { Write-Host "  FAIL  $Message" -ForegroundColor Red; $script:failures++ }
}

function Get-ServiceProviderExclusionTenants {
    <#
    .SYNOPSIS
        From a raw Graph policy (hashtable), returns the tenant IDs whose
        service provider (GDAP) users the policy excludes — an empty array
        when it has no such exclusion. Bracket/ContainsKey access throughout:
        Graph returns the key with a null value on policies without it, and
        dot access on a missing key throws under Set-StrictMode.
    #>
    param($RawPolicy)

    $users = $RawPolicy['conditions']['users']
    $external = if ($users -and $users.ContainsKey('excludeGuestsOrExternalUsers')) { $users['excludeGuestsOrExternalUsers'] } else { $null }
    if (!$external) { return @() }
    if ([string]$external['guestOrExternalUserTypes'] -notmatch 'serviceProvider') { return @() }
    $tenants = $external['externalTenants']
    if (!$tenants -or !$tenants.ContainsKey('members')) { return @() }
    return @($tenants['members'])
}

# ============================================================================
# Connect
# ============================================================================
Write-Host "`n== Connecting to test tenant (app-only) ==" -ForegroundColor Cyan
Connect-MgGraph -ClientId $AppId -TenantId $TenantId `
    -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
$ctx = Get-MgContext
if ($ctx.AuthType -ne 'AppOnly') { throw "Expected AppOnly auth, got $($ctx.AuthType)" }
Write-Host "  Connected to tenant $($ctx.TenantId)" -ForegroundColor Green

try {
    # ========================================================================
    # Prerequisite: a throwaway emergency access account
    # ========================================================================
    # Disabled, random password, no roles or licences — it only has to exist
    # so the script has an account to add to the NoMFA Exclusion Group and to
    # list directly on every policy. Raw Graph calls: this job doesn't
    # install Microsoft.Graph.Users.
    Write-Host "`n== Creating throwaway emergency access account ==" -ForegroundColor Cyan
    $org = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization?`$select=verifiedDomains" -ErrorAction Stop
    $defaultDomain = (@(@($org['value'])[0]['verifiedDomains']) | Where-Object { $_['isDefault'] } | Select-Object -First 1)['name']
    $EmergencyUpn = "${E2EPrefix}CA-Emergency@$defaultDomain"

    # A leftover from an interrupted run would make the create fail
    try {
        $leftover = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($EmergencyUpn))?`$select=id" -ErrorAction Stop
        Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/users/$($leftover['id'])" -ErrorAction Stop
        Write-Host "  Removed leftover $EmergencyUpn from an earlier run" -ForegroundColor Gray
        Start-Sleep -Seconds 10
    }
    catch { }

    $newUser = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users" -ContentType 'application/json' -Body (@{
            accountEnabled    = $false
            displayName       = "${E2EPrefix}CA-Emergency"
            mailNickname      = "${E2EPrefix}CA-Emergency"
            userPrincipalName = $EmergencyUpn
            passwordProfile   = @{
                forceChangePasswordNextSignIn = $true
                password                      = "E2e!$([guid]::NewGuid().ToString('N'))aA9"
            }
        } | ConvertTo-Json) -ErrorAction Stop
    $EmergencyUserId = $newUser['id']
    Write-Host "  Created $EmergencyUpn (disabled, ID: $EmergencyUserId)" -ForegroundColor Green

    $runConfig = Get-Content $CAConfigPath -Raw | ConvertFrom-Json -AsHashtable
    $runConfig['EmergencyAccessUpns'] = @($EmergencyUpn)
    $runConfig['PartnerTenantIds']    = @($PartnerTenantId)
    $runConfig['PolicyModes']         = @{ C001 = 'Enabled' }
    $runConfig | ConvertTo-Json -Depth 5 | Set-Content -Path $RunConfigPath -Encoding UTF8

    # ========================================================================
    # Prerequisite: create the groups CA-Policies depends on
    # ========================================================================
    Write-Host "`n== Creating prerequisite groups (Security-Groups.ps1) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'entra/Security-Groups.ps1') `
        -NonInteractive -ConfigFile $GroupConfigPath -ResultPath $GroupResultPath

    Write-Host "`n== Waiting 30s for directory replication ==" -ForegroundColor Cyan
    Start-Sleep -Seconds 30

    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running CA-Policies.ps1 (non-interactive, ReportOnly) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'entra/CA-Policies.ps1') `
        -NonInteractive -ConfigFile $RunConfigPath -ResultPath $CAResultPath

    Write-Host "`n== Waiting 30s for directory replication ==" -ForegroundColor Cyan
    Start-Sleep -Seconds 30

    # ========================================================================
    # Assert on the script's own reported results
    # ========================================================================
    Write-Host "`n== Verifying script results ==" -ForegroundColor Cyan
    if (!(Test-Path $CAResultPath)) {
        Write-Result $false "Script produced no results file — it likely aborted early"
    }
    else {
        $result = Get-Content $CAResultPath -Raw | ConvertFrom-Json
        Write-Result ([bool]$result.Success) "Script reported success (created: $(@($result.Created).Count), skipped: $(@($result.Skipped).Count), failed: $(@($result.Failed).Count))"
        foreach ($fail in @($result.Failed)) {
            Write-Host "        failed policy: $($fail.Name) — $($fail.Error)" -ForegroundColor Red
        }
        Write-Result (@($result.Created).Count -eq $ExpectedPolicyNames.Count) "Script created all $($ExpectedPolicyNames.Count) policies"
        Write-Result (@($result.EmergencyAccessUserIds) -contains $EmergencyUserId) "Script reported the emergency access account it excluded"
    }

    # ========================================================================
    # Independently verify tenant state via Graph
    # ========================================================================
    Write-Host "`n== Verifying created policies in tenant ==" -ForegroundColor Cyan
    $noMfaGroup = Get-MgGroup -Filter "displayName eq '${E2EPrefix}NoMFA Exclusion Group'" -ErrorAction SilentlyContinue
    foreach ($name in $ExpectedPolicyNames) {
        $fullName = "$E2EPrefix$name"
        $policy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$fullName'" -ErrorAction SilentlyContinue

        if (!$policy) {
            Write-Result $false "$fullName exists"
            continue
        }
        Write-Result $true "$fullName exists"
        Write-Result ($policy.State -eq 'enabledForReportingButNotEnforced') "$fullName is report-only (not enforcing)"
        Write-Result ($noMfaGroup -and (@($policy.Conditions.Users.ExcludeGroups) -contains $noMfaGroup.Id)) "$fullName excludes the E2E NoMFA group"
        Write-Result (@($policy.Conditions.Users.ExcludeUsers) -contains $EmergencyUserId) "$fullName lists the emergency access account directly"
    }

    # The NoMFA Exclusion Group started empty: the script must have added the
    # configured emergency access account to it
    if ($noMfaGroup) {
        $noMfaMembers = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$($noMfaGroup.Id)/members?`$select=id" -ErrorAction Stop
        Write-Result (@(@($noMfaMembers['value']) | ForEach-Object { $_['id'] }) -contains $EmergencyUserId) "Emergency access account was added to the E2E NoMFA group"
    }

    # The UK named location must have been auto-created (prefix-aware), and
    # C007 must actually reference the geo groups and that location
    Write-Host "`n== Verifying auto-created named location and C007/C008 wiring ==" -ForegroundColor Cyan
    $locations = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" -ErrorAction Stop
    $ukLocation = @($locations.value) | Where-Object { $_.displayName -eq "${E2EPrefix}UK" } | Select-Object -First 1
    Write-Result ([bool]$ukLocation) "${E2EPrefix}UK named location was auto-created"
    if ($ukLocation) {
        Write-Result (@($ukLocation.countriesAndRegions) -contains 'GB') "${E2EPrefix}UK named location covers GB"
    }

    $geoIntlGroup = Get-MgGroup -Filter "displayName eq '${E2EPrefix}CA-GEO-International'" -ErrorAction SilentlyContinue
    $travelGroup = Get-MgGroup -Filter "displayName eq '${E2EPrefix}CA-UK-Travel-Exclusion'" -ErrorAction SilentlyContinue
    $c007 = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '${E2EPrefix}C007 - Block Sign-In Outside UK'" -ErrorAction SilentlyContinue
    if ($c007 -and $ukLocation) {
        # All users (guests included) — not a hand-maintained group
        Write-Result (@($c007.Conditions.Users.IncludeUsers) -contains 'All') "C007 applies to all users"
        Write-Result (@($c007.Conditions.Users.IncludeGroups | Where-Object { $_ }).Count -eq 0) "C007 is not scoped to a group"
        # The UK location must be the ONLY excluded location: the portal can't
        # display a named location alongside "AllTrusted", and a portal save
        # then silently drops the UK exclusion (which blocked every UK sign-in).
        Write-Result ((@($c007.Conditions.Locations.ExcludeLocations) -join ',') -eq $ukLocation.id) "C007 excludes the ${E2EPrefix}UK named location, and only that"

        $c007Raw = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($c007.Id)" -ErrorAction Stop
        Write-Result (@(Get-ServiceProviderExclusionTenants -RawPolicy $c007Raw) -contains $PartnerTenantId) "C007 excludes service provider (GDAP) users from the partner tenant"
    }
    Write-Result ([bool]$geoIntlGroup) "${E2EPrefix}CA-GEO-International group exists (created by Security-Groups.ps1)"
    if ($c007 -and $geoIntlGroup) {
        Write-Result (@($c007.Conditions.Users.ExcludeGroups) -contains $geoIntlGroup.Id) "C007 excludes the E2E CA-GEO-International group"
    }
    Write-Result ([bool]$travelGroup) "${E2EPrefix}CA-UK-Travel-Exclusion group was auto-created"
    if ($c007 -and $travelGroup) {
        Write-Result (@($c007.Conditions.Users.ExcludeGroups) -contains $travelGroup.Id) "C007 excludes the E2E UK travel exclusion group"
    }

    # C003: admin accounts and partner (GDAP) sign-ins can never hold a
    # compliant device in this tenant, so both are excluded
    $adminGroup = Get-MgGroup -Filter "displayName eq '${E2EPrefix}BITS Admin Users'" -ErrorAction SilentlyContinue
    $c003 = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '${E2EPrefix}C003 - Block Non Corporate Devices'" -ErrorAction SilentlyContinue
    Write-Result ([bool]$adminGroup) "${E2EPrefix}BITS Admin Users group exists (created by Security-Groups.ps1)"
    if ($c003 -and $adminGroup) {
        Write-Result (@($c003.Conditions.Users.ExcludeGroups) -contains $adminGroup.Id) "C003 excludes the E2E BITS Admin Users group"
    }
    if ($c003) {
        $c003Raw = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($c003.Id)" -ErrorAction Stop
        Write-Result (@(Get-ServiceProviderExclusionTenants -RawPolicy $c003Raw) -contains $PartnerTenantId) "C003 excludes service provider (GDAP) users from the partner tenant"
    }

    # C008's authenticationFlows condition isn't surfaced by every SDK model
    # version — assert via a raw Graph read instead
    $c008 = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '${E2EPrefix}C008 - Block Device Code Flow'" -ErrorAction SilentlyContinue
    if ($c008) {
        $c008Raw = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($c008.Id)" -ErrorAction Stop
        Write-Result ($c008Raw.conditions.authenticationFlows.transferMethods -match 'deviceCodeFlow') `
            "C008 blocks the device code flow authentication transfer method"
    }

    # C009: BYOD Android/iOS — MFA + require app protection policy
    $c009 = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '${E2EPrefix}C009 - BYOD Android and iOS App Protection'" -ErrorAction SilentlyContinue
    if ($c009) {
        Write-Result (@($c009.Conditions.Platforms.IncludePlatforms) -contains 'android' -and @($c009.Conditions.Platforms.IncludePlatforms) -contains 'iOS') `
            "C009 targets android and iOS platforms"
        Write-Result (@($c009.GrantControls.BuiltInControls) -contains 'compliantApplication') "C009 requires an app protection policy"
    }

    # C010/C011: Windows BYOD pair — scoped to the auto-created BYOD group
    $byodGroup = Get-MgGroup -Filter "displayName eq '${E2EPrefix}CA-BYOD-Windows'" -ErrorAction SilentlyContinue
    Write-Result ([bool]$byodGroup) "${E2EPrefix}CA-BYOD-Windows group was auto-created"
    $c010 = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '${E2EPrefix}C010 - Windows BYOD (Browser Access)'" -ErrorAction SilentlyContinue
    if ($c010 -and $byodGroup) {
        Write-Result (@($c010.Conditions.Users.IncludeGroups) -contains $byodGroup.Id) "C010 targets the E2E CA-BYOD-Windows group"
        Write-Result (@($c010.Conditions.ClientAppTypes) -contains 'browser') "C010 is browser-only"
    }
    $c011 = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '${E2EPrefix}C011 - Windows BYOD (Block Native Apps)'" -ErrorAction SilentlyContinue
    if ($c011 -and $byodGroup) {
        Write-Result (@($c011.Conditions.Users.IncludeGroups) -contains $byodGroup.Id) "C011 targets the E2E CA-BYOD-Windows group"
        Write-Result (@($c011.GrantControls.BuiltInControls) -contains 'block') "C011 blocks native/desktop client apps"
    }

    # C012: Guest Access — MFA + daily sign-in frequency for guests, excluding
    # mobile/mac/linux platforms
    $c012 = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '${E2EPrefix}C012 - Guest Access'" -ErrorAction SilentlyContinue
    if ($c012) {
        Write-Result ($null -ne $c012.Conditions.Users.IncludeGuestsOrExternalUsers) "C012 targets guests/external users"
        Write-Result (@($c012.Conditions.Platforms.ExcludePlatforms) -contains 'android') "C012 excludes mobile/mac/linux platforms"
    }

    # ========================================================================
    # Idempotency: a second run must skip everything and create nothing
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run skips all) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'entra/CA-Policies.ps1') `
        -NonInteractive -ConfigFile $RunConfigPath -ResultPath $CAResultPath

    $second = Get-Content $CAResultPath -Raw | ConvertFrom-Json
    Write-Result ([bool]$second.Success -and @($second.Created).Count -eq 0 -and @($second.Skipped).Count -eq $ExpectedPolicyNames.Count) `
        "Second run created nothing and skipped all $($ExpectedPolicyNames.Count) policies"
}
finally {
    # ========================================================================
    # Cleanup — always runs; deletes ONLY prefix-matched objects
    # ========================================================================
    Write-Host "`n== Cleaning up E2E policies ==" -ForegroundColor Cyan
    try {
        $e2ePolicies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop | Where-Object { $_.DisplayName -like "$E2EPrefix*" })
        foreach ($policy in $e2ePolicies) {
            try {
                Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id -ErrorAction Stop
                Write-Host "  Deleted policy $($policy.DisplayName)" -ForegroundColor Gray
            }
            catch {
                Write-Host "  WARNING: could not delete policy $($policy.DisplayName): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        Write-Host "  Removed $($e2ePolicies.Count) polic(y/ies)" -ForegroundColor Green
    }
    catch {
        Write-Host "  WARNING: policy cleanup query failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Manually delete CA policies prefixed '$E2EPrefix' in the test tenant" -ForegroundColor Yellow
    }

    # Named locations must be deleted AFTER the policies that reference them
    Write-Host "`n== Cleaning up E2E named locations ==" -ForegroundColor Cyan
    try {
        $locations = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" -ErrorAction Stop
        foreach ($loc in @($locations.value | Where-Object { $_.displayName -like "$E2EPrefix*" })) {
            # A location still referenced by a policy can't be deleted, and the
            # policy deletions above take a moment to register — retry briefly
            $deleted = $false
            $lastError = $null
            for ($attempt = 1; $attempt -le 4 -and !$deleted; $attempt++) {
                try {
                    Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations/$($loc.id)" -ErrorAction Stop
                    $deleted = $true
                }
                catch {
                    $lastError = $_.Exception.Message
                    if ($attempt -lt 4) { Start-Sleep -Seconds 10 }
                }
            }
            if ($deleted) {
                Write-Host "  Deleted named location $($loc.displayName)" -ForegroundColor Gray
            }
            else {
                Write-Host "  WARNING: could not delete named location $($loc.displayName): $lastError" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Host "  WARNING: named location cleanup query failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Write-Host "`n== Cleaning up E2E groups ==" -ForegroundColor Cyan
    try {
        $e2eGroups = @(Get-MgGroup -Filter "startsWith(displayName, '$E2EPrefix')" -All -ErrorAction Stop)
        foreach ($group in $e2eGroups) {
            try {
                Remove-MgGroup -GroupId $group.Id -Confirm:$false -ErrorAction Stop
                Write-Host "  Deleted group $($group.DisplayName)" -ForegroundColor Gray
            }
            catch {
                Write-Host "  WARNING: could not delete group $($group.DisplayName): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        Write-Host "  Removed $($e2eGroups.Count) group(s)" -ForegroundColor Green
    }
    catch {
        Write-Host "  WARNING: group cleanup query failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Manually delete groups prefixed '$E2EPrefix' in the test tenant" -ForegroundColor Yellow
    }

    Write-Host "`n== Cleaning up throwaway emergency access account ==" -ForegroundColor Cyan
    if ($EmergencyUpn) {
        try {
            # Looked up by UPN rather than trusting $EmergencyUserId, so a run
            # that failed between creating the user and recording its ID still
            # cleans up
            $toDelete = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($EmergencyUpn))?`$select=id" -ErrorAction Stop
            Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/users/$($toDelete['id'])" -ErrorAction Stop
            Write-Host "  Deleted user $EmergencyUpn" -ForegroundColor Gray
        }
        catch {
            Write-Host "  WARNING: could not delete user ${EmergencyUpn}: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "  Manually delete it in the test tenant if it exists" -ForegroundColor Yellow
        }
    }

    Remove-Item $GroupResultPath, $CAResultPath, $RunConfigPath -ErrorAction SilentlyContinue
    $null = Disconnect-MgGraph -ErrorAction SilentlyContinue
}

# ============================================================================
# Summary
# ============================================================================
Write-Host ""
Write-Host ("=" * 60)
Write-Host "E2E test summary: $failures failure(s)"
Write-Host ("=" * 60)

if ($failures -gt 0) { exit 1 }
exit 0
