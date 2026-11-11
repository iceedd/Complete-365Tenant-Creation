#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.6.0' }

<#
.SYNOPSIS
    Unit tests for the policy-building and lockout-safeguard logic in
    entra/CA-Policies.ps1
.DESCRIPTION
    No tenant and no Microsoft Graph connection is needed: the Graph cmdlets
    the script calls are replaced with stubs and mocked.

    These tests pin the behaviour that stops one portal edit from locking a
    whole tenant out:
      - C007 excludes the UK named location ONLY (never together with
        "AllTrusted", which the portal hides and then drops on save)
      - C007 applies to all users and takes people out by exception
      - every policy excludes the NoMFA group AND lists the emergency access
        accounts directly
      - policies that can block a sign-in are always Report-only, whatever
        the config asks for
      - an empty NoMFA Exclusion Group gets an emergency access account
        added to it rather than being silently accepted

    CA-Policies.ps1 runs its main routine when dot-sourced, so the functions
    under test are lifted out of it by name via the PowerShell parser.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Variables set in Pester BeforeAll/BeforeEach blocks are read in the It blocks')]
param()

BeforeAll {
    $caScriptPath = (Resolve-Path (Join-Path $PSScriptRoot '../../entra/CA-Policies.ps1')).Path

    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($caScriptPath, [ref]$null, [ref]$parseErrors)
    if ($parseErrors) { throw "CA-Policies.ps1 has parse errors: $($parseErrors[0].Message)" }

    $functionNames = @(
        'New-ServiceProviderExclusion'
        'Get-PolicyDefinitions'
        'Get-PolicyCode'
        'Test-PolicyCanBlockSignIn'
        'Set-PolicyStates'
        'Add-StandardExclusions'
        'Test-LocationExclusionHiddenByPortal'
        'Get-MissingStandardExclusions'
        'Add-StandardExclusionsToExistingPolicy'
        'Test-ExistingC007NeedsUpdate'
        'Update-ExistingC007'
        'New-ConditionalAccessPolicy'
        'Get-PartnerTenantIds'
        'Get-GroupUserMembers'
        'Find-UserByUpn'
        'Resolve-EmergencyAccessAccounts'
    )
    $definitions = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $functionNames
            }, $true))
    $missing = @($functionNames | Where-Object { $_ -notin $definitions.Name })
    if ($missing) { throw "CA-Policies.ps1 no longer defines: $($missing -join ', ')" }
    foreach ($definition in $definitions) { . ([scriptblock]::Create($definition.Extent.Text)) }

    # The script-level table of names earlier versions gave a policy
    $legacyAssignment = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -eq '$script:LegacyPolicyNames'
        }, $true)
    if (!$legacyAssignment) { throw 'CA-Policies.ps1 no longer defines $script:LegacyPolicyNames' }
    $legacyPolicyNames = & ([scriptblock]::Create($legacyAssignment.Right.Extent.Text))

    # Stand-ins for the Graph cmdlets, so they can be mocked on a machine
    # (or CI runner) that doesn't have the Microsoft.Graph modules installed
    function Invoke-MgGraphRequest { [CmdletBinding()] param($Method, $Uri, $Body, $ContentType) }
    function Get-MgIdentityConditionalAccessPolicy { [CmdletBinding()] param($Filter) }
    function New-MgIdentityConditionalAccessPolicy { [CmdletBinding()] param($BodyParameter) }

    # The functions under test read their settings from script-scope
    # variables. Setting them through a function defined alongside them
    # guarantees both sides resolve the same scope.
    function Set-TestState {
        param(
            [hashtable]$Overrides = @{},
            [bool]$NonInteractive = $true
        )
        $config = @{
            NamePrefix          = ''
            GroupNamePrefix     = ''
            PolicyMode          = 'ReportOnly'
            PolicyModes         = @{}
            PartnerTenantIds    = @('23212a04-40b3-4ade-8101-f6804f754ab6')
            EmergencyAccessUpns = @()
        }
        foreach ($key in $Overrides.Keys) { $config[$key] = $Overrides[$key] }
        $script:RunConfig = $config
        $script:NonInteractive = $NonInteractive
        $script:LegacyPolicyNames = $legacyPolicyNames
    }

    function Get-TestPolicies {
        # Every optional input supplied, so all 12 policies are produced
        @(Get-PolicyDefinitions -NoMfaGroupId 'nomfa-id' -GeoIntlGroupId 'intl-id' -UkLocationId 'uk-id' `
                -ByodWindowsGroupId 'byod-id' -UkTravelExclusionGroupId 'travel-id' -AdminGroupId 'admins-id' `
                -PartnerTenantIds @('23212a04-40b3-4ade-8101-f6804f754ab6'))
    }

    $partnerTenantId = '23212a04-40b3-4ade-8101-f6804f754ab6'

    Set-TestState
}

# ============================================================================
# Get-PolicyDefinitions
# ============================================================================
Describe 'Get-PolicyDefinitions' {

    BeforeEach { Set-TestState }

    It 'returns all 12 policies in code order' {
        $codes = Get-TestPolicies | ForEach-Object { Get-PolicyCode -DisplayName $_.displayName }
        ($codes -join ',') | Should -Be 'C001,C002,C003,C004,C005,C006,C007,C008,C009,C010,C011,C012'
    }

    It 'prepends the configured NamePrefix to every policy' {
        Set-TestState -Overrides @{ NamePrefix = 'E2E-' }
        $names = Get-TestPolicies | ForEach-Object { $_.displayName }
        @($names | Where-Object { $_ -notlike 'E2E-C0*' }) | Should -BeNullOrEmpty
    }

    Context 'C007 - Block Sign-In Outside UK' {
        BeforeEach {
            $c007 = Get-TestPolicies | Where-Object { $_.displayName -like 'C007*' }
        }

        It 'no longer carries the "(UK Users)" suffix' {
            $c007.displayName | Should -Be 'C007 - Block Sign-In Outside UK'
        }

        It 'applies to all users and is not scoped to a group' {
            (@($c007.conditions.users.includeUsers) -join ',') | Should -Be 'All'
            $c007.conditions.users.ContainsKey('includeGroups') | Should -BeFalse
        }

        It 'excludes the UK named location and nothing else' {
            (@($c007.conditions.locations.excludeLocations) -join ',') | Should -Be 'uk-id'
        }

        It 'never excludes AllTrusted (the portal hides the UK next to it and drops it on save)' {
            @($c007.conditions.locations.excludeLocations) | Should -Not -Contain 'AllTrusted'
        }

        It 'blocks from every other location' {
            (@($c007.conditions.locations.includeLocations) -join ',') | Should -Be 'All'
            (@($c007.grantControls.builtInControls) -join ',') | Should -Be 'block'
        }

        It 'excludes the NoMFA, international and travel groups' {
            (@($c007.conditions.users.excludeGroups) -join ',') | Should -Be 'nomfa-id,intl-id,travel-id'
        }

        It 'excludes service provider (GDAP) users from the partner tenant only' {
            $external = $c007.conditions.users.excludeGuestsOrExternalUsers
            $external.guestOrExternalUserTypes | Should -Be 'serviceProvider'
            $external.externalTenants.membershipKind | Should -Be 'enumerated'
            (@($external.externalTenants.members) -join ',') | Should -Be $partnerTenantId
        }

        It 'is still created without the optional groups or a partner tenant' {
            $minimal = @(Get-PolicyDefinitions -NoMfaGroupId 'nomfa-id' -UkLocationId 'uk-id') |
                Where-Object { $_.displayName -like 'C007*' }
            (@($minimal.conditions.users.excludeGroups) -join ',') | Should -Be 'nomfa-id'
            $minimal.conditions.users.ContainsKey('excludeGuestsOrExternalUsers') | Should -BeFalse
        }

        It 'is left out when there is no UK named location to exclude' {
            $withoutLocation = @(Get-PolicyDefinitions -NoMfaGroupId 'nomfa-id')
            @($withoutLocation | Where-Object { $_.displayName -like 'C007*' }) | Should -BeNullOrEmpty
        }
    }

    Context 'C003 - Block Non Corporate Devices' {
        BeforeEach {
            $c003 = Get-TestPolicies | Where-Object { $_.displayName -like 'C003*' }
        }

        It 'excludes the NoMFA group and the admin group' {
            (@($c003.conditions.users.excludeGroups) -join ',') | Should -Be 'nomfa-id,admins-id'
        }

        It 'excludes service provider (GDAP) users from the partner tenant' {
            $external = $c003.conditions.users.excludeGuestsOrExternalUsers
            $external.guestOrExternalUserTypes | Should -Be 'serviceProvider'
            (@($external.externalTenants.members) -join ',') | Should -Be $partnerTenantId
        }

        It 'does not share its partner exclusion object with C007' {
            $policies = Get-TestPolicies
            $a = ($policies | Where-Object { $_.displayName -like 'C003*' }).conditions.users.excludeGuestsOrExternalUsers
            $b = ($policies | Where-Object { $_.displayName -like 'C007*' }).conditions.users.excludeGuestsOrExternalUsers
            [object]::ReferenceEquals($a, $b) | Should -BeFalse
        }

        It 'excludes only the NoMFA group when there is no admin group or partner tenant' {
            $minimal = @(Get-PolicyDefinitions -NoMfaGroupId 'nomfa-id') | Where-Object { $_.displayName -like 'C003*' }
            (@($minimal.conditions.users.excludeGroups) -join ',') | Should -Be 'nomfa-id'
            $minimal.conditions.users.ContainsKey('excludeGuestsOrExternalUsers') | Should -BeFalse
        }
    }
}

# ============================================================================
# Report-only lock
# ============================================================================
Describe 'Test-PolicyCanBlockSignIn' {

    BeforeEach { Set-TestState }

    It '<Code> can block a sign-in: <Expected>' -ForEach @(
        @{ Code = 'C001'; Expected = $true }
        @{ Code = 'C002'; Expected = $false }
        @{ Code = 'C003'; Expected = $true }
        @{ Code = 'C004'; Expected = $false }
        @{ Code = 'C005'; Expected = $false }
        @{ Code = 'C006'; Expected = $true }
        @{ Code = 'C007'; Expected = $true }
        @{ Code = 'C008'; Expected = $true }
        @{ Code = 'C009'; Expected = $true }
        @{ Code = 'C010'; Expected = $false }
        @{ Code = 'C011'; Expected = $true }
        @{ Code = 'C012'; Expected = $false }
    ) {
        $policy = Get-TestPolicies | Where-Object { $_.displayName -like "$Code*" }
        Test-PolicyCanBlockSignIn -Policy $policy | Should -Be $Expected
    }
}

Describe 'Set-PolicyStates' {

    BeforeEach { Set-TestState }

    It 'keeps every policy that can block a sign-in Report-only when the config asks for Enabled everywhere' {
        Set-TestState -Overrides @{ PolicyMode = 'Enabled' }
        $policies = Get-TestPolicies
        Set-PolicyStates -Policies $policies 6>$null

        $reportOnly = $policies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' } |
            ForEach-Object { Get-PolicyCode -DisplayName $_.displayName }
        $enabled = $policies | Where-Object { $_.state -eq 'enabled' } |
            ForEach-Object { Get-PolicyCode -DisplayName $_.displayName }

        ($reportOnly -join ',') | Should -Be 'C001,C003,C006,C007,C008,C009,C011'
        ($enabled -join ',') | Should -Be 'C002,C004,C005,C010,C012'
    }

    It 'ignores a per-policy "Enabled" for a policy that can block a sign-in' {
        Set-TestState -Overrides @{ PolicyModes = @{ C007 = 'Enabled'; C002 = 'Enabled' } }
        $policies = Get-TestPolicies
        Set-PolicyStates -Policies $policies 6>$null

        ($policies | Where-Object { $_.displayName -like 'C007*' }).state | Should -Be 'enabledForReportingButNotEnforced'
        ($policies | Where-Object { $_.displayName -like 'C002*' }).state | Should -Be 'enabled'
    }

    It 'leaves everything Report-only by default' {
        $policies = Get-TestPolicies
        Set-PolicyStates -Policies $policies 6>$null
        @($policies | Where-Object { $_.state -ne 'enabledForReportingButNotEnforced' }) | Should -BeNullOrEmpty
    }
}

# ============================================================================
# Exclusions every policy carries
# ============================================================================
Describe 'Add-StandardExclusions' {

    BeforeEach { Set-TestState }

    It 'adds the NoMFA group and the emergency access account to all 12 policies' {
        $policies = Get-TestPolicies
        foreach ($policy in $policies) {
            $null = Add-StandardExclusions -PolicyConfig $policy -NoMfaGroupId 'nomfa-id' -EmergencyAccessUserIds @('bg02-id')
        }
        @($policies | Where-Object { @($_.conditions.users.excludeGroups) -notcontains 'nomfa-id' }) | Should -BeNullOrEmpty
        @($policies | Where-Object { @($_.conditions.users.excludeUsers) -notcontains 'bg02-id' }) | Should -BeNullOrEmpty
    }

    It 'keeps a policy''s own exclusions and does not duplicate on a second pass' {
        $c007 = Get-TestPolicies | Where-Object { $_.displayName -like 'C007*' }
        $null = Add-StandardExclusions -PolicyConfig $c007 -NoMfaGroupId 'nomfa-id' -EmergencyAccessUserIds @('bg02-id')
        $null = Add-StandardExclusions -PolicyConfig $c007 -NoMfaGroupId 'nomfa-id' -EmergencyAccessUserIds @('bg02-id')

        (@($c007.conditions.users.excludeGroups) -join ',') | Should -Be 'nomfa-id,intl-id,travel-id'
        (@($c007.conditions.users.excludeUsers) -join ',') | Should -Be 'bg02-id'
    }

    It 'adds no excludeUsers key when there is no emergency access account' {
        $policy = @{ conditions = @{ users = @{ includeUsers = @('All') } } }
        $null = Add-StandardExclusions -PolicyConfig $policy -NoMfaGroupId 'nomfa-id' -EmergencyAccessUserIds @()

        $policy.conditions.users.ContainsKey('excludeUsers') | Should -BeFalse
        (@($policy.conditions.users.excludeGroups) -join ',') | Should -Be 'nomfa-id'
    }
}

Describe 'Test-LocationExclusionHiddenByPortal' {

    It 'flags a named location excluded together with AllTrusted' {
        Test-LocationExclusionHiddenByPortal -ExcludeLocations @('uk-id', 'AllTrusted') | Should -BeTrue
    }

    It 'does not flag <Name>' -ForEach @(
        @{ Name = 'a named location on its own'; Locations = @('uk-id') }
        @{ Name = 'AllTrusted on its own'; Locations = @('AllTrusted') }
        @{ Name = 'no excluded locations'; Locations = @() }
    ) {
        Test-LocationExclusionHiddenByPortal -ExcludeLocations $Locations | Should -BeFalse
    }
}

Describe 'Get-PartnerTenantIds' {

    BeforeEach { Set-TestState }

    It 'returns valid tenant IDs once, in lower case' {
        Set-TestState -Overrides @{ PartnerTenantIds = @($partnerTenantId, $partnerTenantId.ToUpper(), 'not-a-tenant-id', '') }
        (@(Get-PartnerTenantIds 6>$null) -join ',') | Should -Be $partnerTenantId
    }

    It 'drops the tenant being configured from its own partner list' {
        @(Get-PartnerTenantIds -CurrentTenantId $partnerTenantId 6>$null) | Should -BeNullOrEmpty
    }

    It 'returns nothing when the list is empty' {
        Set-TestState -Overrides @{ PartnerTenantIds = @() }
        @(Get-PartnerTenantIds 6>$null) | Should -BeNullOrEmpty
    }
}

# ============================================================================
# Emergency access accounts
# ============================================================================
Describe 'Resolve-EmergencyAccessAccounts' {

    BeforeEach { Set-TestState }

    Context 'the NoMFA Exclusion Group is empty' {
        BeforeEach {
            Mock Invoke-MgGraphRequest { @{ value = @() } } -ParameterFilter { $Method -eq 'GET' -and $Uri -like '*/groups/*/members*' }
            Mock Invoke-MgGraphRequest { @{ id = 'bg02-id'; userPrincipalName = 'bg02@contoso.test'; displayName = 'BG02' } } `
                -ParameterFilter { $Method -eq 'GET' -and $Uri -like '*/users/*' }
            Mock Invoke-MgGraphRequest { } -ParameterFilter { $Method -eq 'POST' }
        }

        It 'adds the configured emergency access account to the group and returns it' {
            Set-TestState -Overrides @{ EmergencyAccessUpns = @('bg02@contoso.test') }
            $result = Resolve-EmergencyAccessAccounts -NoMfaGroupId 'nomfa-id' 6>$null

            (@($result.UserIds) -join ',') | Should -Be 'bg02-id'
            (@($result.Upns) -join ',') | Should -Be 'bg02@contoso.test'
            Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter {
                $Method -eq 'POST' -and $Uri -like '*/groups/nomfa-id/members/*' -and $Body -like '*bg02-id*'
            }
        }

        It 'returns nothing, without throwing, when no account is configured' {
            $result = Resolve-EmergencyAccessAccounts -NoMfaGroupId 'nomfa-id' 6>$null

            @($result.UserIds) | Should -BeNullOrEmpty
            Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly -ParameterFilter { $Method -eq 'POST' }
        }
    }

    Context 'the NoMFA Exclusion Group already has members' {
        BeforeEach {
            Mock Invoke-MgGraphRequest {
                @{ value = @(
                        @{ '@odata.type' = '#microsoft.graph.user'; id = 'existing-id'; userPrincipalName = 'existing@contoso.test'; displayName = 'Existing' }
                        @{ '@odata.type' = '#microsoft.graph.device'; id = 'device-id' }
                    )
                }
            } -ParameterFilter { $Method -eq 'GET' -and $Uri -like '*/groups/*/members*' }
            Mock Invoke-MgGraphRequest { } -ParameterFilter { $Method -eq 'POST' }
        }

        It 'uses the user members, ignores other member types, and adds nobody' {
            Set-TestState -Overrides @{ EmergencyAccessUpns = @('bg02@contoso.test') }
            $result = Resolve-EmergencyAccessAccounts -NoMfaGroupId 'nomfa-id' 6>$null

            (@($result.UserIds) -join ',') | Should -Be 'existing-id'
            Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly -ParameterFilter { $Method -eq 'POST' }
        }
    }
}

# ============================================================================
# New-ConditionalAccessPolicy
# ============================================================================
Describe 'New-ConditionalAccessPolicy' {

    BeforeEach {
        Set-TestState
        $c007 = Get-TestPolicies | Where-Object { $_.displayName -like 'C007*' }
    }

    It 'creates the policy with the NoMFA group and the emergency access account excluded' {
        Mock Get-MgIdentityConditionalAccessPolicy { }
        Mock New-MgIdentityConditionalAccessPolicy { [pscustomobject]@{ Id = 'new-id' } }

        $result = New-ConditionalAccessPolicy -PolicyConfig $c007 -NoMfaGroupId 'nomfa-id' -EmergencyAccessUserIds @('bg02-id') 6>$null

        $result.Success | Should -BeTrue
        $result.Skipped | Should -BeFalse
        Should -Invoke New-MgIdentityConditionalAccessPolicy -Times 1 -Exactly -ParameterFilter {
            (@($BodyParameter.conditions.users.excludeUsers) -contains 'bg02-id') -and
            (@($BodyParameter.conditions.users.excludeGroups) -contains 'nomfa-id') -and
            ((@($BodyParameter.conditions.locations.excludeLocations) -join ',') -eq 'uk-id')
        }
    }

    It 'skips, rather than duplicates, a C007 that exists under its previous name' {
        Mock Get-MgIdentityConditionalAccessPolicy { } -ParameterFilter { $Filter -notlike '*(UK Users)*' }
        Mock Get-MgIdentityConditionalAccessPolicy {
            [pscustomobject]@{
                Id          = 'old-id'
                DisplayName = 'C007 - Block Sign-In Outside UK (UK Users)'
                Conditions  = [pscustomobject]@{ Locations = [pscustomobject]@{ ExcludeLocations = @('uk-id') } }
            }
        } -ParameterFilter { $Filter -like '*(UK Users)*' }
        Mock New-MgIdentityConditionalAccessPolicy { }

        $result = New-ConditionalAccessPolicy -PolicyConfig $c007 -NoMfaGroupId 'nomfa-id' -EmergencyAccessUserIds @('bg02-id') 6>$null

        $result.Skipped | Should -BeTrue
        $result.Warning | Should -BeNullOrEmpty
        Should -Invoke New-MgIdentityConditionalAccessPolicy -Times 0 -Exactly
    }

    It 'warns when an existing C007 excludes the UK together with AllTrusted' {
        Mock Get-MgIdentityConditionalAccessPolicy { } -ParameterFilter { $Filter -notlike '*(UK Users)*' }
        Mock Get-MgIdentityConditionalAccessPolicy {
            [pscustomobject]@{
                Id          = 'old-id'
                DisplayName = 'C007 - Block Sign-In Outside UK (UK Users)'
                Conditions  = [pscustomobject]@{ Locations = [pscustomobject]@{ ExcludeLocations = @('uk-id', 'AllTrusted') } }
            }
        } -ParameterFilter { $Filter -like '*(UK Users)*' }
        Mock New-MgIdentityConditionalAccessPolicy { }

        $result = New-ConditionalAccessPolicy -PolicyConfig $c007 -NoMfaGroupId 'nomfa-id' -EmergencyAccessUserIds @('bg02-id') 6>$null

        $result.Skipped | Should -BeTrue
        $result.Warning | Should -Match 'All trusted'
        Should -Invoke New-MgIdentityConditionalAccessPolicy -Times 0 -Exactly
    }

    It 'skips a policy that already exists under its current name without touching it' {
        Mock Get-MgIdentityConditionalAccessPolicy {
            [pscustomobject]@{
                Id          = 'current-id'
                DisplayName = 'C007 - Block Sign-In Outside UK'
                Conditions  = [pscustomobject]@{ Locations = [pscustomobject]@{ ExcludeLocations = @('uk-id') } }
            }
        }
        Mock New-MgIdentityConditionalAccessPolicy { }

        $result = New-ConditionalAccessPolicy -PolicyConfig $c007 -NoMfaGroupId 'nomfa-id' -EmergencyAccessUserIds @('bg02-id') 6>$null

        $result.Skipped | Should -BeTrue
        Should -Invoke New-MgIdentityConditionalAccessPolicy -Times 0 -Exactly
    }
}

# ============================================================================
# Existing policies: finding and adding the standard exclusions
# ============================================================================
Describe 'Get-MissingStandardExclusions' {

    It 'reports nothing missing when the group and the account are both excluded' {
        $policy = [pscustomobject]@{
            Conditions = [pscustomobject]@{
                Users = [pscustomobject]@{ ExcludeGroups = @('other-id', 'nomfa-id'); ExcludeUsers = @('bg02-id') }
            }
        }
        $missing = Get-MissingStandardExclusions -ExistingPolicy $policy -NoMfaGroupId 'nomfa-id' -EmergencyAccessUserIds @('bg02-id')

        $missing.Any | Should -BeFalse
    }

    It 'reports the account missing when only the group is excluded' {
        $policy = [pscustomobject]@{
            Conditions = [pscustomobject]@{
                Users = [pscustomobject]@{ ExcludeGroups = @('nomfa-id'); ExcludeUsers = @() }
            }
        }
        $missing = Get-MissingStandardExclusions -ExistingPolicy $policy -NoMfaGroupId 'nomfa-id' -EmergencyAccessUserIds @('bg02-id')

        $missing.Any | Should -BeTrue
        $missing.GroupMissing | Should -BeFalse
        ($missing.UserIds -join ',') | Should -Be 'bg02-id'
    }

    It 'reports both missing, without throwing, on a policy with no users block' {
        $policy = [pscustomobject]@{ Conditions = [pscustomobject]@{ Locations = $null } }
        $missing = Get-MissingStandardExclusions -ExistingPolicy $policy -NoMfaGroupId 'nomfa-id' -EmergencyAccessUserIds @('bg02-id')

        $missing.Any | Should -BeTrue
        $missing.GroupMissing | Should -BeTrue
    }
}

Describe 'Add-StandardExclusionsToExistingPolicy' {

    It 'adds the two exclusions, keeps the rest of the users block, and sends nothing else' {
        Mock Invoke-MgGraphRequest {
            @{
                state      = 'enabled'
                conditions = @{
                    users     = @{ includeUsers = @('All'); excludeGroups = @('intl-id'); excludeUsers = @() }
                    locations = @{ excludeLocations = @('uk-id') }
                }
            }
        } -ParameterFilter { $Method -eq 'GET' }
        Mock Invoke-MgGraphRequest { } -ParameterFilter { $Method -eq 'PATCH' }

        $result = Add-StandardExclusionsToExistingPolicy -PolicyId 'p1' -NoMfaGroupId 'nomfa-id' -EmergencyAccessUserIds @('bg02-id')

        $result.Success | Should -BeTrue
        Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter {
            if ($Method -ne 'PATCH') { return $false }
            $sent = $Body | ConvertFrom-Json -AsHashtable
            ($sent.Keys -join ',') -eq 'conditions' -and
            ($sent['conditions'].Keys -join ',') -eq 'users' -and
            ((@($sent['conditions']['users']['excludeGroups']) -join ',') -eq 'intl-id,nomfa-id') -and
            ((@($sent['conditions']['users']['excludeUsers']) -join ',') -eq 'bg02-id') -and
            ((@($sent['conditions']['users']['includeUsers']) -join ',') -eq 'All')
        }
    }

    It 'reports failure, without throwing, when the update is rejected' {
        Mock Invoke-MgGraphRequest { @{ conditions = @{ users = @{ includeUsers = @('All') } } } } -ParameterFilter { $Method -eq 'GET' }
        Mock Invoke-MgGraphRequest { throw 'BadRequest' } -ParameterFilter { $Method -eq 'PATCH' }

        $result = Add-StandardExclusionsToExistingPolicy -PolicyId 'p1' -NoMfaGroupId 'nomfa-id' -EmergencyAccessUserIds @('bg02-id')

        $result.Success | Should -BeFalse
        $result.Error | Should -Match 'BadRequest'
    }
}

Describe 'New-ConditionalAccessPolicy (existing policy exclusions)' {

    BeforeEach {
        Set-TestState
        $c007 = Get-TestPolicies | Where-Object { $_.displayName -like 'C007*' }
        Mock New-MgIdentityConditionalAccessPolicy { }
    }

    It 'flags an existing policy that lacks the emergency access account' {
        Mock Get-MgIdentityConditionalAccessPolicy {
            [pscustomobject]@{
                Id          = 'current-id'
                DisplayName = 'C007 - Block Sign-In Outside UK'
                Conditions  = [pscustomobject]@{
                    Locations = [pscustomobject]@{ ExcludeLocations = @('uk-id') }
                    Users     = [pscustomobject]@{ ExcludeGroups = @('nomfa-id'); ExcludeUsers = @() }
                }
            }
        }

        $result = New-ConditionalAccessPolicy -PolicyConfig $c007 -NoMfaGroupId 'nomfa-id' -EmergencyAccessUserIds @('bg02-id') 6>$null

        $result.Skipped | Should -BeTrue
        $result.MissingExclusions | Should -BeTrue
    }

    It 'does not flag an existing policy that already has both exclusions' {
        Mock Get-MgIdentityConditionalAccessPolicy {
            [pscustomobject]@{
                Id          = 'current-id'
                DisplayName = 'C007 - Block Sign-In Outside UK'
                Conditions  = [pscustomobject]@{
                    Locations = [pscustomobject]@{ ExcludeLocations = @('uk-id') }
                    Users     = [pscustomobject]@{ ExcludeGroups = @('nomfa-id'); ExcludeUsers = @('bg02-id') }
                }
            }
        }

        $result = New-ConditionalAccessPolicy -PolicyConfig $c007 -NoMfaGroupId 'nomfa-id' -EmergencyAccessUserIds @('bg02-id') 6>$null

        $result.MissingExclusions | Should -BeFalse
    }
}

# ============================================================================
# Existing C007: detecting and updating one that is not in the current design
# ============================================================================
Describe 'Test-ExistingC007NeedsUpdate' {

    BeforeAll {
        function New-ExistingC007 {
            param(
                [string]$Name = 'C007 - Block Sign-In Outside UK',
                [string[]]$IncludeUsers = @('All'),
                [string[]]$ExcludeLocations = @('uk-id')
            )
            [pscustomobject]@{
                Id          = 'existing-id'
                DisplayName = $Name
                Conditions  = [pscustomobject]@{
                    Users     = [pscustomobject]@{ IncludeUsers = $IncludeUsers; ExcludeGroups = @(); ExcludeUsers = @() }
                    Locations = [pscustomobject]@{ ExcludeLocations = $ExcludeLocations }
                }
            }
        }
    }

    It 'leaves a C007 that is already in the current design alone' {
        Test-ExistingC007NeedsUpdate -ExistingPolicy (New-ExistingC007) -ExpectedName 'C007 - Block Sign-In Outside UK' | Should -BeFalse
    }

    It 'flags a C007 under its previous name' {
        Test-ExistingC007NeedsUpdate -ExistingPolicy (New-ExistingC007 -Name 'C007 - Block Sign-In Outside UK (UK Users)') `
            -ExpectedName 'C007 - Block Sign-In Outside UK' | Should -BeTrue
    }

    It 'flags a C007 that is scoped to a group instead of all users' {
        Test-ExistingC007NeedsUpdate -ExistingPolicy (New-ExistingC007 -IncludeUsers @()) -ExpectedName 'C007 - Block Sign-In Outside UK' | Should -BeTrue
    }

    It 'flags a C007 that excludes AllTrusted, with or without the UK location' -ForEach @(
        @{ Locations = @('uk-id', 'AllTrusted') }
        @{ Locations = @('AllTrusted') }
    ) {
        Test-ExistingC007NeedsUpdate -ExistingPolicy (New-ExistingC007 -ExcludeLocations $Locations) -ExpectedName 'C007 - Block Sign-In Outside UK' | Should -BeTrue
    }

    It 'flags a C007 with no excluded location at all' {
        Test-ExistingC007NeedsUpdate -ExistingPolicy (New-ExistingC007 -ExcludeLocations @()) -ExpectedName 'C007 - Block Sign-In Outside UK' | Should -BeTrue
    }
}

Describe 'Update-ExistingC007' {

    BeforeEach {
        Set-TestState
        $c007 = Get-TestPolicies | Where-Object { $_.displayName -like 'C007*' }
    }

    It 'sends the current design, keeps existing exclusions, drops AllTrusted and forces Report-only' {
        Mock Invoke-MgGraphRequest {
            @{
                state      = 'enabled'
                conditions = @{
                    users     = @{
                        includeUsers  = @()
                        includeGroups = @('old-uk-group-id')
                        excludeGroups = @('custom-group-id')
                        excludeUsers  = @('custom-user-id')
                    }
                    locations = @{ includeLocations = @('All'); excludeLocations = @('uk-id', 'AllTrusted') }
                }
            }
        } -ParameterFilter { $Method -eq 'GET' }
        Mock Invoke-MgGraphRequest { } -ParameterFilter { $Method -eq 'PATCH' }

        $result = Update-ExistingC007 -PolicyId 'old-id' -PolicyConfig $c007 -NoMfaGroupId 'nomfa-id' -EmergencyAccessUserIds @('bg02-id')

        $result.Success | Should -BeTrue
        $result.WasEnabled | Should -BeTrue
        Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter {
            if ($Method -ne 'PATCH') { return $false }
            $sent = $Body | ConvertFrom-Json -AsHashtable
            $users = $sent['conditions']['users']
            ($sent['displayName'] -eq 'C007 - Block Sign-In Outside UK') -and
            ($sent['state'] -eq 'enabledForReportingButNotEnforced') -and
            ((@($users['includeUsers']) -join ',') -eq 'All') -and
            (@($users['includeGroups']).Count -eq 0) -and
            ((@($users['excludeGroups'] | Sort-Object) -join ',') -eq 'custom-group-id,intl-id,nomfa-id,travel-id') -and
            ((@($users['excludeUsers'] | Sort-Object) -join ',') -eq 'bg02-id,custom-user-id') -and
            ($users['excludeGuestsOrExternalUsers']['guestOrExternalUserTypes'] -match 'serviceProvider') -and
            ((@($sent['conditions']['locations']['excludeLocations']) -join ',') -eq 'uk-id') -and
            (!$sent.ContainsKey('grantControls')) -and
            (!$sent['conditions'].ContainsKey('applications'))
        }
    }

    It 'reports failure, without throwing, when the update is rejected' {
        Mock Invoke-MgGraphRequest {
            @{ state = 'enabled'; conditions = @{ users = @{ includeUsers = @() }; locations = $null } }
        } -ParameterFilter { $Method -eq 'GET' }
        Mock Invoke-MgGraphRequest { throw 'BadRequest' } -ParameterFilter { $Method -eq 'PATCH' }

        $result = Update-ExistingC007 -PolicyId 'old-id' -PolicyConfig $c007 -NoMfaGroupId 'nomfa-id' -EmergencyAccessUserIds @('bg02-id')

        $result.Success | Should -BeFalse
        $result.Error | Should -Match 'BadRequest'
    }
}

Describe 'New-ConditionalAccessPolicy (existing C007 design check)' {

    BeforeEach {
        Set-TestState
        Mock New-MgIdentityConditionalAccessPolicy { }
        Mock Get-MgIdentityConditionalAccessPolicy {
            [pscustomobject]@{
                Id          = 'current-id'
                DisplayName = 'whatever the filter matched'
                Conditions  = [pscustomobject]@{
                    Users     = [pscustomobject]@{ IncludeUsers = @(); ExcludeGroups = @(); ExcludeUsers = @() }
                    Locations = [pscustomobject]@{ ExcludeLocations = @('AllTrusted') }
                }
            }
        }
    }

    It 'flags an existing C007 that is not in the current design' {
        $c007 = Get-TestPolicies | Where-Object { $_.displayName -like 'C007*' }
        $result = New-ConditionalAccessPolicy -PolicyConfig $c007 -NoMfaGroupId 'nomfa-id' -EmergencyAccessUserIds @('bg02-id') 6>$null

        $result.Skipped | Should -BeTrue
        $result.NeedsUpdate | Should -BeTrue
    }

    It 'never flags a policy other than C007' {
        $c006 = Get-TestPolicies | Where-Object { $_.displayName -like 'C006*' }
        $result = New-ConditionalAccessPolicy -PolicyConfig $c006 -NoMfaGroupId 'nomfa-id' -EmergencyAccessUserIds @('bg02-id') 6>$null

        $result.Skipped | Should -BeTrue
        $result.NeedsUpdate | Should -BeFalse
    }
}
