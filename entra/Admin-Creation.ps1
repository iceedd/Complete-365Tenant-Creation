#Requires -Version 7.0

<#
.SYNOPSIS
    Creates administrative accounts for tenant management
.DESCRIPTION
    Creates BITS admin accounts with proper group memberships and Entra ID role assignments.
    Includes preview mode and secure password generation.

    Accounts Created:
    - BITS-Admin-Cloud (Intune Admin + Device Local Admin)
    - BITS-Admin-HD (Line 1 Helpdesk - User/Auth/Exchange/Teams/Intune/SharePoint Admin)
    - BITS-Admin-BG01 (Break Glass #1 - Global Admin, MFA required)
    - BITS-Admin-BG02 (Break Glass #2 - Global Admin, NoMFA exempt)

    Cloud Admin Roles:
    - Intune Administrator: Full Intune management
    - Azure AD Joined Device Local Administrator: Local admin on devices
    - Intune Help Desk Operator (via Helpdesk Operator Group)

    HD Admin Roles (hands-on Line 1 support):
    - User Administrator: Manage users, passwords, groups, licenses
    - Authentication Administrator: Reset MFA for non-admins
    - Exchange Administrator: Mailbox management, mail flow
    - Teams Administrator: Teams support
    - Intune Administrator: Device management
    - SharePoint Administrator: OneDrive/SharePoint issues
    - Intune Help Desk Operator (via Helpdesk Operator Group)
.AUTHOR
    BITS
.VERSION
    2.4 - Non-interactive mode (-NonInteractive/-ConfigFile) for unattended
          E2E testing. 2.3 made existing-account role/group checks idempotent.
.PARAMETER NonInteractive
    Run unattended: skip the Y/N confirmation and all "press any key" pauses,
    never attempt interactive re-consent, and never print generated passwords
    to the console (CI logs persist — plaintext secrets don't belong there).
    Used by CI E2E tests.
.PARAMETER ConfigFile
    Optional JSON file overriding run behaviour. Supported keys:
      NamePrefix      (string) prefixed to every account UPN/DisplayName, e.g. "E2E-"
      GroupNamePrefix (string) prefixed to the group names this script references
                       (BITS Admin Users, Helpdesk Operator Group, NoMFA Exclusion
                       Group) — lets E2E tests point at throwaway prefixed groups
                       created by a prior Security-Groups E2E run
      AssignEntraRoles (bool) assign Entra ID directory roles (default true)
      AssignIntuneRoles (bool) assign Intune Help Desk Operator role (default true)
.PARAMETER ResultPath
    Optional path to write a JSON results summary (created/skipped/failed —
    never passwords), so a CI runner can assert on the outcome.
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
    NamePrefix        = ''
    GroupNamePrefix   = ''
    AssignEntraRoles  = $true
    AssignIntuneRoles = $true
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
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Identity.DirectoryManagement'
)

$RequiredScopes = @(
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory"
)

# ============================================================================
# ENTRA ID ROLE DEFINITIONS
# ============================================================================

# Built-in Entra ID Role IDs
$EntraRoles = @{
    "Global Administrator"                      = "62e90394-69f5-4237-9190-012177145e10"
    "User Administrator"                        = "fe930be7-5e62-47db-91af-98c3a49a38b1"
    "Authentication Administrator"              = "c4e39bd9-1100-46d3-8c65-fb160da0071f"
    "Exchange Administrator"                    = "29232cdf-9323-42fd-ade2-1d097af3e4de"
    "Teams Administrator"                       = "69091246-20e8-4a56-aa4d-066075b2a7a8"
    "Intune Administrator"                      = "3a2c62db-5318-420d-8d74-23affee5d9d5"
    "SharePoint Administrator"                  = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"
    "Helpdesk Administrator"                    = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
    "License Administrator"                     = "4d6ac14f-3453-41d0-bef9-a3e0c569773a"
    "Security Administrator"                    = "194ae4cb-b126-40b2-bd5b-6091b380977d"
    "Conditional Access Admin"                  = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"
    "Azure AD Joined Device Local Administrator" = "9f06204d-73c1-4d4c-880a-6edb90606fd8"
    "Cloud Device Administrator"                = "7698a772-787b-4ac8-901f-60d6b08affd2"
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

function New-SecurePassword {
    param([int]$Length = 12)

    $upperCase = 'ABCDEFGHKLMNOPRSTUVWXYZ'
    $lowerCase = 'abcdefghiklmnoprstuvwxyz'
    $numbers = '1234567890'
    $special = '!@#$%^&*()_+-=[]{}|;:,.<>?'

    $password = @()
    $password += Get-Random -InputObject $upperCase.ToCharArray()
    $password += Get-Random -InputObject $lowerCase.ToCharArray()
    $password += Get-Random -InputObject $numbers.ToCharArray()
    $password += Get-Random -InputObject $special.ToCharArray()

    $allChars = $upperCase + $lowerCase + $numbers + $special
    for ($i = 4; $i -lt $Length; $i++) {
        $password += Get-Random -InputObject $allChars.ToCharArray()
    }

    $shuffledPassword = $password | Sort-Object { Get-Random }
    return -join $shuffledPassword
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

    # Get tenant domain
    Write-Host "   Getting tenant information..." -ForegroundColor Gray
    try {
        $organization = Get-MgOrganization | Select-Object -First 1
        $defaultDomain = $organization.VerifiedDomains | Where-Object { $_.IsDefault -eq $true } | Select-Object -ExpandProperty Name

        if ([string]::IsNullOrEmpty($defaultDomain)) {
            Write-Host "   No default domain found" -ForegroundColor Red
            return @{ Success = $false }
        }
        Write-Host "   Tenant: $($organization.DisplayName)" -ForegroundColor Green
        Write-Host "   Domain: $defaultDomain" -ForegroundColor Green
    }
    catch {
        Write-Host "   Failed to get tenant info: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false }
    }

    # Detect usage location from tenant country code, fall back to GB
    $usageLocation = if (-not [string]::IsNullOrEmpty($organization.CountryLetterCode)) {
        $organization.CountryLetterCode
    } else { "GB" }

    # Check for required groups
    Write-Host "   Checking for required groups..." -ForegroundColor Gray
    $groupPrefix = $script:RunConfig.GroupNamePrefix
    $requiredGroups = @("${groupPrefix}BITS Admin Users", "${groupPrefix}NoMFA Exclusion Group")
    $missingGroups = @()

    foreach ($groupName in $requiredGroups) {
        $group = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue
        if (!$group) {
            $missingGroups += $groupName
        }
    }

    if ($missingGroups.Count -gt 0) {
        Write-Host "   Missing groups: $($missingGroups -join ', ')" -ForegroundColor Yellow
        Write-Host "   Run Security Groups script first, or groups will be created" -ForegroundColor Yellow
    }
    else {
        Write-Host "   All required groups found" -ForegroundColor Green
    }

    Write-Host ""
    return @{
        Success = $true
        DefaultDomain = $defaultDomain
        OrganizationName = $organization.DisplayName
        MissingGroups = $missingGroups
        UsageLocation = $usageLocation
    }
}

# ============================================================================
# DATA FUNCTIONS
# ============================================================================

function Get-AdminAccountDefinitions {
    param(
        [string]$DefaultDomain,
        [string]$UsageLocation = "GB"
    )

    $namePrefix  = $script:RunConfig.NamePrefix
    $groupPrefix = $script:RunConfig.GroupNamePrefix

    $accounts = @(
        @{
            Role = "Cloud"
            UPN = "BITS-Admin-Cloud@$DefaultDomain"
            DisplayName = "BITS-Admin-Cloud"
            JobTitle = "Cloud Administrator"
            PasswordLength = 12
            UsageLocation = $UsageLocation
            Groups = @("BITS Admin Users", "Helpdesk Operator Group")
            Description = "Primary cloud admin account"
            EntraRoles = @(
                "Intune Administrator"
                "Azure AD Joined Device Local Administrator"
            )
        },
        @{
            Role = "HD"
            UPN = "BITS-Admin-HD@$DefaultDomain"
            DisplayName = "BITS-Admin-HD"
            JobTitle = "Helpdesk Administrator"
            PasswordLength = 12
            UsageLocation = $UsageLocation
            Groups = @("BITS Admin Users", "Helpdesk Operator Group")
            Description = "Line 1 helpdesk support account"
            EntraRoles = @(
                "User Administrator"
                "Authentication Administrator"
                "Exchange Administrator"
                "Teams Administrator"
                "Intune Administrator"
                "SharePoint Administrator"
            )
        },
        @{
            Role = "BG01"
            UPN = "BITS-Admin-BG01@$DefaultDomain"
            DisplayName = "BITS-Admin-BG01"
            JobTitle = "Emergency Access Account"
            PasswordLength = 18
            UsageLocation = $UsageLocation
            Groups = @("BITS Admin Users")
            Description = "Break glass #1 (MFA required)"
            EntraRoles = @(
                "Global Administrator"
            )
        },
        @{
            Role = "BG02"
            UPN = "BITS-Admin-BG02@$DefaultDomain"
            DisplayName = "BITS-Admin-BG02"
            JobTitle = "Emergency Access Account (NoMFA)"
            PasswordLength = 18
            UsageLocation = $UsageLocation
            Groups = @("BITS Admin Users", "NoMFA Exclusion Group")
            Description = "Break glass #2 (NoMFA exempt)"
            EntraRoles = @(
                "Global Administrator"
            )
        }
    )

    # Apply configured prefixes (test isolation: E2E runs use "E2E-" so created
    # accounts and the groups they reference are identifiable and safely deletable).
    # UPN is rebuilt from the still-unprefixed DisplayName before DisplayName itself
    # is prefixed, so the local part and display name stay in sync.
    if ($namePrefix -or $groupPrefix) {
        foreach ($account in $accounts) {
            $account.UPN         = "$namePrefix$($account.DisplayName)@$DefaultDomain"
            $account.DisplayName = "$namePrefix$($account.DisplayName)"
            $account.Groups      = @($account.Groups | ForEach-Object { "$groupPrefix$_" })
        }
    }

    return $accounts
}

# ============================================================================
# PREVIEW MODE
# ============================================================================

function Show-AdminPreview {
    param(
        [array]$Accounts,
        [string]$DefaultDomain
    )

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  PREVIEW: Admin Accounts" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Domain: $DefaultDomain" -ForegroundColor White
    Write-Host ""
    Write-Host "  The following $($Accounts.Count) admin accounts will be created:" -ForegroundColor White
    Write-Host ""

    # Header
    Write-Host "  # | Account               | Role                    | Password" -ForegroundColor Yellow
    Write-Host "  --|------------------------|-------------------------|----------" -ForegroundColor Gray

    $index = 1
    foreach ($account in $Accounts) {
        $existing = Get-MgUser -Filter "userPrincipalName eq '$($account.UPN)'" -ErrorAction SilentlyContinue
        $status = if ($existing) { "EXISTS" } else { "$($account.PasswordLength) chars" }
        $statusColor = if ($existing) { "Yellow" } else { "Green" }

        Write-Host -NoNewline ("  {0,2} | {1,-22} | {2,-23} | " -f $index, $account.DisplayName, $account.JobTitle.Substring(0, [Math]::Min(23, $account.JobTitle.Length)))
        Write-Host $status -ForegroundColor $statusColor
        $index++
    }

    Write-Host ""
    Write-Host "  Entra ID Role Assignments:" -ForegroundColor Yellow
    Write-Host "    BITS-Admin-Cloud:" -ForegroundColor Gray
    Write-Host "      - Intune Administrator (full Intune management)" -ForegroundColor Cyan
    Write-Host "      - Azure AD Joined Device Local Administrator (local admin on devices)" -ForegroundColor Cyan
    Write-Host "      - Intune Help Desk Operator role (via Helpdesk Operator Group)" -ForegroundColor Cyan
    Write-Host "    BITS-Admin-HD (Line 1 Helpdesk):" -ForegroundColor Gray
    Write-Host "      - User Administrator (users, passwords, groups, licenses)" -ForegroundColor Cyan
    Write-Host "      - Authentication Administrator (MFA resets)" -ForegroundColor Cyan
    Write-Host "      - Exchange Administrator (mailboxes, mail flow)" -ForegroundColor Cyan
    Write-Host "      - Teams Administrator (Teams support)" -ForegroundColor Cyan
    Write-Host "      - Intune Administrator (device management)" -ForegroundColor Cyan
    Write-Host "      - SharePoint Administrator (OneDrive/SharePoint)" -ForegroundColor Cyan
    Write-Host "      - Intune Help Desk Operator role (via Helpdesk Operator Group)" -ForegroundColor Cyan
    Write-Host "    BITS-Admin-BG01 & BG02:" -ForegroundColor Gray
    Write-Host "      - Global Administrator (emergency access only)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Group Memberships:" -ForegroundColor Yellow
    Write-Host "    - Cloud & HD Admins -> BITS Admin Users + Helpdesk Operator Group" -ForegroundColor Gray
    Write-Host "    - BG01 -> BITS Admin Users (requires MFA)" -ForegroundColor Gray
    Write-Host "    - BG02 -> BITS Admin Users + NoMFA Exclusion Group" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Password Generation:" -ForegroundColor Yellow
    Write-Host "    - Standard accounts: 12 characters" -ForegroundColor Gray
    Write-Host "    - Break glass accounts: 18 characters" -ForegroundColor Gray
    Write-Host "    - All passwords: Upper + Lower + Numbers + Special" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  SECURITY WARNING:" -ForegroundColor Red
    Write-Host "    Passwords will be displayed ONCE after creation." -ForegroundColor Yellow
    Write-Host "    Have a secure password manager ready!" -ForegroundColor Yellow
    Write-Host ""
}

# ============================================================================
# ACCOUNT CREATION
# ============================================================================

function New-AdminAccount {
    param([hashtable]$AccountConfig)

    try {
        # Check if user already exists
        $existingUser = Get-MgUser -Filter "userPrincipalName eq '$($AccountConfig.UPN)'" -ErrorAction SilentlyContinue

        if ($existingUser) {
            Write-Host "     Already exists (skipped)" -ForegroundColor Yellow
            return @{ Success = $true; Skipped = $true; User = $existingUser; Password = $null }
        }

        # Generate password
        $password = New-SecurePassword -Length $AccountConfig.PasswordLength

        # Create user
        $userParams = @{
            UserPrincipalName = $AccountConfig.UPN
            DisplayName = $AccountConfig.DisplayName
            GivenName = "BITS Admin"
            Surname = $AccountConfig.Role
            JobTitle = $AccountConfig.JobTitle
            Department = "BITS Admin"
            AccountEnabled = $true
            PasswordProfile = @{
                Password = $password
                ForceChangePasswordNextSignIn = $false
            }
            MailNickname = $AccountConfig.DisplayName -replace '[^a-zA-Z0-9]', ''
            UsageLocation = $AccountConfig.UsageLocation
        }

        $newUser = New-MgUser -BodyParameter $userParams -ErrorAction Stop

        Write-Host "     Created (ID: $($newUser.Id))" -ForegroundColor Green
        return @{ Success = $true; Skipped = $false; User = $newUser; Password = $password }
    }
    catch {
        Write-Host "     Failed: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Add-IntuneHelpDeskOperatorRole {
    <#
    .SYNOPSIS
        Assigns the Intune Help Desk Operator role to the Helpdesk Operator Group
    #>
    param([string]$GroupId)

    try {
        Write-Host "     Assigning Intune Help Desk Operator role to group..." -ForegroundColor Gray

        # Get the built-in Help Desk Operator role definition
        $roleDefsUri = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions?`$filter=isBuiltIn eq true"
        $roleDefs = Invoke-MgGraphRequest -Uri $roleDefsUri -Method GET
        $helpDeskRole = $roleDefs.value | Where-Object { $_.displayName -eq "Help Desk Operator" } | Select-Object -First 1

        if (!$helpDeskRole) {
            Write-Host "       Help Desk Operator role not found" -ForegroundColor Yellow
            return $false
        }

        # Check if assignment already exists
        $existingUri = "https://graph.microsoft.com/beta/deviceManagement/roleAssignments?`$filter=displayName eq 'Helpdesk Operator Group Assignment'"
        $existing = Invoke-MgGraphRequest -Uri $existingUri -Method GET
        if ($existing.value.Count -gt 0) {
            Write-Host "       Role assignment already exists" -ForegroundColor Gray
            return $true
        }

        # Create the role assignment - simpler structure for allDevices scope
        $assignmentBody = @{
            id = ""
            displayName = "Helpdesk Operator Group Assignment"
            description = "Assigns Help Desk Operator role to Helpdesk Operator Group"
            members = @($GroupId)
            resourceScopes = @()
            scopeType = "allDevices"
            "roleDefinition@odata.bind" = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions('$($helpDeskRole.id)')"
        }

        $assignUri = "https://graph.microsoft.com/beta/deviceManagement/roleAssignments"
        $null = Invoke-MgGraphRequest -Uri $assignUri -Method POST -Body $assignmentBody
        Write-Host "       Assigned Intune Help Desk Operator role to group" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "       Failed to assign Intune role: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "       You may need to assign this manually in Intune" -ForegroundColor Gray
        return $false
    }
}

function Add-UserToEntraRoles {
    param(
        [object]$User,
        [array]$RoleNames
    )

    foreach ($roleName in $RoleNames) {
        if (!$EntraRoles.ContainsKey($roleName)) {
            Write-Host "       Unknown role: $roleName" -ForegroundColor Yellow
            continue
        }

        $roleId = $EntraRoles[$roleName]

        try {
            # Check if already assigned (using direct API to avoid module conflicts)
            $checkUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($User.Id)' and roleDefinitionId eq '$roleId'"
            $existingAssignment = Invoke-MgGraphRequest -Uri $checkUri -Method GET -ErrorAction SilentlyContinue

            if ($existingAssignment.value.Count -gt 0) {
                Write-Host "       Already has: $roleName" -ForegroundColor Gray
                continue
            }

            # Assign the role (using direct API)
            $assignUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
            $roleAssignment = @{
                "@odata.type" = "#microsoft.graph.unifiedRoleAssignment"
                principalId = $User.Id
                roleDefinitionId = $roleId
                directoryScopeId = "/"
            }

            $null = Invoke-MgGraphRequest -Uri $assignUri -Method POST -Body $roleAssignment -ErrorAction Stop
            Write-Host "       Assigned: $roleName" -ForegroundColor Green
        }
        catch {
            Write-Host "       Failed to assign $roleName : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

function Add-UserToGroups {
    param(
        [object]$User,
        [array]$GroupNames
    )

    foreach ($groupName in $GroupNames) {
        $group = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue

        if (!$group) {
            # Try to create the group if it's the Helpdesk Operator Group
            if ($groupName -eq "$($script:RunConfig.GroupNamePrefix)Helpdesk Operator Group") {
                try {
                    $namePrefix = $script:RunConfig.NamePrefix
                    $groupParams = @{
                        DisplayName = $groupName
                        Description = "Dynamic group for Intune Help Desk Operator role"
                        GroupTypes = @("DynamicMembership")
                        MailEnabled = $false
                        MailNickname = ($groupName -replace '[^a-zA-Z0-9]', '')
                        MembershipRule = "(user.displayName -startsWith `"${namePrefix}BITS-Admin-Cloud`") or (user.displayName -startsWith `"${namePrefix}BITS-Admin-HD`")"
                        MembershipRuleProcessingState = "On"
                        SecurityEnabled = $true
                    }
                    $group = New-MgGroup -BodyParameter $groupParams -ErrorAction Stop
                    Write-Host "       Created group: $groupName" -ForegroundColor Green
                }
                catch {
                    Write-Host "       Could not create group: $groupName" -ForegroundColor Yellow
                    continue
                }
            }
            else {
                Write-Host "       Group not found: $groupName" -ForegroundColor Yellow
                continue
            }
        }

        # Check if dynamic group
        if ($group.GroupTypes -contains "DynamicMembership") {
            Write-Host "       $groupName (dynamic - auto membership)" -ForegroundColor Gray
            continue
        }

        # Add to static group
        try {
            New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $User.Id -ErrorAction Stop
            Write-Host "       Added to $groupName" -ForegroundColor Green
        }
        catch {
            # Graph's actual duplicate-member error is "...already exist for the
            # following modified properties: 'members'." (no trailing "s") — the
            # E2E idempotency run hit this exact mismatch, since the "*already
            # exists*" pattern never matched and every re-add fell through to the
            # generic failure branch below
            if ($_.Exception.Message -like "*already exist*") {
                Write-Host "       Already in $groupName" -ForegroundColor Gray
            }
            else {
                Write-Host "       Failed to add to ${groupName}: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-AdminCreation {
    # Header
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  ADMIN ACCOUNT CREATION" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Creates BITS administrative accounts for tenant management" -ForegroundColor Gray
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

    # Get account definitions
    $accounts = Get-AdminAccountDefinitions -DefaultDomain $prereqResult.DefaultDomain -UsageLocation $prereqResult.UsageLocation

    # Step 2: Preview
    Write-Host ""
    Write-Host "  STEP 2: Preview" -ForegroundColor Yellow
    Show-AdminPreview -Accounts $accounts -DefaultDomain $prereqResult.DefaultDomain

    # Confirmation (skipped in unattended mode)
    if ($script:NonInteractive) {
        Write-Host "  Non-interactive mode: proceeding without confirmation" -ForegroundColor Gray
    }
    else {
        Write-Host "  [Y] Proceed with creation  [N] Cancel" -ForegroundColor Gray
        Write-Host ""
        $confirm = Read-Host "  Create these admin accounts? (Y/N)"

        if ($confirm -notlike "Y*") {
            Write-Host ""
            Write-Host "  Cancelled by user" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
            return
        }
    }

    # Step 3: Execute
    Write-Host ""
    Write-Host "  STEP 3: Creating Accounts" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    $results = @{
        Created = @()
        Skipped = @()
        Failed = @()
        Passwords = @{}
    }

    foreach ($account in $accounts) {
        Write-Host "   $($account.DisplayName)..." -ForegroundColor White

        $result = New-AdminAccount -AccountConfig $account

        if ($result.Success) {
            if ($result.Skipped) {
                $results.Skipped += @{ Name = $account.DisplayName; UPN = $account.UPN }
                Write-Host "     Already exists - checking groups and roles..." -ForegroundColor Gray
            }
            else {
                $results.Created += @{ Name = $account.DisplayName; UPN = $account.UPN; Id = $result.User.Id }
                $results.Passwords[$account.UPN] = $result.Password
            }

            # Add to groups (for both new and existing accounts)
            Write-Host "     Adding to groups..." -ForegroundColor Gray
            Add-UserToGroups -User $result.User -GroupNames $account.Groups

            # Assign Entra ID roles (for both new and existing accounts)
            if ($account.EntraRoles -and $account.EntraRoles.Count -gt 0 -and $script:RunConfig.AssignEntraRoles) {
                Write-Host "     Assigning Entra ID roles..." -ForegroundColor Gray
                Add-UserToEntraRoles -User $result.User -RoleNames $account.EntraRoles
            }
        }
        else {
            $results.Failed += @{ Name = $account.DisplayName; Error = $result.Error }
        }

        Start-Sleep -Milliseconds 500
    }

    # Assign Intune Help Desk Operator role to Helpdesk Operator Group
    if ($script:RunConfig.AssignIntuneRoles) {
        Write-Host ""
        Write-Host "   Configuring Intune RBAC..." -ForegroundColor White
        $helpdeskGroupName = "$($script:RunConfig.GroupNamePrefix)Helpdesk Operator Group"
        $helpdeskGroup = Get-MgGroup -Filter "displayName eq '$helpdeskGroupName'" -ErrorAction SilentlyContinue
        if ($helpdeskGroup) {
            $null = Add-IntuneHelpDeskOperatorRole -GroupId $helpdeskGroup.Id
        }
        else {
            Write-Host "     $helpdeskGroupName not found - skipping Intune role" -ForegroundColor Yellow
        }
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

    if ($results.Failed.Count -gt 0) {
        Write-Host "  Failed Accounts:" -ForegroundColor Red
        foreach ($fail in $results.Failed) {
            Write-Host "    - $($fail.Name): $($fail.Error)" -ForegroundColor Red
        }
        Write-Host ""
    }

    # Show passwords (critical section) — never in unattended mode: CI logs
    # persist, and automated verification doesn't need the plaintext value
    if (!$script:NonInteractive -and $results.Passwords.Count -gt 0) {
        Write-Host ("=" * 70) -ForegroundColor Red
        Write-Host "  GENERATED PASSWORDS - SAVE THESE NOW!" -ForegroundColor Red
        Write-Host ("=" * 70) -ForegroundColor Red
        Write-Host ""
        Write-Host "  These passwords will NOT be displayed again!" -ForegroundColor Yellow
        Write-Host ""

        foreach ($upn in $results.Passwords.Keys) {
            Write-Host "  $upn" -ForegroundColor White
            Write-Host "  Password: " -NoNewline -ForegroundColor Gray
            Write-Host $results.Passwords[$upn] -ForegroundColor Green
            Write-Host ""
        }

        Write-Host ("=" * 70) -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "  IMPORTANT - Next Steps:" -ForegroundColor Yellow
    Write-Host "    1. SAVE ALL PASSWORDS to a secure password manager NOW" -ForegroundColor Gray
    Write-Host "    2. Wait 5-10 minutes for dynamic group membership" -ForegroundColor Gray
    Write-Host "    3. Test each admin account login" -ForegroundColor Gray
    Write-Host "    4. Run Conditional Access Policies script" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  Roles Auto-Assigned:" -ForegroundColor Green
    Write-Host "    - Cloud Admin: Intune Admin + Device Local Admin" -ForegroundColor Gray
    Write-Host "    - HD Admin: User, Auth, Exchange, Teams, Intune, SharePoint Admin" -ForegroundColor Gray
    Write-Host "    - Break Glass: Global Administrator" -ForegroundColor Gray
    Write-Host "    - Helpdesk Operator Group: Intune Help Desk Operator role" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  Security Reminders:" -ForegroundColor Red
    Write-Host "    - Only BG02 is exempt from MFA" -ForegroundColor Gray
    Write-Host "    - Store break glass passwords separately from daily admin passwords" -ForegroundColor Gray
    Write-Host "    - HD Admin cannot reset MFA for other admins (by design)" -ForegroundColor Gray
    Write-Host "    - Consider setting up sign-in alerts for BG accounts (Azure Monitor or manual review)" -ForegroundColor Gray
    Write-Host ""

    # Machine-readable results for CI runners — never includes passwords
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

    Start-AdminCreation
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
}
