#Requires -Version 7.0

<#
.SYNOPSIS
    Creates distribution lists using Microsoft Graph API
.DESCRIPTION
    Interactive wizard for creating distribution lists using Microsoft Graph REST API.
    Includes preview and validation before creation.
.AUTHOR
    BITS
.VERSION
    2.1 - Non-interactive mode (-NonInteractive/-ConfigFile) for unattended
          E2E testing.
.PARAMETER NonInteractive
    Run unattended: skip all prompts and "press any key" pauses, creating
    exactly the distribution lists listed in -ConfigFile. Used by CI E2E
    tests.
.PARAMETER ConfigFile
    Required in non-interactive mode. JSON file with a "DistributionLists"
    array, each entry: DisplayName, PrimaryEmail, MailNickname (optional,
    derived from PrimaryEmail if omitted), Description (optional), Members
    (optional array of email addresses to add as initial members).
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
    DistributionLists = @()
}

if ($ConfigFile) {
    if (!(Test-Path $ConfigFile)) {
        Write-Host "Config file not found: $ConfigFile" -ForegroundColor Red
        if ($script:NonInteractive) { exit 2 } else { return }
    }
    try {
        $userConfig = Get-Content $ConfigFile -Raw | ConvertFrom-Json -AsHashtable
        if ($userConfig.ContainsKey('DistributionLists')) { $script:RunConfig.DistributionLists = @($userConfig.DistributionLists) }
        Write-Host "Loaded config from $ConfigFile" -ForegroundColor Gray
    }
    catch {
        Write-Host "Failed to parse config file: $($_.Exception.Message)" -ForegroundColor Red
        if ($script:NonInteractive) { exit 2 } else { return }
    }
}

$RequiredModules = @(
    'Microsoft.Graph.Authentication'
)

$RequiredScopes = @(
    "Group.ReadWrite.All",
    "Directory.Read.All"
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
    # @() wrap: Where-Object returns $null when nothing matches and a bare scalar
    # (no .Count) when exactly one item matches — either case throws under
    # Set-StrictMode
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

    # Get accepted domains
    Write-Host "   Getting accepted domains..." -ForegroundColor Gray
    $acceptedDomains = Get-AcceptedDomains
    if ($acceptedDomains.Count -gt 0) {
        Write-Host "   Found $($acceptedDomains.Count) accepted domain(s)" -ForegroundColor Green
    }
    else {
        Write-Host "   Could not retrieve domains (basic validation only)" -ForegroundColor Yellow
    }

    Write-Host ""
    return @{
        Success = $true
        AcceptedDomains = $acceptedDomains
    }
}

function Get-AcceptedDomains {
    try {
        $domains = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/organization?`$expand=verifiedDomains" -Method GET
        $acceptedDomains = $domains.value[0].verifiedDomains | Where-Object { $_.capabilities -contains "Email" } | Select-Object -ExpandProperty name
        return $acceptedDomains
    }
    catch {
        return @()
    }
}

# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

function Test-EmailFormat {
    param([string]$EmailAddress)
    $emailRegex = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return $EmailAddress -match $emailRegex
}

function Test-GroupExists {
    param([string]$MailNickname)
    try {
        $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=mailNickname eq '$MailNickname'"
        $existingGroups = Invoke-MgGraphRequest -Uri $uri -Method GET
        return ($existingGroups.value.Count -gt 0)
    }
    catch {
        return $false
    }
}

function Get-UserIdsFromEmails {
    param([string[]]$EmailAddresses)

    $userIds = @()

    foreach ($email in $EmailAddresses) {
        try {
            $uri = "https://graph.microsoft.com/v1.0/users?`$filter=mail eq '$email' or userPrincipalName eq '$email'"
            $user = Invoke-MgGraphRequest -Uri $uri -Method GET

            if ($user.value.Count -gt 0) {
                $userIds += "https://graph.microsoft.com/v1.0/users/$($user.value[0].id)"
                Write-Host "       Found: $email" -ForegroundColor Green
            }
            else {
                Write-Host "       Not found: $email (skipped)" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "       Error: $email (skipped)" -ForegroundColor Yellow
        }
    }

    return $userIds
}

# ============================================================================
# DISTRIBUTION LIST CREATION
# ============================================================================

function New-DistributionListInteractive {
    param([array]$AcceptedDomains)

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  NEW DISTRIBUTION LIST" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""

    if ($AcceptedDomains.Count -gt 0) {
        Write-Host "  Available domains: $($AcceptedDomains -join ', ')" -ForegroundColor Gray
    }
    Write-Host "  Type 'cancel' at any prompt to abort" -ForegroundColor Gray
    Write-Host ""

    # Get group name
    do {
        $groupName = Read-Host "  Display Name (e.g., Marketing Team)"
        if ($groupName -eq "cancel") { return $null }
    } while ([string]::IsNullOrWhiteSpace($groupName))

    # Get email address
    do {
        $defaultDomain = if ($AcceptedDomains.Count -gt 0) { $AcceptedDomains[0] } else { "yourdomain.com" }
        $suggestedEmail = ($groupName -replace '[^a-zA-Z0-9]', '').ToLower() + "@$defaultDomain"
        Write-Host "  Suggested: $suggestedEmail" -ForegroundColor Gray
        $primaryEmail = Read-Host "  Email Address (press Enter for suggested)"

        if ($primaryEmail -eq "cancel") { return $null }
        if ([string]::IsNullOrWhiteSpace($primaryEmail)) { $primaryEmail = $suggestedEmail }

        if (!(Test-EmailFormat $primaryEmail)) {
            Write-Host "  Invalid email format" -ForegroundColor Red
            $primaryEmail = $null
        }
        elseif ($AcceptedDomains.Count -gt 0) {
            $domain = ($primaryEmail -split '@')[1]
            if ($domain -notin $AcceptedDomains) {
                Write-Host "  Domain not accepted by tenant" -ForegroundColor Red
                $primaryEmail = $null
            }
        }
    } while ([string]::IsNullOrWhiteSpace($primaryEmail))

    # Get alias
    $suggestedAlias = ($primaryEmail -split '@')[0] -replace '[^a-zA-Z0-9]', ''
    $alias = Read-Host "  Alias (press Enter for '$suggestedAlias')"
    if ([string]::IsNullOrWhiteSpace($alias)) { $alias = $suggestedAlias }

    # Check if exists
    if (Test-GroupExists $alias) {
        Write-Host "  A group with this alias already exists" -ForegroundColor Red
        return $null
    }

    # Get description
    $description = Read-Host "  Description (optional)"
    if ([string]::IsNullOrWhiteSpace($description)) {
        $description = "Distribution list: $groupName"
    }

    # Get initial members
    Write-Host ""
    Write-Host "  Initial Members (optional):" -ForegroundColor Yellow
    Write-Host "  Enter email addresses separated by commas, or press Enter to skip" -ForegroundColor Gray
    $membersInput = Read-Host "  Members"

    $memberUserIds = @()
    if (![string]::IsNullOrWhiteSpace($membersInput)) {
        Write-Host "     Looking up users..." -ForegroundColor Gray
        $memberEmails = $membersInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { Test-EmailFormat $_ }
        if ($memberEmails.Count -gt 0) {
            $memberUserIds = Get-UserIdsFromEmails -EmailAddresses $memberEmails
        }
    }

    # Return the configuration
    return @{
        DisplayName = $groupName
        MailNickname = $alias
        PrimaryEmail = $primaryEmail
        Description = $description
        MemberUserIds = $memberUserIds
    }
}

function Show-DistributionListPreview {
    param([hashtable]$Config)

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  PREVIEW: Distribution List" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Display Name:  $($Config.DisplayName)" -ForegroundColor White
    Write-Host "  Email Address: $($Config.PrimaryEmail)" -ForegroundColor White
    Write-Host "  Alias:         $($Config.MailNickname)" -ForegroundColor White
    Write-Host "  Description:   $($Config.Description)" -ForegroundColor White
    Write-Host "  Members:       $(if ($Config.MemberUserIds.Count -gt 0) { $Config.MemberUserIds.Count } else { 'None' })" -ForegroundColor White
    Write-Host ""
}

function New-DistributionListFromConfig {
    param([hashtable]$Config)

    try {
        $groupBody = @{
            displayName = $Config.DisplayName
            mailNickname = $Config.MailNickname
            description = $Config.Description
            mailEnabled = $true
            securityEnabled = $false
            groupTypes = @()
        }

        if ($Config.MemberUserIds.Count -gt 0) {
            $groupBody["members@odata.bind"] = $Config.MemberUserIds
        }

        $newGroup = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups" -Method POST -Body $groupBody

        Write-Host "     Created successfully (ID: $($newGroup.id))" -ForegroundColor Green
        return @{ Success = $true; Group = $newGroup }
    }
    catch {
        Write-Host "     Failed: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-DistributionListCreation {
    # Header
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  DISTRIBUTION LISTS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Creates Exchange distribution lists via Microsoft Graph" -ForegroundColor Gray
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

    if ($script:NonInteractive) {
        Write-Host ""
        Write-Host "  STEP 2: Creating Distribution Lists (non-interactive)" -ForegroundColor Yellow
        Write-Host ("   " + "-" * 50) -ForegroundColor Gray

        $results = @{ Created = @(); Skipped = @(); Failed = @() }

        foreach ($dlConfig in $script:RunConfig.DistributionLists) {
            $primaryEmail = $dlConfig.PrimaryEmail
            Write-Host "   $($dlConfig.DisplayName) ($primaryEmail)..." -ForegroundColor White

            if (!(Test-EmailFormat $primaryEmail)) {
                Write-Host "     Failed: invalid email address format" -ForegroundColor Red
                $results.Failed += @{ Name = $primaryEmail; Error = 'Invalid email address format' }
                continue
            }

            $mailNickname = if ($dlConfig.ContainsKey('MailNickname') -and $dlConfig.MailNickname) { $dlConfig.MailNickname } else { ($primaryEmail -split '@')[0] -replace '[^a-zA-Z0-9]', '' }

            if (Test-GroupExists $mailNickname) {
                Write-Host "     Already exists (skipped)" -ForegroundColor Yellow
                $results.Skipped += $primaryEmail
                continue
            }

            $memberUserIds = @()
            $members = if ($dlConfig.ContainsKey('Members')) { @($dlConfig.Members) } else { @() }
            if ($members.Count -gt 0) {
                Write-Host "     Looking up members..." -ForegroundColor Gray
                $memberUserIds = Get-UserIdsFromEmails -EmailAddresses $members
            }

            $config = @{
                DisplayName   = $dlConfig.DisplayName
                MailNickname  = $mailNickname
                PrimaryEmail  = $primaryEmail
                Description   = if ($dlConfig.ContainsKey('Description') -and $dlConfig.Description) { $dlConfig.Description } else { "Distribution list: $($dlConfig.DisplayName)" }
                MemberUserIds = $memberUserIds
            }

            $result = New-DistributionListFromConfig -Config $config
            if ($result.Success) {
                $results.Created += $primaryEmail
            }
            else {
                $results.Failed += @{ Name = $primaryEmail; Error = $result.Error }
            }
        }

        Write-Host ""
        Write-Host ("=" * 70) -ForegroundColor Cyan
        Write-Host "  SUMMARY" -ForegroundColor Cyan
        Write-Host ("=" * 70) -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Created: $($results.Created.Count)" -ForegroundColor Green
        Write-Host "  Skipped (existing): $($results.Skipped.Count)" -ForegroundColor Yellow
        Write-Host "  Failed: $($results.Failed.Count)" -ForegroundColor $(if ($results.Failed.Count -gt 0) { "Red" } else { "Green" })
        Write-Host ""

        if ($ResultPath) {
            @{
                Success = ($results.Failed.Count -eq 0)
                Created = @($results.Created)
                Skipped = @($results.Skipped)
                Failed  = @($results.Failed)
            } | ConvertTo-Json -Depth 5 | Set-Content -Path $ResultPath -Encoding UTF8
            Write-Host "  Results written to $ResultPath" -ForegroundColor Gray
        }
        return
    }

    $totalCreated = 0
    $totalFailed = 0

    # Loop to create multiple lists
    do {
        # Step 2: Collect information
        Write-Host ""
        Write-Host "  STEP 2: Distribution List Details" -ForegroundColor Yellow
        $config = New-DistributionListInteractive -AcceptedDomains $prereqResult.AcceptedDomains

        if ($null -eq $config) {
            Write-Host "  Cancelled" -ForegroundColor Yellow
            break
        }

        # Step 3: Preview
        Write-Host ""
        Write-Host "  STEP 3: Preview" -ForegroundColor Yellow
        Show-DistributionListPreview -Config $config

        # Confirmation
        Write-Host "  [Y] Create this list  [N] Cancel" -ForegroundColor Gray
        $confirm = Read-Host "  Create? (Y/N)"

        if ($confirm -like "Y*") {
            # Step 4: Create
            Write-Host ""
            Write-Host "  STEP 4: Creating Distribution List" -ForegroundColor Yellow
            Write-Host ("   " + "-" * 50) -ForegroundColor Gray
            Write-Host "   $($config.DisplayName)..." -ForegroundColor White

            $result = New-DistributionListFromConfig -Config $config

            if ($result.Success) {
                $totalCreated++
                Write-Host ""
                Write-Host "  Email: $($result.Group.mail)" -ForegroundColor Green
            }
            else {
                $totalFailed++
            }
        }
        else {
            Write-Host "  Skipped" -ForegroundColor Yellow
        }

        Write-Host ""
        $another = Read-Host "  Create another distribution list? (y/N)"

    } while ($another -like "y*")

    # Summary
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Created: $totalCreated" -ForegroundColor Green
    Write-Host "  Failed:  $totalFailed" -ForegroundColor $(if ($totalFailed -gt 0) { "Red" } else { "Green" })
    Write-Host ""

    if ($totalCreated -gt 0) {
        Write-Host "  Next Steps:" -ForegroundColor Yellow
        Write-Host "    1. Add members via Microsoft 365 Admin Center if needed" -ForegroundColor Gray
        Write-Host "    2. Configure delivery management settings" -ForegroundColor Gray
        Write-Host "    3. Set message approval if required" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  Manage groups at:" -ForegroundColor Yellow
        Write-Host "    https://admin.microsoft.com/AdminPortal/Home#/groups" -ForegroundColor Cyan
    }

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

    Start-DistributionListCreation
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
}
