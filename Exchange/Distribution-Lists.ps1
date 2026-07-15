#Requires -Version 7.0

<#
.SYNOPSIS
    Creates Exchange Online distribution lists
.DESCRIPTION
    Interactive wizard for creating distribution groups in Exchange Online.
    Includes preview and validation before creation.
.AUTHOR
    BITS
.VERSION
    3.0 - Switched from Microsoft Graph to Exchange Online cmdlets. A live
          E2E run confirmed the Graph-based approach (POST /groups with
          mailEnabled=true, securityEnabled=false, groupTypes=[]) always
          400s — Microsoft's own groups-overview documentation lists
          distribution groups as read-only via Microsoft Graph; the only
          way to create one is via Exchange Online PowerShell. Also adds
          non-interactive mode (-NonInteractive/-ConfigFile) for unattended
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
    'ExchangeOnlineManagement'
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

    # Check Exchange Online connection
    Write-Host "   Checking Exchange Online connection..." -ForegroundColor Gray
    $connection = Get-ConnectionInformation -ErrorAction SilentlyContinue
    if (!$connection -or $connection.State -ne "Connected") {
        Write-Host "   Not connected to Exchange Online" -ForegroundColor Red
        Write-Host "   Please connect using the main menu first" -ForegroundColor Yellow
        Write-Host ""
        return @{ Success = $false }
    }
    Write-Host "   Connected as: $($connection.UserPrincipalName)" -ForegroundColor Green

    # Get accepted domains
    Write-Host "   Retrieving accepted domains..." -ForegroundColor Gray
    try {
        $domains = Get-AcceptedDomain -ErrorAction Stop
        # @() wrap: Where-Object/-ExpandProperty return $null when nothing
        # matches and a bare scalar (no .Count) when exactly one item matches —
        # either case throws under Set-StrictMode
        $acceptedDomains = @($domains | Where-Object { $_.DomainType -eq "Authoritative" } | Select-Object -ExpandProperty DomainName)
        if ($acceptedDomains.Count -gt 0) {
            Write-Host "   Found $($acceptedDomains.Count) accepted domain(s)" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "   Could not retrieve accepted domains (basic validation only)" -ForegroundColor Yellow
        $acceptedDomains = @()
    }

    Write-Host ""
    return @{
        Success         = $true
        AcceptedDomains = $acceptedDomains
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
        $existing = Get-DistributionGroup -Identity $MailNickname -ErrorAction SilentlyContinue
        return ($null -ne $existing)
    }
    catch {
        return $false
    }
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

    # @() wrap applied to the whole if/else, not nested inside a branch — a
    # single-element result from inside a branch still collapses to a bare
    # scalar when the if/else expression itself is assigned
    $members = @(
        if (![string]::IsNullOrWhiteSpace($membersInput)) {
            $membersInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { Test-EmailFormat $_ }
        }
    )

    # Return the configuration
    return @{
        DisplayName  = $groupName
        MailNickname = $alias
        PrimaryEmail = $primaryEmail
        Description  = $description
        Members      = $members
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
    Write-Host "  Members:       $(if (@($Config.Members).Count -gt 0) { @($Config.Members).Count } else { 'None' })" -ForegroundColor White
    Write-Host ""
}

function New-DistributionListFromConfig {
    param([hashtable]$Config)

    try {
        $groupParams = @{
            Name               = $Config.DisplayName
            DisplayName        = $Config.DisplayName
            Alias              = $Config.MailNickname
            PrimarySmtpAddress = $Config.PrimaryEmail
            Notes              = $Config.Description
        }

        if (@($Config.Members).Count -gt 0) {
            $groupParams.Members = @($Config.Members)
        }

        $newGroup = New-DistributionGroup @groupParams -ErrorAction Stop

        Write-Host "     Created successfully (Email: $($newGroup.PrimarySmtpAddress))" -ForegroundColor Green
        return @{ Success = $true; Group = $newGroup }
    }
    catch {
        # Exchange Online directory reads are eventually consistent: the
        # exists-check can miss a group created moments earlier, and the
        # duplicate New-DistributionGroup then fails (confirmed live with
        # 'Required field ExternalDirectoryObjectId was not returned from
        # Graph API'). Re-check with polling before declaring failure — if
        # the group is there, the requested end state already holds.
        $creationError = $_.Exception.Message
        for ($attempt = 1; $attempt -le 6; $attempt++) {
            $existing = Get-DistributionGroup -Identity $Config.PrimaryEmail -ErrorAction SilentlyContinue
            if ($existing) {
                Write-Host "     Already exists (detected after failed create — directory lag), skipping" -ForegroundColor Yellow
                return @{ Success = $true; Skipped = $true; Group = $existing }
            }
            if ($attempt -lt 6) { Start-Sleep -Seconds 10 }
        }
        Write-Host "     Failed: $creationError" -ForegroundColor Red
        return @{ Success = $false; Error = $creationError }
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
    Write-Host "  Creates Exchange Online distribution lists" -ForegroundColor Gray
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

            # @() wrap applied to the whole if/else, not nested inside a
            # branch — a single-element result from inside a branch still
            # collapses to a bare scalar when the if/else expression itself
            # is assigned, same as a function's return value would
            $members = @(if ($dlConfig.ContainsKey('Members')) { $dlConfig.Members })

            $config = @{
                DisplayName  = $dlConfig.DisplayName
                MailNickname = $mailNickname
                PrimaryEmail = $primaryEmail
                Description  = if ($dlConfig.ContainsKey('Description') -and $dlConfig.Description) { $dlConfig.Description } else { "Distribution list: $($dlConfig.DisplayName)" }
                Members      = $members
            }

            $result = New-DistributionListFromConfig -Config $config
            if ($result.Success) {
                # Skipped=$true means the create raced a group that already
                # existed (directory lag) — report it as skipped, not created.
                if ($result.ContainsKey('Skipped') -and $result.Skipped) {
                    $results.Skipped += $primaryEmail
                }
                else {
                    $results.Created += $primaryEmail
                }
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
                Write-Host "  Email: $($result.Group.PrimarySmtpAddress)" -ForegroundColor Green
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
