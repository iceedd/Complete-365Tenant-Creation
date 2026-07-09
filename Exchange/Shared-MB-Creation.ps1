#Requires -Version 7.0

<#
.SYNOPSIS
    Creates Exchange Online shared mailboxes
.DESCRIPTION
    Interactive wizard for creating shared mailboxes in Exchange Online.
    Includes preview and validation before creation.
.AUTHOR
    BITS
.VERSION
    2.0 - Standardized UX
#>

# ============================================================================
# CONFIGURATION
# ============================================================================

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

function Test-EmailAddress {
    param([string]$EmailAddress)

    $emailRegex = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return $EmailAddress -match $emailRegex
}

function Test-AcceptedDomain {
    param(
        [string]$EmailAddress,
        [array]$AcceptedDomains
    )

    if ($AcceptedDomains.Count -eq 0) {
        return $true  # Skip validation if we couldn't get domains
    }

    $domain = ($EmailAddress -split '@')[1]
    return $domain -in $AcceptedDomains
}

function Test-SharedMailboxExists {
    param([string]$EmailAddress)

    try {
        $existingMailbox = Get-Mailbox -Identity $EmailAddress -ErrorAction SilentlyContinue
        return $null -ne $existingMailbox
    }
    catch {
        return $false
    }
}

function New-AliasFromEmail {
    param([string]$EmailAddress)

    $localPart = ($EmailAddress -split '@')[0]
    # Remove invalid characters and limit length
    $alias = $localPart -replace '[^a-zA-Z0-9]', ''
    return $alias.Substring(0, [Math]::Min($alias.Length, 20))
}

# ============================================================================
# INPUT COLLECTION
# ============================================================================

function Get-SharedMailboxInput {
    param([array]$AcceptedDomains)

    Write-Host ""
    Write-Host "  Shared Mailbox Details:" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    if ($AcceptedDomains.Count -gt 0) {
        Write-Host "   Available domains: $($AcceptedDomains -join ', ')" -ForegroundColor Gray
    }
    Write-Host "   Type 'cancel' at any prompt to abort" -ForegroundColor Gray
    Write-Host ""

    # Get email address
    do {
        $emailAddress = Read-Host "   Email address (e.g., sales@company.com)"
        if ($emailAddress -eq "cancel") { return $null }
        if ([string]::IsNullOrWhiteSpace($emailAddress)) {
            Write-Host "   Email address cannot be empty" -ForegroundColor Red
            continue
        }
        if (!(Test-EmailAddress -EmailAddress $emailAddress)) {
            Write-Host "   Invalid email address format" -ForegroundColor Red
            continue
        }
        if (!(Test-AcceptedDomain -EmailAddress $emailAddress -AcceptedDomains $AcceptedDomains)) {
            Write-Host "   Domain is not accepted in your tenant" -ForegroundColor Red
            continue
        }
        if (Test-SharedMailboxExists -EmailAddress $emailAddress) {
            Write-Host "   A mailbox with this address already exists" -ForegroundColor Red
            continue
        }
        break
    } while ($true)

    # Get display name
    do {
        $displayName = Read-Host "   Display name (e.g., Sales Department)"
        if ($displayName -eq "cancel") { return $null }
        if ([string]::IsNullOrWhiteSpace($displayName)) {
            Write-Host "   Display name cannot be empty" -ForegroundColor Red
        }
        elseif ($displayName.Length -gt 256) {
            Write-Host "   Display name must be 256 characters or less" -ForegroundColor Red
        }
        else { break }
    } while ($true)

    # Get alias
    $suggestedAlias = New-AliasFromEmail -EmailAddress $emailAddress
    $alias = Read-Host "   Alias (press Enter for '$suggestedAlias')"
    if ([string]::IsNullOrWhiteSpace($alias)) { $alias = $suggestedAlias }

    # Optional description
    $description = Read-Host "   Description (optional)"

    return @{
        EmailAddress = $emailAddress.ToLower()
        DisplayName  = $displayName
        Alias        = $alias
        Description  = $description
    }
}

# ============================================================================
# PREVIEW
# ============================================================================

function Show-SharedMailboxPreview {
    param([hashtable]$Config)

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  PREVIEW: Shared Mailbox" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Email:        $($Config.EmailAddress)" -ForegroundColor White
    Write-Host "  Display Name: $($Config.DisplayName)" -ForegroundColor White
    Write-Host "  Alias:        $($Config.Alias)" -ForegroundColor White
    if (![string]::IsNullOrWhiteSpace($Config.Description)) {
        Write-Host "  Description:  $($Config.Description)" -ForegroundColor White
    }
    Write-Host ""
}

# ============================================================================
# MAILBOX CREATION
# ============================================================================

function New-SharedMailboxItem {
    param([hashtable]$Config)

    try {
        $mailboxParams = @{
            Shared             = $true
            Name               = $Config.DisplayName
            DisplayName        = $Config.DisplayName
            PrimarySmtpAddress = $Config.EmailAddress
            Alias              = $Config.Alias
        }

        $newMailbox = New-Mailbox @mailboxParams -ErrorAction Stop

        # Configure additional settings
        $configParams = @{
            Identity                          = $Config.EmailAddress
            MessageCopyForSentAsEnabled       = $true
            MessageCopyForSendOnBehalfEnabled = $true
        }

        Set-Mailbox @configParams -ErrorAction Stop

        Write-Host "     Created successfully (Email: $($Config.EmailAddress))" -ForegroundColor Green
        return @{ Success = $true; Mailbox = $newMailbox }
    }
    catch {
        Write-Host "     Failed: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-SharedMailboxCreation {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  SHARED MAILBOX CREATION" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Creates Exchange Online shared mailboxes with optimized settings" -ForegroundColor Gray
    Write-Host ""

    # Step 1: Prerequisites
    Write-Host "  STEP 1: Prerequisites" -ForegroundColor Yellow
    $prereqResult = Test-Prerequisites
    if (!$prereqResult.Success) {
        Write-Host "  Prerequisites not met. Please resolve issues and try again." -ForegroundColor Red
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    $totalCreated = 0
    $totalFailed  = 0

    do {
        # Step 2: Collect information
        Write-Host ""
        Write-Host "  STEP 2: Mailbox Details" -ForegroundColor Yellow
        $config = Get-SharedMailboxInput -AcceptedDomains $prereqResult.AcceptedDomains

        if ($null -eq $config) {
            Write-Host ""
            Write-Host "  Cancelled" -ForegroundColor Yellow
            break
        }

        # Step 3: Preview
        Write-Host ""
        Write-Host "  STEP 3: Preview" -ForegroundColor Yellow
        Show-SharedMailboxPreview -Config $config

        # Confirmation
        Write-Host "  [Y] Create this mailbox  [N] Cancel" -ForegroundColor Gray
        $confirm = Read-Host "  Create? (Y/N)"

        if ($confirm -like "Y*") {
            Write-Host ""
            Write-Host "  STEP 4: Creating Mailbox" -ForegroundColor Yellow
            Write-Host ("   " + "-" * 50) -ForegroundColor Gray
            Write-Host "   $($config.DisplayName)..." -ForegroundColor White

            $result = New-SharedMailboxItem -Config $config

            if ($result.Success) {
                $totalCreated++
            }
            else {
                $totalFailed++
            }
        }
        else {
            Write-Host "  Skipped" -ForegroundColor Yellow
        }

        Write-Host ""
        $another = Read-Host "  Create another shared mailbox? (y/N)"

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
        Write-Host "    1. Go to Exchange Admin Center > Recipients > Mailboxes" -ForegroundColor Gray
        Write-Host "    2. Find the shared mailbox and click 'Manage mailbox delegation'" -ForegroundColor Gray
        Write-Host "    3. Add users with Full Access and Send As permissions" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  Manage at: https://admin.exchange.microsoft.com" -ForegroundColor Cyan
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

    Start-SharedMailboxCreation
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
}
