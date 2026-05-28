#Requires -Version 7.0

<#
.SYNOPSIS
    Configures Exchange Online archive mailboxes and storage quotas
.DESCRIPTION
    Enables archive mailboxes and configures storage quotas for all user mailboxes.
    Warning: 40GB | Prohibit Send: 45GB | Prohibit Send/Receive: 49GB
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

$QuotaConfig = @{
    WarningQuota             = 40GB
    ProhibitSendQuota        = 45GB
    ProhibitSendReceiveQuota = 49GB
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

# ============================================================================
# PREREQUISITES
# ============================================================================

function Test-Prerequisites {
    Write-Host ""
    Write-Host "   PREREQUISITES CHECK" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    Write-Host "   Checking Exchange Online connection..." -ForegroundColor Gray
    $connection = Get-ConnectionInformation -ErrorAction SilentlyContinue
    if (!$connection -or $connection.State -ne "Connected") {
        Write-Host "   Not connected to Exchange Online" -ForegroundColor Red
        Write-Host "   Please connect using the main menu first" -ForegroundColor Yellow
        Write-Host ""
        return @{ Success = $false }
    }
    Write-Host "   Connected as: $($connection.UserPrincipalName)" -ForegroundColor Green

    Write-Host ""
    return @{ Success = $true }
}

# ============================================================================
# VALIDATION
# ============================================================================

function Test-QuotaValues {
    param($Config)

    if ($Config.WarningQuota -ge $Config.ProhibitSendQuota) {
        throw "Warning quota must be less than Prohibit Send quota"
    }
    if ($Config.ProhibitSendQuota -ge $Config.ProhibitSendReceiveQuota) {
        throw "Prohibit Send quota must be less than Prohibit Send/Receive quota"
    }
    Write-Host "   Quota configuration validated" -ForegroundColor Green
}

# ============================================================================
# MAILBOX CONFIGURATION
# ============================================================================

function Enable-MailboxArchiving {
    param([array]$Mailboxes)

    Write-Host ""
    Write-Host "   Enabling archive mailboxes..." -ForegroundColor Gray

    $stats = @{ AlreadyEnabled = 0; NewlyEnabled = 0; Failed = 0 }
    $errors = @()

    foreach ($mailbox in $Mailboxes) {
        try {
            $current = Get-Mailbox -Identity $mailbox.UserPrincipalName -ErrorAction Stop

            if ($current.ArchiveStatus -eq 'Active') {
                Write-Host "     Already enabled: $($mailbox.UserPrincipalName)" -ForegroundColor Green
                $stats.AlreadyEnabled++
            }
            else {
                Write-Host "     Enabling: $($mailbox.UserPrincipalName)..." -ForegroundColor Gray
                Enable-Mailbox -Identity $mailbox.UserPrincipalName -Archive -ErrorAction Stop

                Start-Sleep -Seconds 2
                $verify = Get-Mailbox -Identity $mailbox.UserPrincipalName -ErrorAction Stop

                if ($verify.ArchiveStatus -eq 'Active') {
                    Write-Host "     Enabled: $($mailbox.UserPrincipalName)" -ForegroundColor Green
                    $stats.NewlyEnabled++
                }
                else {
                    throw "Archive enablement verification failed"
                }
            }
        }
        catch {
            $msg = "Failed archive for $($mailbox.UserPrincipalName): $($_.Exception.Message)"
            Write-Host "     $msg" -ForegroundColor Red
            $errors += $msg
            $stats.Failed++
        }
    }

    Write-Host ""
    Write-Host "   Archive results:" -ForegroundColor Gray
    Write-Host "     Already enabled: $($stats.AlreadyEnabled)" -ForegroundColor Green
    Write-Host "     Newly enabled:   $($stats.NewlyEnabled)" -ForegroundColor Green
    Write-Host "     Failed:          $($stats.Failed)" -ForegroundColor $(if ($stats.Failed -gt 0) { "Red" } else { "Green" })

    return @{ Stats = $stats; Errors = $errors }
}

function Compare-MailboxQuota {
    param($ExchangeQuota, [long]$TargetBytes)
    if ($null -eq $ExchangeQuota -or $ExchangeQuota.IsUnlimited) { return $false }
    try { return $ExchangeQuota.ToBytes() -eq $TargetBytes }
    catch { return $false }
}

function Set-MailboxQuotas {
    param(
        [array]$Mailboxes,
        [hashtable]$QuotaConfiguration
    )

    Write-Host ""
    Write-Host "   Configuring mailbox quotas..." -ForegroundColor Gray

    $stats = @{ Updated = 0; AlreadyConfigured = 0; Failed = 0 }
    $errors = @()

    foreach ($mailbox in $Mailboxes) {
        try {
            $current = Get-Mailbox -Identity $mailbox.UserPrincipalName -ErrorAction Stop

            $needsUpdate = (
                -not (Compare-MailboxQuota $current.IssueWarningQuota             $QuotaConfiguration.WarningQuota) -or
                -not (Compare-MailboxQuota $current.ProhibitSendQuota             $QuotaConfiguration.ProhibitSendQuota) -or
                -not (Compare-MailboxQuota $current.ProhibitSendReceiveQuota      $QuotaConfiguration.ProhibitSendReceiveQuota)
            )

            if (!$needsUpdate) {
                Write-Host "     Already configured: $($mailbox.UserPrincipalName)" -ForegroundColor Green
                $stats.AlreadyConfigured++
            }
            else {
                Write-Host "     Updating: $($mailbox.UserPrincipalName)..." -ForegroundColor Gray

                Set-Mailbox -Identity $mailbox.UserPrincipalName `
                    -IssueWarningQuota $QuotaConfiguration.WarningQuota `
                    -ProhibitSendQuota $QuotaConfiguration.ProhibitSendQuota `
                    -ProhibitSendReceiveQuota $QuotaConfiguration.ProhibitSendReceiveQuota `
                    -UseDatabaseQuotaDefaults $false `
                    -ErrorAction Stop

                Write-Host "     Updated: $($mailbox.UserPrincipalName)" -ForegroundColor Green
                $stats.Updated++
            }
        }
        catch {
            $msg = "Failed quota for $($mailbox.UserPrincipalName): $($_.Exception.Message)"
            Write-Host "     $msg" -ForegroundColor Red
            $errors += $msg
            $stats.Failed++
        }
    }

    Write-Host ""
    Write-Host "   Quota results:" -ForegroundColor Gray
    Write-Host "     Updated:          $($stats.Updated)" -ForegroundColor Green
    Write-Host "     Already correct:  $($stats.AlreadyConfigured)" -ForegroundColor Green
    Write-Host "     Failed:           $($stats.Failed)" -ForegroundColor $(if ($stats.Failed -gt 0) { "Red" } else { "Green" })

    return @{ Stats = $stats; Errors = $errors }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-ArchivePolicies {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  ARCHIVE POLICIES & MAILBOX QUOTAS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Enables archive mailboxes and configures storage quotas for all users" -ForegroundColor Gray
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

    # Step 2: Configuration Preview
    Write-Host ""
    Write-Host "  STEP 2: Configuration Preview" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    # Validate quotas
    try {
        Test-QuotaValues -Config $QuotaConfig
    }
    catch {
        Write-Host "  Invalid quota configuration: $_" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    # Get mailbox count
    Write-Host "   Retrieving mailboxes..." -ForegroundColor Gray
    $allMailboxes = Get-Mailbox -RecipientTypeDetails UserMailbox -ResultSize Unlimited -ErrorAction SilentlyContinue

    if (!$allMailboxes -or $allMailboxes.Count -eq 0) {
        Write-Host "   No user mailboxes found in the tenant" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    Write-Host ""
    Write-Host "  The following will be configured for ALL $($allMailboxes.Count) user mailboxes:" -ForegroundColor White
    Write-Host ""
    Write-Host "    Archive mailbox:          Enabled" -ForegroundColor Gray
    Write-Host "    Warning quota:            $($QuotaConfig.WarningQuota / 1GB) GB" -ForegroundColor Gray
    Write-Host "    Prohibit send quota:      $($QuotaConfig.ProhibitSendQuota / 1GB) GB" -ForegroundColor Gray
    Write-Host "    Prohibit send/receive:    $($QuotaConfig.ProhibitSendReceiveQuota / 1GB) GB" -ForegroundColor Gray
    Write-Host ""

    # Confirmation
    Write-Host "  [Y] Proceed with configuration  [N] Cancel" -ForegroundColor Gray
    $confirm = Read-Host "  Apply settings? (Y/N)"

    if ($confirm -notlike "Y*") {
        Write-Host ""
        Write-Host "  Cancelled by user" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    # Step 3: Apply archive settings
    Write-Host ""
    Write-Host "  STEP 3: Enabling Archive Mailboxes" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    $archiveResult = Enable-MailboxArchiving -Mailboxes $allMailboxes

    # Step 4: Apply quotas
    Write-Host ""
    Write-Host "  STEP 4: Configuring Storage Quotas" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    $quotaResult = Set-MailboxQuotas -Mailboxes $allMailboxes -QuotaConfiguration $QuotaConfig

    # Summary
    $totalErrors = $archiveResult.Errors + $quotaResult.Errors

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Mailboxes processed: $($allMailboxes.Count)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Archive:" -ForegroundColor Yellow
    Write-Host "    Already enabled: $($archiveResult.Stats.AlreadyEnabled)" -ForegroundColor Green
    Write-Host "    Newly enabled:   $($archiveResult.Stats.NewlyEnabled)" -ForegroundColor Green
    Write-Host "    Failed:          $($archiveResult.Stats.Failed)" -ForegroundColor $(if ($archiveResult.Stats.Failed -gt 0) { "Red" } else { "Green" })
    Write-Host ""
    Write-Host "  Quotas:" -ForegroundColor Yellow
    Write-Host "    Updated:         $($quotaResult.Stats.Updated)" -ForegroundColor Green
    Write-Host "    Already correct: $($quotaResult.Stats.AlreadyConfigured)" -ForegroundColor Green
    Write-Host "    Failed:          $($quotaResult.Stats.Failed)" -ForegroundColor $(if ($quotaResult.Stats.Failed -gt 0) { "Red" } else { "Green" })

    if ($totalErrors.Count -gt 0) {
        Write-Host ""
        Write-Host "  Errors:" -ForegroundColor Red
        foreach ($err in $totalErrors) {
            Write-Host "    - $err" -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "  Next Steps:" -ForegroundColor Yellow
    Write-Host "    1. Monitor mailbox usage with Get-MailboxStatistics" -ForegroundColor Gray
    Write-Host "    2. Consider auto-expanding archives for high-usage mailboxes" -ForegroundColor Gray
    Write-Host "    3. Test archive accessibility in Outlook clients" -ForegroundColor Gray
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

    Start-ArchivePolicies
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
}
