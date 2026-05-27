#Requires -Version 7.0

<#
.SYNOPSIS
    Configures Microsoft Defender Safe Attachments and Safe Links policies
.DESCRIPTION
    Manages email security with safe attachments scanning and URL protection
.AUTHOR
    BITS
.VERSION
    2.0
#>

# Required Modules
$RequiredModules = @(
    'ExchangeOnlineManagement'
)

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

# Create Safe Attachments Policy
function New-SafeAttachmentsConfiguration {
    Write-Host ""
    Write-Host "   Configuring Safe Attachments Policies..." -ForegroundColor Cyan

    $safeAttachPolicyName = "Default Safe Attachments Policy"
    $safeAttachRuleName = "Default Safe Attachments Rule"

    try {
        # Check if Safe Attachments policy already exists
        $existingPolicy = Get-SafeAttachmentPolicy -Identity $safeAttachPolicyName -ErrorAction SilentlyContinue

        if ($existingPolicy) {
            Write-Host "   Safe Attachments policy '$safeAttachPolicyName' already exists" -ForegroundColor Yellow
            Write-Host "   Updating existing policy..." -ForegroundColor Cyan

            Set-SafeAttachmentPolicy -Identity $safeAttachPolicyName `
                -Enable $true `
                -Action DynamicDelivery `
                -Redirect $false `
                -ActionOnError $true

            Write-Host "   Updated Safe Attachments policy" -ForegroundColor Green
        }
        else {
            Write-Host "   Creating new Safe Attachments policy..." -ForegroundColor Cyan

            New-SafeAttachmentPolicy -Name $safeAttachPolicyName `
                -Enable $true `
                -Action DynamicDelivery `
                -Redirect $false `
                -ActionOnError $true

            Write-Host "   Created Safe Attachments policy" -ForegroundColor Green
        }

        # Check if Safe Attachments rule already exists
        $existingRule = Get-SafeAttachmentRule -Identity $safeAttachRuleName -ErrorAction SilentlyContinue

        if ($existingRule) {
            Write-Host "   Safe Attachments rule already exists, skipping rule creation" -ForegroundColor Yellow
        }
        else {
            Write-Host "   Creating Safe Attachments rule to apply policy..." -ForegroundColor Cyan

            New-SafeAttachmentRule -Name $safeAttachRuleName `
                -SafeAttachmentPolicy $safeAttachPolicyName `
                -RecipientDomainIs (Get-AcceptedDomain).Name `
                -Enabled $true `
                -Priority 0

            Write-Host "   Created Safe Attachments rule (applied to all domains)" -ForegroundColor Green
        }

        return $true
    }
    catch {
        Write-Host "     Failed to configure Safe Attachments policy: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Create Safe Links Policy
function New-SafeLinksConfiguration {
    Write-Host ""
    Write-Host "   Configuring Safe Links Policies..." -ForegroundColor Cyan

    $safeLinksPolicyName = "Default Safe Links Policy"
    $safeLinksRuleName = "Default Safe Links Rule"

    try {
        # Check if Safe Links policy already exists
        $existingPolicy = Get-SafeLinksPolicy -Identity $safeLinksPolicyName -ErrorAction SilentlyContinue

        if ($existingPolicy) {
            Write-Host "   Safe Links policy '$safeLinksPolicyName' already exists" -ForegroundColor Yellow
            Write-Host "   Updating existing policy..." -ForegroundColor Cyan

            Set-SafeLinksPolicy -Identity $safeLinksPolicyName `
                -IsEnabled $true `
                -EnableSafeLinksForEmail $true `
                -EnableSafeLinksForTeams $true `
                -EnableSafeLinksForOffice $true `
                -TrackClicks $true `
                -AllowClickThrough $false `
                -ScanUrls $true `
                -EnableForInternalSenders $true `
                -DeliverMessageAfterScan $true `
                -DisableUrlRewrite $false `
                -EnableOrganizationBranding $false

            Write-Host "   Updated Safe Links policy" -ForegroundColor Green
        }
        else {
            Write-Host "   Creating new Safe Links policy..." -ForegroundColor Cyan

            New-SafeLinksPolicy -Name $safeLinksPolicyName `
                -IsEnabled $true `
                -EnableSafeLinksForEmail $true `
                -EnableSafeLinksForTeams $true `
                -EnableSafeLinksForOffice $true `
                -TrackClicks $true `
                -AllowClickThrough $false `
                -ScanUrls $true `
                -EnableForInternalSenders $true `
                -DeliverMessageAfterScan $true `
                -DisableUrlRewrite $false `
                -EnableOrganizationBranding $false

            Write-Host "   Created Safe Links policy" -ForegroundColor Green
        }

        # Check if Safe Links rule already exists
        $existingRule = Get-SafeLinksRule -Identity $safeLinksRuleName -ErrorAction SilentlyContinue

        if ($existingRule) {
            Write-Host "   Safe Links rule already exists, skipping rule creation" -ForegroundColor Yellow
        }
        else {
            Write-Host "   Creating Safe Links rule to apply policy..." -ForegroundColor Cyan

            New-SafeLinksRule -Name $safeLinksRuleName `
                -SafeLinksPolicy $safeLinksPolicyName `
                -RecipientDomainIs (Get-AcceptedDomain).Name `
                -Enabled $true `
                -Priority 0

            Write-Host "   Created Safe Links rule (applied to all domains)" -ForegroundColor Green
        }

        return $true
    }
    catch {
        Write-Host "     Failed to configure Safe Links policy: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Start-SafeAttachments {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  SAFE ATTACHMENTS & SAFE LINKS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Configures email security with attachment scanning and URL protection" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  STEP 1: Prerequisites" -ForegroundColor Yellow
    $prereqResult = Test-Prerequisites
    if (!$prereqResult.Success) {
        Write-Host "  Prerequisites not met. Please resolve issues and try again." -ForegroundColor Red
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    Write-Host ""
    Write-Host "  STEP 2: Configuring Policies" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray
    Write-Host "   Safe Attachments Policy..." -ForegroundColor White

    $safeAttachmentsResult = New-SafeAttachmentsConfiguration

    Write-Host ""
    Write-Host "   Safe Links Policy..." -ForegroundColor White
    $safeLinksResult = New-SafeLinksConfiguration

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  Safe Attachments: $(if ($safeAttachmentsResult) { 'Configured' } else { 'Failed' })" -ForegroundColor $(if ($safeAttachmentsResult) { "Green" } else { "Red" })
    Write-Host "  Safe Links:       $(if ($safeLinksResult) { 'Configured' } else { 'Failed' })" -ForegroundColor $(if ($safeLinksResult) { "Green" } else { "Red" })

    if ($safeAttachmentsResult -and $safeLinksResult) {
        Write-Host ""
        Write-Host "  Next Steps:" -ForegroundColor Yellow
        Write-Host "    - Safe Attachments: Dynamic Delivery (1-2 min delay for emails with attachments)" -ForegroundColor Gray
        Write-Host "    - Safe Links: Protects Email, Teams, and Office apps" -ForegroundColor Gray
        Write-Host "    - Click tracking enabled, malicious links blocked when clicked" -ForegroundColor Gray
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

    Start-SafeAttachments
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
}
