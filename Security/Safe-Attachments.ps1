#Requires -Version 7.0

<#
.SYNOPSIS
    Configures Microsoft Defender Safe Attachments and Safe Links policies
.DESCRIPTION
    Manages email security with safe attachments scanning and URL protection
.AUTHOR
    CB & Claude Partnership
.VERSION
    1.0
#>

# Required Modules
$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Security',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'ExchangeOnlineManagement'
)

# Auto-install and import required modules
function Initialize-Modules {
    Write-Host "🔧 Checking required modules..." -ForegroundColor Yellow
    
    try {
        foreach ($Module in $RequiredModules) {
            try {
                if (!(Get-Module -ListAvailable -Name $Module)) {
                    Write-Host "Installing $Module..." -ForegroundColor Yellow
                    Install-Module $Module -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
                }
                if (!(Get-Module -Name $Module)) {
                    Write-Host "Importing $Module..." -ForegroundColor Yellow
                    Import-Module $Module -Force -ErrorAction Stop
                }
                Write-Host "✅ $Module ready!" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to install/import ${Module}: $($_.Exception.Message)"
                return $false
            }
        }
        Write-Host "✅ All modules ready!" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Module initialization failed: $($_.Exception.Message)"
        return $false
    }
}

# Connect to Exchange Online
function Connect-ExchangeOnlineService {
    Write-Host "🔌 Connecting to Exchange Online..." -ForegroundColor Cyan

    try {
        # Check if already connected
        $existingConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue

        if ($existingConnection) {
            Write-Host "✅ Already connected to Exchange Online" -ForegroundColor Green
            return $true
        }

        # Connect to Exchange Online
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Host "✅ Successfully connected to Exchange Online" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to connect to Exchange Online: $($_.Exception.Message)"
        return $false
    }
}

# Create Safe Attachments Policy
function New-SafeAttachmentsConfiguration {
    Write-Host "`n📎 Configuring Safe Attachments Policies..." -ForegroundColor Cyan

    $safeAttachPolicyName = "Default Safe Attachments Policy"
    $safeAttachRuleName = "Default Safe Attachments Rule"

    try {
        # Check if Safe Attachments policy already exists
        $existingPolicy = Get-SafeAttachmentPolicy -Identity $safeAttachPolicyName -ErrorAction SilentlyContinue

        if ($existingPolicy) {
            Write-Host "⚠️ Safe Attachments policy '$safeAttachPolicyName' already exists" -ForegroundColor Yellow
            Write-Host "   Updating existing policy..." -ForegroundColor Cyan

            Set-SafeAttachmentPolicy -Identity $safeAttachPolicyName `
                -Enable $true `
                -Action DynamicDelivery `
                -Redirect $false `
                -ActionOnError $true

            Write-Host "✅ Updated Safe Attachments policy" -ForegroundColor Green
        }
        else {
            Write-Host "   Creating new Safe Attachments policy..." -ForegroundColor Cyan

            New-SafeAttachmentPolicy -Name $safeAttachPolicyName `
                -Enable $true `
                -Action DynamicDelivery `
                -Redirect $false `
                -ActionOnError $true

            Write-Host "✅ Created Safe Attachments policy" -ForegroundColor Green
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

            Write-Host "✅ Created Safe Attachments rule (applied to all domains)" -ForegroundColor Green
        }

        return $true
    }
    catch {
        Write-Error "Failed to configure Safe Attachments policy: $($_.Exception.Message)"
        return $false
    }
}

# Create Safe Links Policy
function New-SafeLinksConfiguration {
    Write-Host "`n🔗 Configuring Safe Links Policies..." -ForegroundColor Cyan

    $safeLinksPolicyName = "Default Safe Links Policy"
    $safeLinksRuleName = "Default Safe Links Rule"

    try {
        # Check if Safe Links policy already exists
        $existingPolicy = Get-SafeLinksPolicy -Identity $safeLinksPolicyName -ErrorAction SilentlyContinue

        if ($existingPolicy) {
            Write-Host "⚠️ Safe Links policy '$safeLinksPolicyName' already exists" -ForegroundColor Yellow
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

            Write-Host "✅ Updated Safe Links policy" -ForegroundColor Green
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

            Write-Host "✅ Created Safe Links policy" -ForegroundColor Green
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

            Write-Host "✅ Created Safe Links rule (applied to all domains)" -ForegroundColor Green
        }

        return $true
    }
    catch {
        Write-Error "Failed to configure Safe Links policy: $($_.Exception.Message)"
        return $false
    }
}

# Main execution
function Start-SafeAttachments {
    Write-Host "🚀 Starting Safe Attachments & Safe Links Configuration..." -ForegroundColor Cyan
    Write-Host "   Settings: User-friendly (Dynamic Delivery for attachments)" -ForegroundColor Gray

    if (!(Initialize-Modules)) {
        Write-Error "Failed to initialize required modules. Exiting."
        return
    }

    if (!(Connect-ExchangeOnlineService)) {
        Write-Error "Failed to connect to Exchange Online. Exiting."
        return
    }

    $safeAttachmentsSuccess = New-SafeAttachmentsConfiguration
    $safeLinksSuccess = New-SafeLinksConfiguration

    if ($safeAttachmentsSuccess -and $safeLinksSuccess) {
        Write-Host "`n✅ Safe Attachments & Safe Links configuration completed successfully!" -ForegroundColor Green

        Write-Host "`n📋 Configuration Summary:" -ForegroundColor Cyan
        Write-Host "   Safe Attachments:" -ForegroundColor White
        Write-Host "     - Action: Dynamic Delivery (users can read email body while attachments scan)" -ForegroundColor White
        Write-Host "     - Scanning: Enabled for all attachments" -ForegroundColor White
        Write-Host "     - Delay: 1-2 minutes for emails with attachments" -ForegroundColor White
        Write-Host "`n   Safe Links:" -ForegroundColor White
        Write-Host "     - Protection: Email, Teams, and Office apps" -ForegroundColor White
        Write-Host "     - Click tracking: Enabled" -ForegroundColor White
        Write-Host "     - Real-time URL scanning: Enabled" -ForegroundColor White
        Write-Host "     - Applied to: All accepted domains (including internal senders)" -ForegroundColor White

        Write-Host "`n💡 Users may notice:" -ForegroundColor Cyan
        Write-Host "   - Slight delay for emails with attachments (1-2 min)" -ForegroundColor Gray
        Write-Host "   - URLs in emails will look different (rewritten for protection)" -ForegroundColor Gray
        Write-Host "   - Malicious links will be blocked when clicked" -ForegroundColor Gray
    }
    else {
        Write-Error "Safe Attachments/Links configuration failed."
    }

    Write-Host "`n🔌 Disconnecting from Exchange Online..." -ForegroundColor Cyan
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
}

# Execute the script
Start-SafeAttachments