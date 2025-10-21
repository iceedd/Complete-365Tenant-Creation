#Requires -Version 7.0

<#
.SYNOPSIS
    Configures Microsoft Defender anti-phishing policies
.DESCRIPTION
    Manages anti-phishing protection, impersonation protection, and mailbox intelligence
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

# Create Anti-Phishing Policy
function New-AntiPhishingConfiguration {
    Write-Host "`n📧 Configuring Anti-Phishing Policies..." -ForegroundColor Cyan

    $policyName = "Default Anti-Phishing Policy"
    $ruleName = "Default Anti-Phishing Rule"

    try {
        # Check if policy already exists
        $existingPolicy = Get-AntiPhishPolicy -Identity $policyName -ErrorAction SilentlyContinue

        if ($existingPolicy) {
            Write-Host "⚠️ Anti-phishing policy '$policyName' already exists" -ForegroundColor Yellow
            Write-Host "   Updating existing policy..." -ForegroundColor Cyan

            Set-AntiPhishPolicy -Identity $policyName `
                -Enabled $true `
                -EnableSpoofIntelligence $true `
                -EnableMailboxIntelligence $true `
                -EnableMailboxIntelligenceProtection $true `
                -MailboxIntelligenceProtectionAction MoveToJmf `
                -EnableSimilarUsersSafetyTips $true `
                -EnableSimilarDomainsSafetyTips $true `
                -EnableUnusualCharactersSafetyTips $true `
                -EnableOrganizationDomainsProtection $false `
                -EnableTargetedUserProtection $false `
                -PhishThresholdLevel 2 `
                -TargetedUserProtectionAction MoveToJmf `
                -TargetedDomainProtectionAction MoveToJmf `
                -AuthenticationFailAction MoveToJmf `
                -SpoofIntelligenceAction MoveToJmf

            Write-Host "✅ Updated anti-phishing policy" -ForegroundColor Green
        }
        else {
            Write-Host "   Creating new anti-phishing policy..." -ForegroundColor Cyan

            New-AntiPhishPolicy -Name $policyName `
                -Enabled $true `
                -EnableSpoofIntelligence $true `
                -EnableMailboxIntelligence $true `
                -EnableMailboxIntelligenceProtection $true `
                -MailboxIntelligenceProtectionAction MoveToJmf `
                -EnableSimilarUsersSafetyTips $true `
                -EnableSimilarDomainsSafetyTips $true `
                -EnableUnusualCharactersSafetyTips $true `
                -EnableOrganizationDomainsProtection $false `
                -EnableTargetedUserProtection $false `
                -PhishThresholdLevel 2 `
                -TargetedUserProtectionAction MoveToJmf `
                -TargetedDomainProtectionAction MoveToJmf `
                -AuthenticationFailAction MoveToJmf `
                -SpoofIntelligenceAction MoveToJmf

            Write-Host "✅ Created anti-phishing policy" -ForegroundColor Green
        }

        # Check if rule already exists
        $existingRule = Get-AntiPhishRule -Identity $ruleName -ErrorAction SilentlyContinue

        if ($existingRule) {
            Write-Host "   Anti-phishing rule already exists, skipping rule creation" -ForegroundColor Yellow
        }
        else {
            Write-Host "   Creating anti-phishing rule to apply policy..." -ForegroundColor Cyan

            New-AntiPhishRule -Name $ruleName `
                -AntiPhishPolicy $policyName `
                -RecipientDomainIs (Get-AcceptedDomain).Name `
                -Enabled $true `
                -Priority 0

            Write-Host "✅ Created anti-phishing rule (applied to all domains)" -ForegroundColor Green
        }

        # Display configuration summary
        Write-Host "`n📋 Anti-Phishing Configuration Summary:" -ForegroundColor Cyan
        Write-Host "   Policy Name: $policyName" -ForegroundColor White
        Write-Host "   Spoof Protection: Enabled (moves to Junk Mail)" -ForegroundColor White
        Write-Host "   Mailbox Intelligence: Enabled (learns normal behavior)" -ForegroundColor White
        Write-Host "   Safety Tips: Enabled (warns users of suspicious emails)" -ForegroundColor White
        Write-Host "   Action: Move suspicious emails to Junk Mail folder" -ForegroundColor White
        Write-Host "   Applied to: All accepted domains" -ForegroundColor White

        return $true
    }
    catch {
        Write-Error "Failed to configure anti-phishing policy: $($_.Exception.Message)"
        return $false
    }
}

# Main execution
function Start-AntiPhishing {
    Write-Host "🚀 Starting Anti-Phishing Configuration..." -ForegroundColor Cyan
    Write-Host "   Settings: User-friendly (warnings over blocking)" -ForegroundColor Gray

    if (!(Initialize-Modules)) {
        Write-Error "Failed to initialize required modules. Exiting."
        return
    }

    if (!(Connect-ExchangeOnlineService)) {
        Write-Error "Failed to connect to Exchange Online. Exiting."
        return
    }

    if (New-AntiPhishingConfiguration) {
        Write-Host "`n✅ Anti-phishing configuration completed successfully!" -ForegroundColor Green
        Write-Host "💡 Users will now receive warnings on suspicious emails" -ForegroundColor Cyan
        Write-Host "💡 Suspected phishing emails will be moved to Junk Mail (not blocked)" -ForegroundColor Cyan
    }
    else {
        Write-Error "Anti-phishing configuration failed."
    }

    Write-Host "`n🔌 Disconnecting from Exchange Online..." -ForegroundColor Cyan
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
}

# Execute the script
Start-AntiPhishing