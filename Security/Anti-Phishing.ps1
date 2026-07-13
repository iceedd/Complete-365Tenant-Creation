#Requires -Version 7.0

<#
.SYNOPSIS
    Configures Microsoft Defender anti-phishing policies
.DESCRIPTION
    Manages anti-phishing protection, impersonation protection, and mailbox intelligence
.AUTHOR
    BITS
.VERSION
    2.1 - Non-interactive mode (-NonInteractive/-ConfigFile) for unattended
          E2E testing.
.PARAMETER NonInteractive
    Run unattended: skip all "press any key" pauses. Used by CI E2E tests.
.PARAMETER ConfigFile
    Optional JSON file overriding run behaviour. Supported keys:
      NamePrefix (string) prefixed to the policy and rule name, e.g. "E2E-"
                 — lets E2E tests create/verify/delete a throwaway prefixed
                 policy instead of the real tenant's default policy.
.PARAMETER ResultPath
    Optional path to write a JSON results summary, so a CI runner can assert
    on the outcome.
#>

param(
    [switch] $NonInteractive,
    [string] $ConfigFile,
    [string] $ResultPath
)

$script:NonInteractive = [bool]$NonInteractive

$script:RunConfig = @{
    NamePrefix = ''
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

# Create Anti-Phishing Policy
function New-AntiPhishingConfiguration {
    Write-Host ""
    Write-Host "   Configuring Anti-Phishing Policies..." -ForegroundColor Cyan

    $policyName = "$($script:RunConfig.NamePrefix)Default Anti-Phishing Policy"
    $ruleName = "$($script:RunConfig.NamePrefix)Default Anti-Phishing Rule"
    $policyAction = 'Updated'
    $ruleAction = 'Skipped'

    try {
        # Check if policy already exists
        $existingPolicy = Get-AntiPhishPolicy -Identity $policyName -ErrorAction SilentlyContinue

        if ($existingPolicy) {
            Write-Host "   Anti-phishing policy '$policyName' already exists" -ForegroundColor Yellow
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
                -AuthenticationFailAction MoveToJmf

            Write-Host "   Updated anti-phishing policy" -ForegroundColor Green
        }
        else {
            Write-Host "   Creating new anti-phishing policy..." -ForegroundColor Cyan
            $policyAction = 'Created'

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
                -AuthenticationFailAction MoveToJmf

            Write-Host "   Created anti-phishing policy" -ForegroundColor Green
        }

        # Check if rule already exists
        $existingRule = Get-AntiPhishRule -Identity $ruleName -ErrorAction SilentlyContinue

        if ($existingRule) {
            Write-Host "   Anti-phishing rule already exists, skipping rule creation" -ForegroundColor Yellow
        }
        else {
            Write-Host "   Creating anti-phishing rule to apply policy..." -ForegroundColor Cyan
            $ruleAction = 'Created'

            New-AntiPhishRule -Name $ruleName `
                -AntiPhishPolicy $policyName `
                -RecipientDomainIs (Get-AcceptedDomain).Name `
                -Enabled $true `
                -Priority 0

            Write-Host "   Created anti-phishing rule (applied to all domains)" -ForegroundColor Green
        }

        # Display configuration summary
        Write-Host ""
        Write-Host "   Anti-Phishing Configuration Summary:" -ForegroundColor Cyan
        Write-Host "   Policy Name: $policyName" -ForegroundColor White
        Write-Host "   Spoof Protection: Enabled (moves to Junk Mail)" -ForegroundColor White
        Write-Host "   Mailbox Intelligence: Enabled (learns normal behavior)" -ForegroundColor White
        Write-Host "   Safety Tips: Enabled (warns users of suspicious emails)" -ForegroundColor White
        Write-Host "   Action: Move suspicious emails to Junk Mail folder" -ForegroundColor White
        Write-Host "   Applied to: All accepted domains" -ForegroundColor White

        return @{
            Success      = $true
            PolicyName   = $policyName
            RuleName     = $ruleName
            PolicyAction = $policyAction
            RuleAction   = $ruleAction
        }
    }
    catch {
        Write-Host "     Failed to configure anti-phishing policy: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; PolicyName = $policyName; RuleName = $ruleName; Error = $_.Exception.Message }
    }
}

function Write-Result-File {
    param([hashtable]$Result)
    if (!$ResultPath) { return }
    $Result | ConvertTo-Json -Depth 5 | Set-Content -Path $ResultPath -Encoding UTF8
}

function Start-AntiPhishing {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  ANTI-PHISHING POLICIES" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Configures Defender anti-phishing with mailbox intelligence" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  STEP 1: Prerequisites" -ForegroundColor Yellow
    $prereqResult = Test-Prerequisites
    if (!$prereqResult.Success) {
        Write-Host "  Prerequisites not met. Please resolve issues and try again." -ForegroundColor Red
        Write-Host ""
        Write-Result-File -Result @{ Success = $false; Error = "Prerequisites not met" }
        if ($script:NonInteractive) { return }
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    Write-Host ""
    Write-Host "  STEP 2: Configuring Policies" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    $result = New-AntiPhishingConfiguration

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""

    if ($result.Success) {
        Write-Host "  Status: Configured successfully" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Next Steps:" -ForegroundColor Yellow
        Write-Host "    1. Users will receive warnings on suspicious emails" -ForegroundColor Gray
        Write-Host "    2. Suspected phishing emails moved to Junk Mail (not blocked)" -ForegroundColor Gray
        Write-Host "    3. Review policies in Microsoft Defender portal" -ForegroundColor Gray
    }
    else {
        Write-Host "  Status: Configuration failed - check errors above" -ForegroundColor Red
    }

    Write-Result-File -Result $result

    if ($script:NonInteractive) { return }
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
        Write-Result-File -Result @{ Success = $false; Error = "Failed to initialize required modules" }
        if ($script:NonInteractive) { exit 1 } else { return }
    }

    Start-AntiPhishing
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Result-File -Result @{ Success = $false; Error = $_.Exception.Message }
    if ($script:NonInteractive) { exit 1 }
}
