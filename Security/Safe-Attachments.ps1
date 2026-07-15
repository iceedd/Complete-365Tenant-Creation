#Requires -Version 7.0

<#
.SYNOPSIS
    Configures Microsoft Defender Safe Attachments and Safe Links policies
.DESCRIPTION
    Manages email security with safe attachments scanning and URL protection
.AUTHOR
    BITS
.VERSION
    2.1 - Non-interactive mode (-NonInteractive/-ConfigFile) for unattended
          E2E testing.
.PARAMETER NonInteractive
    Run unattended: skip all "press any key" pauses. Used by CI E2E tests.
.PARAMETER ConfigFile
    Optional JSON file overriding run behaviour. Supported keys:
      NamePrefix (string) prefixed to all policy/rule names, e.g. "E2E-" —
                 lets E2E tests create/verify/delete throwaway prefixed
                 policies instead of the real tenant's default policies.
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

    # New tenants (and some existing ones) reject New-SafeAttachmentPolicy /
    # New-SafeLinksPolicy with "you first need to run the command:
    # Enable-OrganizationCustomization" until that one-time, tenant-wide
    # command has been run (confirmed live in Anti-Phishing.ps1's E2E test).
    # Running it twice throws, so gate on Get-OrganizationConfig's
    # IsDehydrated flag.
    Write-Host "   Checking organization customization..." -ForegroundColor Gray
    try {
        $orgConfig = Get-OrganizationConfig -ErrorAction Stop
        if ($orgConfig.IsDehydrated) {
            Write-Host "   Enabling organization customization (one-time, tenant-wide)..." -ForegroundColor Yellow
            Enable-OrganizationCustomization -ErrorAction Stop

            # Provisioning isn't instantaneous — confirmed live: IsDehydrated
            # can still read $true for well over a minute afterwards. Poll
            # rather than trust a fixed sleep.
            $maxAttempts = 12
            for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
                Start-Sleep -Seconds 10
                if (!(Get-OrganizationConfig -ErrorAction Stop).IsDehydrated) { break }
                Write-Host "     Still provisioning, waiting ($attempt/$maxAttempts)..." -ForegroundColor Gray
            }
            Write-Host "   Organization customization enabled" -ForegroundColor Green
        }
        else {
            Write-Host "   Organization customization already enabled" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "   Warning: could not verify/enable organization customization: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Write-Host ""
    return @{ Success = $true }
}

# Create Safe Attachments Policy
function New-SafeAttachmentsConfiguration {
    Write-Host ""
    Write-Host "   Configuring Safe Attachments Policies..." -ForegroundColor Cyan

    $safeAttachPolicyName = "$($script:RunConfig.NamePrefix)Default Safe Attachments Policy"
    $safeAttachRuleName = "$($script:RunConfig.NamePrefix)Default Safe Attachments Rule"
    $policyAction = 'Updated'
    $ruleAction = 'Skipped'

    try {
        # Check if Safe Attachments policy already exists
        $existingPolicy = Get-SafeAttachmentPolicy -Identity $safeAttachPolicyName -ErrorAction SilentlyContinue

        if ($existingPolicy) {
            Write-Host "   Safe Attachments policy '$safeAttachPolicyName' already exists" -ForegroundColor Yellow
            Write-Host "   Updating existing policy..." -ForegroundColor Cyan

            # ActionOnError isn't a real parameter of Set-SafeAttachmentPolicy
            # (confirmed live: "A parameter cannot be found that matches
            # parameter name 'ActionOnError'" — it doesn't exist on this
            # cmdlet at all, per Microsoft Learn's documented parameter set).
            # $null = : Set-* can emit the updated object, corrupting this
            # function's hashtable return under strict mode (confirmed live:
            # the identical crash hit the Set-SafeLinksPolicy update path).
            $null = Set-SafeAttachmentPolicy -Identity $safeAttachPolicyName `
                -Enable $true `
                -Action DynamicDelivery `
                -Redirect $false

            Write-Host "   Updated Safe Attachments policy" -ForegroundColor Green
        }
        else {
            Write-Host "   Creating new Safe Attachments policy..." -ForegroundColor Cyan
            $policyAction = 'Created'

            # $null = suppresses the created-object output — otherwise it
            # leaks into this function's own return value (confirmed live in
            # Anti-Phishing.ps1's E2E test, same bug class).
            $null = New-SafeAttachmentPolicy -Name $safeAttachPolicyName `
                -Enable $true `
                -Action DynamicDelivery `
                -Redirect $false

            Write-Host "   Created Safe Attachments policy" -ForegroundColor Green
        }

        # Check if Safe Attachments rule already exists
        $existingRule = Get-SafeAttachmentRule -Identity $safeAttachRuleName -ErrorAction SilentlyContinue

        if ($existingRule) {
            Write-Host "   Safe Attachments rule already exists, skipping rule creation" -ForegroundColor Yellow
        }
        else {
            Write-Host "   Creating Safe Attachments rule to apply policy..." -ForegroundColor Cyan
            $ruleAction = 'Created'

            # Exchange Online directory-replication lag, two forms confirmed
            # live in Anti-Phishing.ps1's E2E test: (1) a policy just created
            # above can briefly be unresolvable by name to New-*Rule
            # -...Policy ("Policy ... not found") — retry handles this.
            # (2) Get-SafeAttachmentRule above can return nothing for a rule
            # that was in fact already created moments before, so New-*Rule
            # then fails with "already has rule ... associated with it" —
            # treat that specific conflict as success, since the end state
            # (the rule exists) is exactly what was requested.
            $acceptedDomains = (Get-AcceptedDomain).Name
            $maxAttempts = 6
            for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
                try {
                    $null = New-SafeAttachmentRule -Name $safeAttachRuleName `
                        -SafeAttachmentPolicy $safeAttachPolicyName `
                        -RecipientDomainIs $acceptedDomains `
                        -Enabled $true `
                        -Priority 0 `
                        -ErrorAction Stop
                    break
                }
                catch {
                    if ($_.Exception.Message -match 'already has rule .* associated with it') {
                        Write-Host "   Safe Attachments rule already exists (detected on create), skipping" -ForegroundColor Yellow
                        $ruleAction = 'Skipped'
                        break
                    }
                    if ($attempt -eq $maxAttempts) { throw }
                    Write-Host "     Policy not yet replicated, retrying ($attempt/$maxAttempts)..." -ForegroundColor Gray
                    Start-Sleep -Seconds 10
                }
            }

            if ($ruleAction -eq 'Created') {
                Write-Host "   Created Safe Attachments rule (applied to all domains)" -ForegroundColor Green
            }
        }

        return @{
            Success      = $true
            PolicyName   = $safeAttachPolicyName
            RuleName     = $safeAttachRuleName
            PolicyAction = $policyAction
            RuleAction   = $ruleAction
        }
    }
    catch {
        Write-Host "     Failed to configure Safe Attachments policy: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; PolicyName = $safeAttachPolicyName; RuleName = $safeAttachRuleName; Error = $_.Exception.Message }
    }
}

# Create Safe Links Policy
function New-SafeLinksConfiguration {
    Write-Host ""
    Write-Host "   Configuring Safe Links Policies..." -ForegroundColor Cyan

    $safeLinksPolicyName = "$($script:RunConfig.NamePrefix)Default Safe Links Policy"
    $safeLinksRuleName = "$($script:RunConfig.NamePrefix)Default Safe Links Rule"
    $policyAction = 'Updated'
    $ruleAction = 'Skipped'

    try {
        # Check if Safe Links policy already exists
        $existingPolicy = Get-SafeLinksPolicy -Identity $safeLinksPolicyName -ErrorAction SilentlyContinue

        if ($existingPolicy) {
            Write-Host "   Safe Links policy '$safeLinksPolicyName' already exists" -ForegroundColor Yellow
            Write-Host "   Updating existing policy..." -ForegroundColor Cyan

            # IsEnabled isn't a real parameter of Set-SafeLinksPolicy
            # (confirmed live: "A parameter cannot be found that matches
            # parameter name 'IsEnabled'" — Safe Links policies have no
            # top-level enabled toggle; enabling happens via the rule's
            # own -Enabled parameter instead, per Microsoft Learn's
            # documented parameter set).
            # $null = : Set-SafeLinksPolicy emits the updated policy object
            # on this path (confirmed live — it corrupted this function's
            # hashtable return and crashed the caller's .Success read under
            # strict mode).
            $null = Set-SafeLinksPolicy -Identity $safeLinksPolicyName `
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
            $policyAction = 'Created'

            $null = New-SafeLinksPolicy -Name $safeLinksPolicyName `
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
            $ruleAction = 'Created'

            $acceptedDomains = (Get-AcceptedDomain).Name
            $maxAttempts = 6
            for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
                try {
                    $null = New-SafeLinksRule -Name $safeLinksRuleName `
                        -SafeLinksPolicy $safeLinksPolicyName `
                        -RecipientDomainIs $acceptedDomains `
                        -Enabled $true `
                        -Priority 0 `
                        -ErrorAction Stop
                    break
                }
                catch {
                    if ($_.Exception.Message -match 'already has rule .* associated with it') {
                        Write-Host "   Safe Links rule already exists (detected on create), skipping" -ForegroundColor Yellow
                        $ruleAction = 'Skipped'
                        break
                    }
                    if ($attempt -eq $maxAttempts) { throw }
                    Write-Host "     Policy not yet replicated, retrying ($attempt/$maxAttempts)..." -ForegroundColor Gray
                    Start-Sleep -Seconds 10
                }
            }

            if ($ruleAction -eq 'Created') {
                Write-Host "   Created Safe Links rule (applied to all domains)" -ForegroundColor Green
            }
        }

        return @{
            Success      = $true
            PolicyName   = $safeLinksPolicyName
            RuleName     = $safeLinksRuleName
            PolicyAction = $policyAction
            RuleAction   = $ruleAction
        }
    }
    catch {
        Write-Host "     Failed to configure Safe Links policy: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; PolicyName = $safeLinksPolicyName; RuleName = $safeLinksRuleName; Error = $_.Exception.Message }
    }
}

function Write-Result-File {
    param([hashtable]$Result)
    if (!$ResultPath) { return }
    $Result | ConvertTo-Json -Depth 5 | Set-Content -Path $ResultPath -Encoding UTF8
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
        Write-Result-File -Result @{ Success = $false; Error = "Prerequisites not met" }
        if ($script:NonInteractive) { return }
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

    Write-Host "  Safe Attachments: $(if ($safeAttachmentsResult.Success) { 'Configured' } else { 'Failed' })" -ForegroundColor $(if ($safeAttachmentsResult.Success) { "Green" } else { "Red" })
    Write-Host "  Safe Links:       $(if ($safeLinksResult.Success) { 'Configured' } else { 'Failed' })" -ForegroundColor $(if ($safeLinksResult.Success) { "Green" } else { "Red" })

    if ($safeAttachmentsResult.Success -and $safeLinksResult.Success) {
        Write-Host ""
        Write-Host "  Next Steps:" -ForegroundColor Yellow
        Write-Host "    - Safe Attachments: Dynamic Delivery (1-2 min delay for emails with attachments)" -ForegroundColor Gray
        Write-Host "    - Safe Links: Protects Email, Teams, and Office apps" -ForegroundColor Gray
        Write-Host "    - Click tracking enabled, malicious links blocked when clicked" -ForegroundColor Gray
    }

    Write-Result-File -Result @{
        Success        = ([bool]$safeAttachmentsResult.Success -and [bool]$safeLinksResult.Success)
        SafeAttachments = $safeAttachmentsResult
        SafeLinks       = $safeLinksResult
    }

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

    Start-SafeAttachments
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Result-File -Result @{ Success = $false; Error = $_.Exception.Message }
    if ($script:NonInteractive) { exit 1 }
}
