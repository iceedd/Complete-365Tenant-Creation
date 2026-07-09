#Requires -Version 7.0

<#
.SYNOPSIS
    Configures Authentication Methods for Entra ID
.DESCRIPTION
    Enables strong authentication methods (Authenticator, FIDO2, OATH, TAP) and disables
    weak methods (SMS, Voice, Email OTP). Configures the registration campaign to exclude
    the NoMFA Exclusion Group (break-glass accounts).
.AUTHOR
    BITS
.VERSION
    1.1 - Non-interactive mode (-NonInteractive/-ConfigFile) for unattended
          E2E testing.
.PARAMETER NonInteractive
    Run unattended: skip the Y/N confirmation and all "press any key" pauses.
    Used by CI E2E tests.
.PARAMETER ConfigFile
    Optional JSON file overriding run behaviour. Supported keys:
      GroupNamePrefix (string) prefixed to "NoMFA Exclusion Group" when
                       looking up the registration-campaign exclusion group —
                       lets E2E tests point at a throwaway prefixed group
                       created by a prior Security-Groups E2E run
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
    GroupNamePrefix = ''
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
    'Microsoft.Graph.Authentication'
)

$RequiredScopes = @(
    "Policy.ReadWrite.AuthenticationMethod"
)

# Authentication method definitions
# id must match the Graph API method configuration ID exactly
$AuthMethodConfig = @(
    @{ Id = "microsoftAuthenticator"; DisplayName = "Microsoft Authenticator"; TargetState = "enabled"  },
    @{ Id = "fido2";                  DisplayName = "Passkey (FIDO2)";          TargetState = "enabled"  },
    @{ Id = "temporaryAccessPass";    DisplayName = "Temporary Access Pass";    TargetState = "enabled"  },
    @{ Id = "softwareOath";           DisplayName = "Software OATH Tokens";     TargetState = "enabled"  },
    @{ Id = "hardwareOath";           DisplayName = "Hardware OATH Tokens";     TargetState = "enabled"  },
    @{ Id = "sms";                    DisplayName = "SMS";                      TargetState = "disabled" },
    @{ Id = "voice";                  DisplayName = "Voice Call";               TargetState = "disabled" },
    @{ Id = "email";                  DisplayName = "Email OTP";                TargetState = "disabled" }
)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Initialize-ScriptModules {
    Write-Host "   Checking required modules..." -ForegroundColor Yellow

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

# ============================================================================
# PREREQUISITES
# ============================================================================

function Test-Prerequisites {
    Write-Host ""
    Write-Host "   PREREQUISITES CHECK" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    # Graph connection
    $context = Get-MgContext
    if (!$context) {
        Write-Host "   Not connected to Microsoft Graph" -ForegroundColor Red
        Write-Host "   Please connect using the main menu first" -ForegroundColor Yellow
        return @{ Success = $false }
    }
    Write-Host "   Connected as: $($context.Account)" -ForegroundColor Green

    # Check scopes
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

    # NoMFA group lookup
    $groupPrefix = $script:RunConfig.GroupNamePrefix
    $noMfaGroupName = "${groupPrefix}NoMFA Exclusion Group"
    Write-Host "   Looking up $noMfaGroupName..." -ForegroundColor Gray
    $noMfaGroup = Get-MgGroup -Filter "displayName eq '$noMfaGroupName'" -ErrorAction SilentlyContinue

    if (!$noMfaGroup) {
        Write-Host "   $noMfaGroupName not found - registration campaign exclusion will be skipped" -ForegroundColor Yellow
        Write-Host "   Run Security Groups script first to create it" -ForegroundColor Yellow
        return @{ Success = $true; NoMfaGroupId = $null }
    }

    Write-Host "   NoMFA Exclusion Group found (ID: $($noMfaGroup.Id))" -ForegroundColor Green
    Write-Host ""
    return @{ Success = $true; NoMfaGroupId = $noMfaGroup.Id }
}

# ============================================================================
# DATA FUNCTIONS
# ============================================================================

function Get-CurrentAuthMethods {
    <#
    .SYNOPSIS
        Reads current authentication method states from Graph
    #>
    $currentStates = @{}

    try {
        foreach ($method in $AuthMethodConfig) {
            try {
                # hardwareOath is beta-only (Microsoft Learn marks it "(preview)"
                # and documents it solely under graph-rest-beta) — v1.0 404s/400s
                $apiVersion = if ($method.Id -eq 'hardwareOath') { 'beta' } else { 'v1.0' }
                $current = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/$apiVersion/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/$($method.Id)" `
                    -ErrorAction Stop

                $currentStates[$method.Id] = $current.state
            }
            catch {
                # Method may not exist in tenant — treat as unknown
                $currentStates[$method.Id] = "unknown"
            }
        }
    }
    catch {
        Write-Host "   Warning: Could not read all current method states" -ForegroundColor Yellow
    }

    return $currentStates
}

# ============================================================================
# PREVIEW
# ============================================================================

function Show-AuthMethodPreview {
    param(
        [hashtable]$CurrentStates
    )

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  PREVIEW: Authentication Methods Configuration" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  # | Method                        | Current   | Action" -ForegroundColor Yellow
    Write-Host "  --|-------------------------------|-----------|------------------" -ForegroundColor Gray

    $index = 1
    foreach ($method in $AuthMethodConfig) {
        $current = if ($CurrentStates.ContainsKey($method.Id)) { $CurrentStates[$method.Id] } else { "unknown" }
        $target  = $method.TargetState

        $actionColor = if ($target -eq "enabled") { "Green" } else { "Red" }
        $action = if ($current -eq $target) { "No change" } else { $target.ToUpper() }
        $actionColor = if ($action -eq "No change") { "Gray" } elseif ($target -eq "enabled") { "Green" } else { "Red" }

        Write-Host ("  {0,2} | {1,-29} | {2,-9} | " -f $index, $method.DisplayName, $current) -NoNewline -ForegroundColor White
        Write-Host $action -ForegroundColor $actionColor
        $index++
    }

    Write-Host ""
}

function Show-RegistrationCampaignPreview {
    param([string]$NoMfaGroupId)

    Write-Host "  Registration Campaign:" -ForegroundColor Yellow

    if ($NoMfaGroupId) {
        Write-Host "    - State: Enabled" -ForegroundColor Green
        Write-Host "    - Snoozeable: Yes (14 days)" -ForegroundColor Gray
        Write-Host "    - NoMFA Exclusion Group: Excluded" -ForegroundColor Green
    }
    else {
        Write-Host "    - Skipped (NoMFA Exclusion Group not found)" -ForegroundColor Yellow
    }

    Write-Host ""
}

# ============================================================================
# EXECUTION
# ============================================================================

function Set-AuthenticationMethods {
    $results = @{ Updated = @(); Skipped = @(); Failed = @() }

    foreach ($method in $AuthMethodConfig) {
        Write-Host "   $($method.DisplayName)..." -ForegroundColor White

        try {
            $body = @{
                "@odata.type" = "#microsoft.graph.$($method.Id)AuthenticationMethodConfiguration"
                state         = $method.TargetState
            } | ConvertTo-Json

            # hardwareOath is beta-only (Microsoft Learn marks it "(preview)"
            # and documents it solely under graph-rest-beta) — v1.0 404s/400s
            $apiVersion = if ($method.Id -eq 'hardwareOath') { 'beta' } else { 'v1.0' }
            $null = Invoke-MgGraphRequest -Method PATCH `
                -Uri "https://graph.microsoft.com/$apiVersion/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/$($method.Id)" `
                -Body $body `
                -ContentType "application/json" `
                -ErrorAction Stop

            Write-Host "     Set to: $($method.TargetState)" -ForegroundColor Green
            $results.Updated += $method.DisplayName
        }
        catch {
            Write-Host "     Failed: $($_.Exception.Message)" -ForegroundColor Red
            $results.Failed += @{ Name = $method.DisplayName; Error = $_.Exception.Message }
        }

        Start-Sleep -Milliseconds 300
    }

    return $results
}

function Set-RegistrationCampaign {
    param([string]$NoMfaGroupId)

    if (!$NoMfaGroupId) {
        Write-Host "   Registration campaign skipped (no NoMFA group)" -ForegroundColor Yellow
        return $false
    }

    Write-Host "   Configuring registration campaign..." -ForegroundColor White

    try {
        $body = @{
            registrationEnforcement = @{
                authenticationMethodsRegistrationCampaign = @{
                    state            = "enabled"
                    snoozeDurationInDays = 14
                    excludeTargets   = @(
                        @{
                            id              = $NoMfaGroupId
                            targetType      = "group"
                            targetedAuthenticationMethod = "microsoftAuthenticator"
                        }
                    )
                    includeTargets   = @(
                        @{
                            id              = "all_users"
                            targetType      = "group"
                            targetedAuthenticationMethod = "microsoftAuthenticator"
                        }
                    )
                }
            }
        } | ConvertTo-Json -Depth 10

        $null = Invoke-MgGraphRequest -Method PATCH `
            -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy" `
            -Body $body `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Host "     Registration campaign configured" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "     Failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-AuthMethodsConfiguration {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  AUTHENTICATION METHODS CONFIGURATION" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Enables strong MFA methods and disables weak ones" -ForegroundColor Gray
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

    $noMfaGroupId = $prereqResult.NoMfaGroupId

    # Step 2: Read current state
    Write-Host "  STEP 2: Reading Current State" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray
    Write-Host "   Fetching current authentication method states..." -ForegroundColor Gray
    $currentStates = Get-CurrentAuthMethods
    Write-Host "   Done" -ForegroundColor Green

    # Step 3: Preview
    Write-Host ""
    Write-Host "  STEP 3: Preview" -ForegroundColor Yellow
    Show-AuthMethodPreview -CurrentStates $currentStates
    Show-RegistrationCampaignPreview -NoMfaGroupId $noMfaGroupId

    # Confirmation (skipped in unattended mode)
    if ($script:NonInteractive) {
        Write-Host "  Non-interactive mode: proceeding without confirmation" -ForegroundColor Gray
    }
    else {
        Write-Host "  [Y] Apply configuration  [N] Cancel" -ForegroundColor Gray
        Write-Host ""
        $confirm = Read-Host "  Proceed? (Y/N)"

        if ($confirm -notlike "Y*") {
            Write-Host ""
            Write-Host "  Cancelled by user" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
            try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
            return
        }
    }

    # Step 4: Apply
    Write-Host ""
    Write-Host "  STEP 4: Applying Configuration" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    $methodResults = Set-AuthenticationMethods

    Write-Host ""
    $campaignResult = Set-RegistrationCampaign -NoMfaGroupId $noMfaGroupId

    # Step 5: Summary
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Methods updated: $($methodResults.Updated.Count)" -ForegroundColor Green
    Write-Host "  Methods skipped: $($methodResults.Skipped.Count)" -ForegroundColor Yellow
    Write-Host "  Methods failed:  $($methodResults.Failed.Count)" -ForegroundColor $(if ($methodResults.Failed.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "  Reg. campaign:   $(if ($campaignResult) { 'Configured' } else { 'Skipped' })" -ForegroundColor $(if ($campaignResult) { "Green" } else { "Yellow" })
    Write-Host ""

    if ($methodResults.Failed.Count -gt 0) {
        Write-Host "  Failed Methods:" -ForegroundColor Red
        foreach ($fail in $methodResults.Failed) {
            Write-Host "    - $($fail.Name): $($fail.Error)" -ForegroundColor Red
        }
        Write-Host ""
    }

    Write-Host "  Next Steps:" -ForegroundColor Yellow
    Write-Host "    1. Verify in Entra admin center > Protection > Authentication Methods" -ForegroundColor Gray
    Write-Host "    2. Confirm Registration Campaign shows NoMFA group excluded" -ForegroundColor Gray
    Write-Host "    3. Complete migration from legacy MFA policy if still In Progress" -ForegroundColor Gray
    Write-Host ""

    # Machine-readable results for CI runners
    if ($ResultPath) {
        @{
            Success           = ($methodResults.Failed.Count -eq 0)
            Updated           = @($methodResults.Updated)
            Failed            = @($methodResults.Failed)
            CampaignConfigured = $campaignResult
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

    Start-AuthMethodsConfiguration
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
}
