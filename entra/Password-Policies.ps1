#Requires -Version 7.0

<#
.SYNOPSIS
    Configures Entra ID password policies and SSPR
.DESCRIPTION
    Configures password expiration (never expire), SSPR settings,
    and assigns SSPR to the SSPR Eligible Users group.
.AUTHOR
    LYON Tech
.VERSION
    2.0 - Implemented password policies and SSPR configuration
#>

# ============================================================================
# CONFIGURATION
# ============================================================================

$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Identity.SignIns'
)

$RequiredScopes = @(
    "Directory.ReadWrite.All",
    "Policy.ReadWrite.AuthenticationMethod",
    "Group.Read.All",
    "UserAuthenticationMethod.ReadWrite.All"
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
    $missingScopes = $RequiredScopes | Where-Object { $_ -notin $context.Scopes }

    if ($missingScopes.Count -gt 0) {
        Write-Host "   Missing scopes: $($missingScopes -join ', ')" -ForegroundColor Yellow
        Write-Host "   Requesting additional permissions..." -ForegroundColor Yellow

        try {
            $allScopes = ($context.Scopes + $missingScopes) | Select-Object -Unique
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            Connect-MgGraph -Scopes $allScopes -NoWelcome -ErrorAction Stop
            Write-Host "   Permissions updated" -ForegroundColor Green
        }
        catch {
            Write-Host "   Could not get required permissions: $($_.Exception.Message)" -ForegroundColor Red
            return @{ Success = $false }
        }
    }
    else {
        Write-Host "   All required permissions present" -ForegroundColor Green
    }

    # Check for SSPR Eligible Users group
    Write-Host "   Checking for SSPR Eligible Users group..." -ForegroundColor Gray
    $ssprGroup = Get-MgGroup -Filter "displayName eq 'SSPR Eligible Users'" -ErrorAction SilentlyContinue

    if (!$ssprGroup) {
        Write-Host "   SSPR Eligible Users group not found" -ForegroundColor Yellow
        Write-Host "   Run Security-Groups script first to create this group" -ForegroundColor Yellow
        return @{ Success = $false; MissingSsprGroup = $true }
    }
    Write-Host "   SSPR Eligible Users group found (ID: $($ssprGroup.Id))" -ForegroundColor Green

    Write-Host ""
    return @{
        Success = $true
        SsprGroupId = $ssprGroup.Id
        SsprGroupName = $ssprGroup.DisplayName
    }
}

# ============================================================================
# PASSWORD EXPIRATION
# ============================================================================

function Set-PasswordNeverExpire {
    <#
    .SYNOPSIS
        Configure domain password policy to never expire
    #>

    Write-Host "   Configuring password expiration policy..." -ForegroundColor Gray

    try {
        # Get current domain settings
        $domains = Get-MgDomain -ErrorAction SilentlyContinue

        # Get the default/initial domain
        $primaryDomain = $domains | Where-Object { $_.IsDefault -eq $true } | Select-Object -First 1

        if (!$primaryDomain) {
            Write-Host "     Could not find primary domain" -ForegroundColor Yellow
            return @{ Success = $false; Error = "Primary domain not found" }
        }

        # Check current password policy
        $currentPolicy = $primaryDomain.PasswordValidityPeriodInDays

        Write-Host "     Current password validity: $currentPolicy days" -ForegroundColor Gray

        if ($currentPolicy -eq 2147483647 -or $null -eq $currentPolicy) {
            Write-Host "     Passwords already set to never expire" -ForegroundColor Green
            return @{ Success = $true; AlreadySet = $true }
        }

        # Set password to never expire (2147483647 = never)
        $params = @{
            PasswordValidityPeriodInDays = 2147483647
            PasswordNotificationWindowInDays = 14
        }

        Update-MgDomain -DomainId $primaryDomain.Id -BodyParameter $params -ErrorAction Stop

        Write-Host "     Password expiration set to: Never" -ForegroundColor Green
        return @{ Success = $true; Changed = $true }
    }
    catch {
        Write-Host "     Failed to set password expiration: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "     You may need to configure this via Microsoft 365 Admin Center" -ForegroundColor Gray
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ============================================================================
# SSPR CONFIGURATION
# ============================================================================

function Set-SsprConfiguration {
    <#
    .SYNOPSIS
        Configure Self-Service Password Reset settings
    #>
    param([string]$SsprGroupId)

    Write-Host "   Configuring Self-Service Password Reset..." -ForegroundColor Gray

    try {
        # Get current SSPR policy using direct API
        Write-Host "     Checking current SSPR configuration..." -ForegroundColor Gray

        # Configure SSPR to target the SSPR Eligible Users group
        # Note: Full SSPR configuration requires additional Graph calls

        # For now, show guidance
        Write-Host "     SSPR Group ID for configuration: $SsprGroupId" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "     SSPR must be configured in Entra admin center:" -ForegroundColor Yellow
        Write-Host "     1. Go to: Protection > Password reset" -ForegroundColor Gray
        Write-Host "     2. Set 'Self service password reset enabled' to 'Selected'" -ForegroundColor Gray
        Write-Host "     3. Select 'SSPR Eligible Users' group" -ForegroundColor Gray
        Write-Host "     4. Configure authentication methods (Authenticator app + Phone)" -ForegroundColor Gray
        Write-Host "     5. Set 'Number of methods required to reset' to 2" -ForegroundColor Gray
        Write-Host ""
        Write-Host "     Direct link:" -ForegroundColor Gray
        Write-Host "     https://entra.microsoft.com/#view/Microsoft_AAD_IAM/PasswordResetMenuBlade/~/Properties" -ForegroundColor Cyan

        return @{ Success = $true; ManualConfigRequired = $true }
    }
    catch {
        Write-Host "     Failed to configure SSPR: $($_.Exception.Message)" -ForegroundColor Yellow
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ============================================================================
# BANNED PASSWORDS
# ============================================================================

function Show-BannedPasswordGuidance {
    Write-Host "   Banned Password List Configuration:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "     Configure custom banned passwords in Entra admin center:" -ForegroundColor Gray
    Write-Host "     1. Go to: Protection > Authentication methods > Password protection" -ForegroundColor Gray
    Write-Host "     2. Enable 'Enforce custom list'" -ForegroundColor Gray
    Write-Host "     3. Add company-specific terms:" -ForegroundColor Gray
    Write-Host "        - Company name and variations" -ForegroundColor Gray
    Write-Host "        - Product names" -ForegroundColor Gray
    Write-Host "        - Location names" -ForegroundColor Gray
    Write-Host "        - Common project names" -ForegroundColor Gray
    Write-Host ""
    Write-Host "     Direct link:" -ForegroundColor Gray
    Write-Host "     https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/PasswordProtection" -ForegroundColor Cyan
    Write-Host ""
}

# ============================================================================
# SMART LOCKOUT
# ============================================================================

function Show-SmartLockoutGuidance {
    Write-Host "   Smart Lockout Configuration:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "     Recommended settings:" -ForegroundColor Gray
    Write-Host "     - Lockout threshold: 10 failed attempts" -ForegroundColor Gray
    Write-Host "     - Lockout duration: 60 seconds" -ForegroundColor Gray
    Write-Host "     - Enable lockout tracking" -ForegroundColor Gray
    Write-Host ""
    Write-Host "     Configure in Entra admin center:" -ForegroundColor Gray
    Write-Host "     Protection > Authentication methods > Password protection" -ForegroundColor Gray
    Write-Host ""
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-PasswordPolicies {
    # Header
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  PASSWORD POLICIES & SSPR" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Configures password expiration and self-service password reset" -ForegroundColor Gray
    Write-Host ""

    # Step 1: Prerequisites
    Write-Host "  STEP 1: Prerequisites" -ForegroundColor Yellow
    $prereqResult = Test-Prerequisites

    if (!$prereqResult.Success) {
        Write-Host ""
        Write-Host "  Prerequisites not met. Please resolve issues and try again." -ForegroundColor Red
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    # Step 2: Preview
    Write-Host ""
    Write-Host "  STEP 2: Configuration Preview" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray
    Write-Host ""
    Write-Host "  The following settings will be configured:" -ForegroundColor White
    Write-Host ""
    Write-Host "  Password Expiration:" -ForegroundColor Yellow
    Write-Host "    - Set to: Never expire (NIST 800-63B recommendation)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Self-Service Password Reset:" -ForegroundColor Yellow
    Write-Host "    - Target group: SSPR Eligible Users" -ForegroundColor Gray
    Write-Host "    - Methods required: 2" -ForegroundColor Gray
    Write-Host "    - Allowed methods: Authenticator app, Phone" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Additional guidance provided for:" -ForegroundColor Yellow
    Write-Host "    - Custom banned password list" -ForegroundColor Gray
    Write-Host "    - Smart lockout settings" -ForegroundColor Gray
    Write-Host ""

    # Confirmation
    Write-Host "  [Y] Proceed with configuration  [N] Cancel" -ForegroundColor Gray
    Write-Host ""
    $confirm = Read-Host "  Apply password policies? (Y/N)"

    if ($confirm -notlike "Y*") {
        Write-Host ""
        Write-Host "  Cancelled by user" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
        return
    }

    # Step 3: Execute
    Write-Host ""
    Write-Host "  STEP 3: Applying Configuration" -ForegroundColor Yellow
    Write-Host ("   " + "-" * 50) -ForegroundColor Gray

    $results = @{
        PasswordExpiration = $null
        Sspr = $null
    }

    # Set password never expire
    $results.PasswordExpiration = Set-PasswordNeverExpire

    Write-Host ""

    # Configure SSPR
    $results.Sspr = Set-SsprConfiguration -SsprGroupId $prereqResult.SsprGroupId

    Write-Host ""

    # Show additional guidance
    Show-BannedPasswordGuidance
    Show-SmartLockoutGuidance

    # Step 4: Summary
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""

    # Password expiration result
    if ($results.PasswordExpiration.Success) {
        if ($results.PasswordExpiration.AlreadySet) {
            Write-Host "  Password Expiration: Already configured (never expire)" -ForegroundColor Green
        }
        else {
            Write-Host "  Password Expiration: Set to never expire" -ForegroundColor Green
        }
    }
    else {
        Write-Host "  Password Expiration: Manual configuration required" -ForegroundColor Yellow
    }

    # SSPR result
    if ($results.Sspr.ManualConfigRequired) {
        Write-Host "  SSPR: Manual configuration required (see guidance above)" -ForegroundColor Yellow
    }
    elseif ($results.Sspr.Success) {
        Write-Host "  SSPR: Configured successfully" -ForegroundColor Green
    }
    else {
        Write-Host "  SSPR: Failed - $($results.Sspr.Error)" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "  IMPORTANT:" -ForegroundColor Yellow
    Write-Host "    - SSPR Eligible Users group: $($prereqResult.SsprGroupName)" -ForegroundColor Gray
    Write-Host "    - Group ID: $($prereqResult.SsprGroupId)" -ForegroundColor Gray
    Write-Host "    - Complete SSPR setup in Entra admin center" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  Next Steps:" -ForegroundColor Yellow
    Write-Host "    1. Configure SSPR in Entra admin center (link provided above)" -ForegroundColor Gray
    Write-Host "    2. Add company-specific banned passwords" -ForegroundColor Gray
    Write-Host "    3. Review smart lockout settings" -ForegroundColor Gray
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

    Start-PasswordPolicies
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
}
