#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs entra/Password-Policies.ps1 unattended against the
    dedicated M365 test tenant and verifies the password expiration policy it
    applies.
.DESCRIPTION
    Connects to Microsoft Graph with certificate-based app-only auth, then:
      1. Runs entra/Security-Groups.ps1 non-interactively (E2E- prefix) to
         create the prerequisite SSPR Eligible Users group
      2. Runs entra/Password-Policies.ps1 non-interactively (GroupNamePrefix
         E2E-) — the real script, same file the menu calls
      3. Verifies the script reports success and that the tenant's default
         domain has PasswordValidityPeriodInDays set to "never expire"
         (2147483647) via Graph
      4. Re-runs the script to prove idempotency (second run must report
         AlreadySet rather than Changed)
      5. Deletes the E2E- prefixed group created for this test in a finally
         block that always runs

    Like Auth-Methods.ps1, this script mutates a tenant-wide singleton (the
    default domain's password validity period) rather than creating named
    objects — there is no throwaway copy of "the tenant's password policy"
    to create and tear down. Setting it to never-expire for real *is* the
    test, matching what happens in a real customer engagement. The SSPR and
    banned-password/smart-lockout portions of the script are pure guidance
    text with no Graph calls, so nothing further to verify there. Only the
    prerequisite SSPR group is cleaned up.
.EXAMPLE
    ./Invoke-PasswordPoliciesE2E.ps1 -TenantId $env:M365_TENANT_ID -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $TenantId,
    [Parameter(Mandatory)] [string] $AppId,
    [Parameter(Mandatory)] [string] $CertificateThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot        = $PSScriptRoot | Split-Path | Split-Path
$GroupConfigPath = Join-Path $PSScriptRoot 'security-groups.e2e.json'
$PwdConfigPath   = Join-Path $PSScriptRoot 'password-policies.e2e.json'
$GroupResultPath = Join-Path ([IO.Path]::GetTempPath()) "sg-e2e-result-$([guid]::NewGuid().ToString('n')).json"
$PwdResultPath   = Join-Path ([IO.Path]::GetTempPath()) "pp-e2e-result-$([guid]::NewGuid().ToString('n')).json"

$pwdConfig = Get-Content $PwdConfigPath -Raw | ConvertFrom-Json
$E2EPrefix = $pwdConfig.GroupNamePrefix
if (!$E2EPrefix) { throw "E2E config must set a GroupNamePrefix — refusing to run without test isolation" }

$failures = 0

function Write-Result {
    param([bool]$Pass, [string]$Message)
    if ($Pass) { Write-Host "  PASS  $Message" -ForegroundColor Green }
    else       { Write-Host "  FAIL  $Message" -ForegroundColor Red; $script:failures++ }
}

# ============================================================================
# Connect
# ============================================================================
Write-Host "`n== Connecting to test tenant (app-only) ==" -ForegroundColor Cyan
Connect-MgGraph -ClientId $AppId -TenantId $TenantId `
    -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
$ctx = Get-MgContext
if ($ctx.AuthType -ne 'AppOnly') { throw "Expected AppOnly auth, got $($ctx.AuthType)" }
Write-Host "  Connected to tenant $($ctx.TenantId)" -ForegroundColor Green

try {
    # ========================================================================
    # Prerequisite: create the SSPR group Password-Policies depends on
    # ========================================================================
    Write-Host "`n== Creating prerequisite group (Security-Groups.ps1) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'entra/Security-Groups.ps1') `
        -NonInteractive -ConfigFile $GroupConfigPath -ResultPath $GroupResultPath

    Write-Host "`n== Waiting 30s for directory replication ==" -ForegroundColor Cyan
    Start-Sleep -Seconds 30

    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running Password-Policies.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'entra/Password-Policies.ps1') `
        -NonInteractive -ConfigFile $PwdConfigPath -ResultPath $PwdResultPath

    # ========================================================================
    # Assert on the script's own reported results
    # ========================================================================
    Write-Host "`n== Verifying script results ==" -ForegroundColor Cyan
    if (!(Test-Path $PwdResultPath)) {
        Write-Result $false "Script produced no results file — it likely aborted early"
    }
    else {
        $result = Get-Content $PwdResultPath -Raw | ConvertFrom-Json
        Write-Result ([bool]$result.Success) "Script reported success"
        Write-Result ([bool]$result.PasswordExpiration.Success) "Password expiration configured ($(if ($result.PasswordExpiration.Changed) { 'changed' } elseif ($result.PasswordExpiration.AlreadySet) { 'already set' } else { 'unknown' }))"
    }

    # ========================================================================
    # Independently verify tenant state via Graph
    # ========================================================================
    Write-Host "`n== Verifying default domain password policy ==" -ForegroundColor Cyan
    $domains = Get-MgDomain -ErrorAction Stop
    $primaryDomain = $domains | Where-Object { $_.IsDefault -eq $true } | Select-Object -First 1
    Write-Result ($null -ne $primaryDomain) "Default domain found"
    Write-Result ($primaryDomain.PasswordValidityPeriodInDays -eq 2147483647) `
        "Default domain password never expires (actual: $($primaryDomain.PasswordValidityPeriodInDays))"

    # ========================================================================
    # Idempotency: a second run must report AlreadySet, not Changed
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run reports AlreadySet) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'entra/Password-Policies.ps1') `
        -NonInteractive -ConfigFile $PwdConfigPath -ResultPath $PwdResultPath

    $second = Get-Content $PwdResultPath -Raw | ConvertFrom-Json
    Write-Result ([bool]$second.Success -and [bool]$second.PasswordExpiration.AlreadySet) `
        "Second run reported AlreadySet (no redundant change)"
}
finally {
    # ========================================================================
    # Cleanup — always runs; deletes ONLY the prefix-matched prerequisite
    # group. The password expiration policy itself is a tenant-wide singleton
    # applied as part of the test, not a throwaway test object, so it is
    # intentionally left in place (see script docstring).
    # ========================================================================
    Write-Host "`n== Cleaning up E2E groups ==" -ForegroundColor Cyan
    try {
        $e2eGroups = @(Get-MgGroup -Filter "startsWith(displayName, '$E2EPrefix')" -All -ErrorAction Stop)
        foreach ($group in $e2eGroups) {
            try {
                Remove-MgGroup -GroupId $group.Id -Confirm:$false -ErrorAction Stop
                Write-Host "  Deleted group $($group.DisplayName)" -ForegroundColor Gray
            }
            catch {
                Write-Host "  WARNING: could not delete group $($group.DisplayName): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        Write-Host "  Removed $($e2eGroups.Count) group(s)" -ForegroundColor Green
    }
    catch {
        Write-Host "  WARNING: group cleanup query failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Manually delete groups prefixed '$E2EPrefix' in the test tenant" -ForegroundColor Yellow
    }

    Remove-Item $GroupResultPath, $PwdResultPath -ErrorAction SilentlyContinue
    $null = Disconnect-MgGraph -ErrorAction SilentlyContinue
}

# ============================================================================
# Summary
# ============================================================================
Write-Host ""
Write-Host ("=" * 60)
Write-Host "E2E test summary: $failures failure(s)"
Write-Host ("=" * 60)

if ($failures -gt 0) { exit 1 }
exit 0
