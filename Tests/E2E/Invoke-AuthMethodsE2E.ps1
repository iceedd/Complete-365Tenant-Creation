#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs entra/Auth-Methods.ps1 unattended against the
    dedicated M365 test tenant and verifies the authentication method
    configuration it applies.
.DESCRIPTION
    Connects to Microsoft Graph with certificate-based app-only auth, then:
      1. Runs entra/Security-Groups.ps1 non-interactively (E2E- prefix) to
         create the prerequisite NoMFA Exclusion Group
      2. Runs entra/Auth-Methods.ps1 non-interactively (GroupNamePrefix E2E-)
         — the real script, same file the menu calls
      3. Verifies each authentication method configuration matches its target
         state, and that the registration campaign is enabled and excludes
         the E2E NoMFA group
      4. Re-runs the script to prove idempotency (unconditional PATCH calls
         succeed identically on a second run)
      5. Deletes the E2E- prefixed group created for this test in a finally
         block that always runs

    Unlike Security-Groups/Admin-Creation/CA-Policies, Auth-Methods.ps1
    mutates tenant-wide singleton settings (the authentication methods policy
    and its registration campaign) rather than creating named/prefixed
    objects — there is no throwaway copy of "the tenant's auth method policy"
    to create and tear down. Applying it for real *is* the test, matching
    what happens in a real customer engagement. Only the prerequisite NoMFA
    group is cleaned up.
.EXAMPLE
    ./Invoke-AuthMethodsE2E.ps1 -TenantId $env:M365_TENANT_ID -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
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
$AuthConfigPath  = Join-Path $PSScriptRoot 'auth-methods.e2e.json'
$GroupResultPath = Join-Path ([IO.Path]::GetTempPath()) "sg-e2e-result-$([guid]::NewGuid().ToString('n')).json"
$AuthResultPath  = Join-Path ([IO.Path]::GetTempPath()) "am-e2e-result-$([guid]::NewGuid().ToString('n')).json"

$authConfig = Get-Content $AuthConfigPath -Raw | ConvertFrom-Json
$E2EPrefix = $authConfig.GroupNamePrefix
if (!$E2EPrefix) { throw "E2E config must set a GroupNamePrefix — refusing to run without test isolation" }

# The 8 methods Auth-Methods.ps1 configures, with their expected target state
$ExpectedMethodStates = [ordered]@{
    microsoftAuthenticator = 'enabled'
    fido2                  = 'enabled'
    temporaryAccessPass    = 'enabled'
    softwareOath           = 'enabled'
    hardwareOath           = 'enabled'
    sms                    = 'disabled'
    voice                  = 'disabled'
    email                  = 'disabled'
}

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
    # Prerequisite: create the NoMFA group Auth-Methods depends on
    # ========================================================================
    Write-Host "`n== Creating prerequisite group (Security-Groups.ps1) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'entra/Security-Groups.ps1') `
        -NonInteractive -ConfigFile $GroupConfigPath -ResultPath $GroupResultPath

    Write-Host "`n== Waiting 30s for directory replication ==" -ForegroundColor Cyan
    Start-Sleep -Seconds 30

    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running Auth-Methods.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'entra/Auth-Methods.ps1') `
        -NonInteractive -ConfigFile $AuthConfigPath -ResultPath $AuthResultPath

    # ========================================================================
    # Assert on the script's own reported results
    # ========================================================================
    Write-Host "`n== Verifying script results ==" -ForegroundColor Cyan
    if (!(Test-Path $AuthResultPath)) {
        Write-Result $false "Script produced no results file — it likely aborted early"
    }
    else {
        $result = Get-Content $AuthResultPath -Raw | ConvertFrom-Json
        Write-Result ([bool]$result.Success) "Script reported success (updated: $(@($result.Updated).Count), failed: $(@($result.Failed).Count))"
        Write-Result ([bool]$result.CampaignConfigured) "Script reports registration campaign configured"
        foreach ($fail in @($result.Failed)) {
            Write-Host "        failed method: $($fail.Name) — $($fail.Error)" -ForegroundColor Red
        }
    }

    # ========================================================================
    # Independently verify tenant state via Graph
    # ========================================================================
    Write-Host "`n== Verifying authentication method states in tenant ==" -ForegroundColor Cyan
    foreach ($methodId in $ExpectedMethodStates.Keys) {
        $expected = $ExpectedMethodStates[$methodId]
        $current = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/$methodId" `
            -ErrorAction Stop
        Write-Result ($current.state -eq $expected) "$methodId is '$expected' (actual: $($current.state))"
    }

    Write-Host "`n== Verifying registration campaign ==" -ForegroundColor Cyan
    $noMfaGroup = Get-MgGroup -Filter "displayName eq '${E2EPrefix}NoMFA Exclusion Group'" -ErrorAction SilentlyContinue
    $policy = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy" `
        -ErrorAction Stop
    $campaign = $policy.registrationEnforcement.authenticationMethodsRegistrationCampaign
    Write-Result ($campaign.state -eq 'enabled') "Registration campaign is enabled"
    $excludedIds = @($campaign.excludeTargets | ForEach-Object { $_.id })
    Write-Result ($noMfaGroup -and ($excludedIds -contains $noMfaGroup.Id)) "Registration campaign excludes the E2E NoMFA group"

    # ========================================================================
    # Idempotency: a second run must also succeed (unconditional PATCH calls,
    # so "idempotent" here means "safe to re-run", not "skips work")
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run also succeeds) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'entra/Auth-Methods.ps1') `
        -NonInteractive -ConfigFile $AuthConfigPath -ResultPath $AuthResultPath

    $second = Get-Content $AuthResultPath -Raw | ConvertFrom-Json
    Write-Result ([bool]$second.Success -and @($second.Failed).Count -eq 0) `
        "Second run also succeeded with no failures"
}
finally {
    # ========================================================================
    # Cleanup — always runs; deletes ONLY the prefix-matched prerequisite group.
    # The auth method / registration campaign settings themselves are tenant-
    # wide singletons applied as part of the test, not throwaway test objects,
    # so they are intentionally left in place (see script docstring).
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

    Remove-Item $GroupResultPath, $AuthResultPath -ErrorAction SilentlyContinue
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
