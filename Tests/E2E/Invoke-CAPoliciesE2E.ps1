#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs entra/CA-Policies.ps1 unattended against the
    dedicated M365 test tenant and verifies the Conditional Access policies
    it creates.
.DESCRIPTION
    Connects to Microsoft Graph with certificate-based app-only auth, then:
      1. Runs entra/Security-Groups.ps1 non-interactively (E2E- prefix) to
         create the prerequisite groups CA-Policies depends on (NoMFA
         Exclusion Group, CA-GEO-UK, CA-GEO-International)
      2. Runs entra/CA-Policies.ps1 non-interactively (E2E- prefix,
         PolicyMode ReportOnly) — the real script, same file the menu calls.
         ReportOnly is mandatory here: most of these policies target "All"
         users, and this runs in a shared test tenant, so Enabled would
         actually enforce block/MFA rules for real traffic. The script
         auto-creates the (prefixed) UK named location when the geo groups
         exist, so C007 is expected to be CREATED, not skipped.
      3. Verifies all 8 expected policies exist, are report-only, exclude
         the E2E NoMFA group, and that C007 references the geo group and
         named location and C008 blocks the device code flow
      4. Re-runs the script to prove idempotency
      5. Deletes every E2E- prefixed CA policy, named location, and group in
         a finally block that always runs, so cleanup happens even on failure

    Only objects whose displayName starts with the E2E prefix are ever
    deleted or asserted on.
.EXAMPLE
    ./Invoke-CAPoliciesE2E.ps1 -TenantId $env:M365_TENANT_ID -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
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
$CAConfigPath    = Join-Path $PSScriptRoot 'ca-policies.e2e.json'
$GroupResultPath = Join-Path ([IO.Path]::GetTempPath()) "sg-e2e-result-$([guid]::NewGuid().ToString('n')).json"
$CAResultPath    = Join-Path ([IO.Path]::GetTempPath()) "ca-e2e-result-$([guid]::NewGuid().ToString('n')).json"

$caConfig = Get-Content $CAConfigPath -Raw | ConvertFrom-Json
$E2EPrefix = $caConfig.NamePrefix
if (!$E2EPrefix) { throw "E2E config must set a NamePrefix — refusing to run without test isolation" }
if ($caConfig.PolicyMode -ne 'ReportOnly') { throw "E2E config must use PolicyMode ReportOnly — refusing to risk enforcing policies in a shared tenant" }

# All 8 policies CA-Policies.ps1 creates. C007 depends on the geo groups
# (created by the Security-Groups prerequisite step below) and the UK named
# location, which the script now auto-creates when those groups exist.
$ExpectedPolicyNames = @(
    'C001 - Block High Risk Users'
    'C002 - MFA Required for All Users'
    'C003 - Block Non Corporate Devices'
    'C004 - Require Password Change for High Risk Users'
    'C005 - Require MFA for Risky Sign-Ins'
    'C006 - Block Legacy Authentication'
    'C008 - Block Device Code Flow'
    'C007 - Block Sign-In Outside UK (UK Users)'
)

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
    # Prerequisite: create the groups CA-Policies depends on
    # ========================================================================
    Write-Host "`n== Creating prerequisite groups (Security-Groups.ps1) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'entra/Security-Groups.ps1') `
        -NonInteractive -ConfigFile $GroupConfigPath -ResultPath $GroupResultPath

    Write-Host "`n== Waiting 30s for directory replication ==" -ForegroundColor Cyan
    Start-Sleep -Seconds 30

    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running CA-Policies.ps1 (non-interactive, ReportOnly) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'entra/CA-Policies.ps1') `
        -NonInteractive -ConfigFile $CAConfigPath -ResultPath $CAResultPath

    Write-Host "`n== Waiting 30s for directory replication ==" -ForegroundColor Cyan
    Start-Sleep -Seconds 30

    # ========================================================================
    # Assert on the script's own reported results
    # ========================================================================
    Write-Host "`n== Verifying script results ==" -ForegroundColor Cyan
    if (!(Test-Path $CAResultPath)) {
        Write-Result $false "Script produced no results file — it likely aborted early"
    }
    else {
        $result = Get-Content $CAResultPath -Raw | ConvertFrom-Json
        Write-Result ([bool]$result.Success) "Script reported success (created: $(@($result.Created).Count), skipped: $(@($result.Skipped).Count), failed: $(@($result.Failed).Count))"
        foreach ($fail in @($result.Failed)) {
            Write-Host "        failed policy: $($fail.Name) — $($fail.Error)" -ForegroundColor Red
        }
    }

    # ========================================================================
    # Independently verify tenant state via Graph
    # ========================================================================
    Write-Host "`n== Verifying created policies in tenant ==" -ForegroundColor Cyan
    $noMfaGroup = Get-MgGroup -Filter "displayName eq '${E2EPrefix}NoMFA Exclusion Group'" -ErrorAction SilentlyContinue
    foreach ($name in $ExpectedPolicyNames) {
        $fullName = "$E2EPrefix$name"
        $policy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$fullName'" -ErrorAction SilentlyContinue

        if (!$policy) {
            Write-Result $false "$fullName exists"
            continue
        }
        Write-Result $true "$fullName exists"
        Write-Result ($policy.State -eq 'enabledForReportingButNotEnforced') "$fullName is report-only (not enforcing)"
        Write-Result ($noMfaGroup -and (@($policy.Conditions.Users.ExcludeGroups) -contains $noMfaGroup.Id)) "$fullName excludes the E2E NoMFA group"
    }

    # The UK named location must have been auto-created (prefix-aware), and
    # C007 must actually reference the geo groups and that location
    Write-Host "`n== Verifying auto-created named location and C007/C008 wiring ==" -ForegroundColor Cyan
    $locations = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" -ErrorAction Stop
    $ukLocation = @($locations.value) | Where-Object { $_.displayName -eq "${E2EPrefix}UK" } | Select-Object -First 1
    Write-Result ([bool]$ukLocation) "${E2EPrefix}UK named location was auto-created"
    if ($ukLocation) {
        Write-Result (@($ukLocation.countriesAndRegions) -contains 'GB') "${E2EPrefix}UK named location covers GB"
    }

    $geoUkGroup = Get-MgGroup -Filter "displayName eq '${E2EPrefix}CA-GEO-UK'" -ErrorAction SilentlyContinue
    $c007 = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '${E2EPrefix}C007 - Block Sign-In Outside UK (UK Users)'" -ErrorAction SilentlyContinue
    if ($c007 -and $ukLocation -and $geoUkGroup) {
        Write-Result (@($c007.Conditions.Users.IncludeGroups) -contains $geoUkGroup.Id) "C007 targets the E2E CA-GEO-UK group"
        Write-Result (@($c007.Conditions.Locations.ExcludeLocations) -contains $ukLocation.id) "C007 excludes the ${E2EPrefix}UK named location"
    }

    # C008's authenticationFlows condition isn't surfaced by every SDK model
    # version — assert via a raw Graph read instead
    $c008 = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '${E2EPrefix}C008 - Block Device Code Flow'" -ErrorAction SilentlyContinue
    if ($c008) {
        $c008Raw = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($c008.Id)" -ErrorAction Stop
        Write-Result ($c008Raw.conditions.authenticationFlows.transferMethods -match 'deviceCodeFlow') `
            "C008 blocks the device code flow authentication transfer method"
    }

    # ========================================================================
    # Idempotency: a second run must skip everything and create nothing
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run skips all) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'entra/CA-Policies.ps1') `
        -NonInteractive -ConfigFile $CAConfigPath -ResultPath $CAResultPath

    $second = Get-Content $CAResultPath -Raw | ConvertFrom-Json
    Write-Result ([bool]$second.Success -and @($second.Created).Count -eq 0 -and @($second.Skipped).Count -eq $ExpectedPolicyNames.Count) `
        "Second run created nothing and skipped all $($ExpectedPolicyNames.Count) policies"
}
finally {
    # ========================================================================
    # Cleanup — always runs; deletes ONLY prefix-matched objects
    # ========================================================================
    Write-Host "`n== Cleaning up E2E policies ==" -ForegroundColor Cyan
    try {
        $e2ePolicies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop | Where-Object { $_.DisplayName -like "$E2EPrefix*" })
        foreach ($policy in $e2ePolicies) {
            try {
                Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id -ErrorAction Stop
                Write-Host "  Deleted policy $($policy.DisplayName)" -ForegroundColor Gray
            }
            catch {
                Write-Host "  WARNING: could not delete policy $($policy.DisplayName): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        Write-Host "  Removed $($e2ePolicies.Count) polic(y/ies)" -ForegroundColor Green
    }
    catch {
        Write-Host "  WARNING: policy cleanup query failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Manually delete CA policies prefixed '$E2EPrefix' in the test tenant" -ForegroundColor Yellow
    }

    # Named locations must be deleted AFTER the policies that reference them
    Write-Host "`n== Cleaning up E2E named locations ==" -ForegroundColor Cyan
    try {
        $locations = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" -ErrorAction Stop
        foreach ($loc in @($locations.value | Where-Object { $_.displayName -like "$E2EPrefix*" })) {
            try {
                Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations/$($loc.id)" -ErrorAction Stop
                Write-Host "  Deleted named location $($loc.displayName)" -ForegroundColor Gray
            }
            catch {
                Write-Host "  WARNING: could not delete named location $($loc.displayName): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Host "  WARNING: named location cleanup query failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

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

    Remove-Item $GroupResultPath, $CAResultPath -ErrorAction SilentlyContinue
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
