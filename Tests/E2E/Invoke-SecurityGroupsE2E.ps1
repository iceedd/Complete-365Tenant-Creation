#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs entra/Security-Groups.ps1 unattended against the
    dedicated M365 test tenant and verifies the groups it creates.
.DESCRIPTION
    Connects to Microsoft Graph with certificate-based app-only auth, executes
    the real Security-Groups script in non-interactive mode with the E2E config
    (groups prefixed "E2E-", no license groups, no Intune role assignment),
    verifies each expected group exists with the right membership type, then
    deletes every "E2E-"-prefixed group it finds — cleanup runs even when
    verification fails.

    Only groups whose displayName starts with the E2E prefix are ever deleted.
.EXAMPLE
    ./Invoke-SecurityGroupsE2E.ps1 -TenantId $env:M365_TENANT_ID -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $TenantId,
    [Parameter(Mandatory)] [string] $AppId,
    [Parameter(Mandatory)] [string] $CertificateThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot   = $PSScriptRoot | Split-Path | Split-Path
$ConfigPath = Join-Path $PSScriptRoot 'security-groups.e2e.json'
$ResultPath = Join-Path ([IO.Path]::GetTempPath()) "sg-e2e-result-$([guid]::NewGuid().ToString('n')).json"

$E2EPrefix = (Get-Content $ConfigPath -Raw | ConvertFrom-Json).NamePrefix
if (!$E2EPrefix) { throw "E2E config must set a NamePrefix — refusing to run without test isolation" }

# The six static groups Security-Groups.ps1 creates, with expected membership types
$ExpectedGroups = @(
    @{ Name = 'NoMFA Exclusion Group';   Dynamic = $false },
    @{ Name = 'BITS Admin Users';        Dynamic = $true  },
    @{ Name = 'SSPR Eligible Users';     Dynamic = $true  },
    @{ Name = 'Helpdesk Operator Group'; Dynamic = $true  },
    @{ Name = 'CA-GEO-UK';               Dynamic = $false },
    @{ Name = 'CA-GEO-International';    Dynamic = $false }
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
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running Security-Groups.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'entra/Security-Groups.ps1') `
        -NonInteractive -ConfigFile $ConfigPath -ResultPath $ResultPath

    # ========================================================================
    # Assert on the script's own reported results
    # ========================================================================
    Write-Host "`n== Verifying script results ==" -ForegroundColor Cyan
    if (!(Test-Path $ResultPath)) {
        Write-Result $false "Script produced no results file — it likely aborted early"
    }
    else {
        $result = Get-Content $ResultPath -Raw | ConvertFrom-Json
        Write-Result ([bool]$result.Success) "Script reported success (created: $(@($result.Created).Count), skipped: $(@($result.Skipped).Count), failed: $(@($result.Failed).Count))"
        foreach ($fail in @($result.Failed)) {
            Write-Host "        failed group: $($fail.Name) — $($fail.Error)" -ForegroundColor Red
        }
    }

    # ========================================================================
    # Independently verify tenant state via Graph
    # ========================================================================
    Write-Host "`n== Verifying created groups in tenant ==" -ForegroundColor Cyan
    foreach ($expected in $ExpectedGroups) {
        $name  = "$E2EPrefix$($expected.Name)"
        $group = Get-MgGroup -Filter "displayName eq '$name'" -ErrorAction SilentlyContinue

        if (!$group) {
            Write-Result $false "$name exists"
            continue
        }
        Write-Result $true "$name exists"

        $isDynamic = @($group.GroupTypes) -contains 'DynamicMembership'
        Write-Result ($isDynamic -eq $expected.Dynamic) "$name membership type is $(if ($expected.Dynamic) { 'Dynamic' } else { 'Assigned' })"

        if ($expected.Dynamic) {
            Write-Result (![string]::IsNullOrWhiteSpace($group.MembershipRule)) "$name has a membership rule"
        }
    }

    # ========================================================================
    # Idempotency: a second run must skip everything and create nothing
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run skips all) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'entra/Security-Groups.ps1') `
        -NonInteractive -ConfigFile $ConfigPath -ResultPath $ResultPath

    $second = Get-Content $ResultPath -Raw | ConvertFrom-Json
    Write-Result ([bool]$second.Success -and @($second.Created).Count -eq 0 -and @($second.Skipped).Count -eq $ExpectedGroups.Count) `
        "Second run created nothing and skipped all $($ExpectedGroups.Count) groups"
}
finally {
    # ========================================================================
    # Cleanup — always runs; deletes ONLY prefix-matched groups
    # ========================================================================
    Write-Host "`n== Cleaning up E2E groups ==" -ForegroundColor Cyan
    try {
        $e2eGroups = @(Get-MgGroup -Filter "startsWith(displayName, '$E2EPrefix')" -All -ErrorAction Stop)
        foreach ($group in $e2eGroups) {
            try {
                Remove-MgGroup -GroupId $group.Id -Confirm:$false -ErrorAction Stop
                Write-Host "  Deleted $($group.DisplayName)" -ForegroundColor Gray
            }
            catch {
                Write-Host "  WARNING: could not delete $($group.DisplayName): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        Write-Host "  Removed $($e2eGroups.Count) group(s)" -ForegroundColor Green
    }
    catch {
        Write-Host "  WARNING: cleanup query failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Manually delete groups prefixed '$E2EPrefix' in the test tenant" -ForegroundColor Yellow
    }

    Remove-Item $ResultPath -ErrorAction SilentlyContinue
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
