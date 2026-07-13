#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs Exchange/Distribution-Lists.ps1 unattended against
    the dedicated M365 test tenant and verifies the distribution list it
    creates.
.DESCRIPTION
    Connects to Microsoft Graph with certificate-based app-only auth, then:
      1. Writes a throwaway config file describing one E2E- prefixed
         distribution list in the test tenant's own initial domain (always
         accepted, so no prior setup is needed)
      2. Runs Exchange/Distribution-Lists.ps1 non-interactively — the real
         script, same file the menu calls
      3. Verifies the group exists via Microsoft Graph: mailEnabled,
         !securityEnabled, empty groupTypes (a classic distribution list,
         not a Microsoft 365 group or mail-enabled security group), and the
         expected mail address
      4. Re-runs the script to prove idempotency (second run must skip the
         already-existing list)
      5. Deletes the group in a finally block that always runs, so cleanup
         happens even on failure
.EXAMPLE
    ./Invoke-DistributionListsE2E.ps1 -TenantId $env:M365_TENANT_ID -TenantDomain $env:M365_TENANT_DOMAIN -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $TenantId,
    [Parameter(Mandatory)] [string] $TenantDomain,
    [Parameter(Mandatory)] [string] $AppId,
    [Parameter(Mandatory)] [string] $CertificateThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot        = $PSScriptRoot | Split-Path | Split-Path
$E2EPrefix       = "e2e-dl-"
$E2EMailNickname = "${E2EPrefix}test"
$E2EEmail        = "$E2EMailNickname@$TenantDomain"
$E2EDisplayName  = "E2E Test Distribution List"

$DLConfigPath = Join-Path ([IO.Path]::GetTempPath()) "dl-e2e-config-$([guid]::NewGuid().ToString('n')).json"
$ResultPath   = Join-Path ([IO.Path]::GetTempPath()) "dl-e2e-result-$([guid]::NewGuid().ToString('n')).json"

@{
    DistributionLists = @(
        @{
            DisplayName  = $E2EDisplayName
            PrimaryEmail = $E2EEmail
            MailNickname = $E2EMailNickname
            Description  = "Created by Invoke-DistributionListsE2E.ps1"
        }
    )
} | ConvertTo-Json -Depth 5 | Set-Content -Path $DLConfigPath -Encoding UTF8

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
    Write-Host "`n== Running Distribution-Lists.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Exchange/Distribution-Lists.ps1') `
        -NonInteractive -ConfigFile $DLConfigPath -ResultPath $ResultPath

    # ========================================================================
    # Assert on the script's own reported results
    # ========================================================================
    Write-Host "`n== Verifying script results ==" -ForegroundColor Cyan
    if (!(Test-Path $ResultPath)) {
        Write-Result $false "Script produced no results file — it likely aborted early"
    }
    else {
        $result = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
        Write-Result ([bool]$result.Success -and @($result.Created) -contains $E2EEmail) "Script reported success and created $E2EEmail"
        foreach ($fail in @($result.Failed)) {
            Write-Host "        failed list: $($fail.Name) — $($fail.Error)" -ForegroundColor Red
        }
    }

    # ========================================================================
    # Independently verify tenant state via Graph
    # ========================================================================
    Write-Host "`n== Verifying created distribution list in tenant ==" -ForegroundColor Cyan
    $groups = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=mailNickname eq '$E2EMailNickname'" -Method GET -ErrorAction Stop
    $group = $groups.value | Select-Object -First 1
    Write-Result ([bool]$group) "$E2EDisplayName exists"
    if ($group) {
        Write-Result ($group.mailEnabled -eq $true) "$E2EDisplayName is mail-enabled"
        Write-Result ($group.securityEnabled -eq $false) "$E2EDisplayName is not security-enabled"
        Write-Result (@($group.groupTypes).Count -eq 0) "$E2EDisplayName has no groupTypes (classic distribution list, not M365 group)"
        Write-Result ($group.mail -eq $E2EEmail) "$E2EDisplayName has the expected mail address (got: $($group.mail))"
    }

    # ========================================================================
    # Idempotency: a second run must skip the already-existing list
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run skips) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'Exchange/Distribution-Lists.ps1') `
        -NonInteractive -ConfigFile $DLConfigPath -ResultPath $ResultPath

    $second = Get-Content $ResultPath -Raw | ConvertFrom-Json -AsHashtable
    Write-Result ([bool]$second.Success -and @($second.Created).Count -eq 0 -and (@($second.Skipped) -contains $E2EEmail)) `
        "Second run created nothing and skipped the already-existing list"
}
finally {
    # ========================================================================
    # Cleanup — always runs
    # ========================================================================
    Write-Host "`n== Cleaning up E2E distribution list ==" -ForegroundColor Cyan
    try {
        $groups = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=mailNickname eq '$E2EMailNickname'" -Method GET -ErrorAction Stop
        foreach ($group in @($groups.value)) {
            try {
                $null = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)" -Method DELETE -ErrorAction Stop
                Write-Host "  Deleted group $($group.displayName)" -ForegroundColor Gray
            }
            catch {
                Write-Host "  WARNING: could not delete group $($group.displayName): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Host "  WARNING: group cleanup query failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Manually delete the '$E2EDisplayName' distribution list in the test tenant" -ForegroundColor Yellow
    }

    Remove-Item $DLConfigPath, $ResultPath -ErrorAction SilentlyContinue
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
