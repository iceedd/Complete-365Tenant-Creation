#Requires -Version 7.0

<#
.SYNOPSIS
    App-only smoke test against the dedicated M365 test tenant.
.DESCRIPTION
    Connects to Microsoft Graph and Exchange Online using certificate-based
    app-only authentication, then exercises the read-only API surface that the
    tenant-automation scripts depend on. Intended to run in CI on a Windows
    runner, but can also be run locally.

    All checks are read-only — nothing is created or modified in the tenant.

    Core checks (Graph, Exchange Online) fail the run. Checks that depend on
    tenant licensing or optional role assignments (Intune, Security &
    Compliance) emit warnings only.
.PARAMETER TenantId
    Directory (tenant) ID of the test tenant.
.PARAMETER TenantDomain
    Initial domain of the test tenant, e.g. contoso-test.onmicrosoft.com.
.PARAMETER AppId
    Application (client) ID of the Claude-SmokeTest app registration.
.PARAMETER CertificateThumbprint
    Thumbprint of the auth certificate in Cert:\CurrentUser\My.
.EXAMPLE
    ./Invoke-SmokeTest.ps1 -TenantId $env:M365_TENANT_ID -TenantDomain $env:M365_TENANT_DOMAIN -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
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

$script:CoreFailures = 0
$script:Warnings     = 0

function Invoke-Check {
    param(
        [string] $Name,
        [scriptblock] $Check,
        [switch] $WarnOnly
    )
    try {
        $detail = & $Check
        Write-Host "  PASS  $Name$(if ($detail) { " — $detail" })" -ForegroundColor Green
    }
    catch {
        if ($WarnOnly) {
            $script:Warnings++
            Write-Host "  WARN  $Name — $($_.Exception.Message)" -ForegroundColor Yellow
        }
        else {
            $script:CoreFailures++
            Write-Host "  FAIL  $Name — $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# ============================================================================
# Microsoft Graph (core)
# ============================================================================
Write-Host "`n== Microsoft Graph ==" -ForegroundColor Cyan

Invoke-Check "Connect-MgGraph (app-only, certificate)" {
    Connect-MgGraph -ClientId $AppId -TenantId $TenantId `
        -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
    $ctx = Get-MgContext
    if ($ctx.AuthType -ne 'AppOnly') { throw "Expected AppOnly auth, got $($ctx.AuthType)" }
    "tenant $($ctx.TenantId)"
}

Invoke-Check "Read organization" {
    $org = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization" -ErrorAction Stop
    $org.value[0].displayName
}

Invoke-Check "List groups (Security-Groups/Device-Groups surface)" {
    $groups = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups?`$top=5&`$select=id,displayName" -ErrorAction Stop
    "$($groups.value.Count) returned"
}

Invoke-Check "List conditional access policies (CA-Policies surface)" {
    $pols = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$top=5" -ErrorAction Stop
    "$($pols.value.Count) returned"
}

Invoke-Check "Read SharePoint root site (Site-Groups surface)" {
    $site = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/root" -ErrorAction Stop
    $site.webUrl
}

# Intune endpoints need an Intune license on the tenant — warn-only
Invoke-Check "List Intune compliance policies (beta, Compliance-Policies surface)" -WarnOnly {
    $pols = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?`$top=5" -ErrorAction Stop
    "$($pols.value.Count) returned"
}

Invoke-Check "List Intune settings catalog policies (beta, Configuration-Policies surface)" -WarnOnly {
    $pols = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$top=5" -ErrorAction Stop
    "$($pols.value.Count) returned"
}

# ============================================================================
# Exchange Online (core)
# ============================================================================
Write-Host "`n== Exchange Online ==" -ForegroundColor Cyan

Invoke-Check "Connect-ExchangeOnline (app-only, certificate)" {
    Connect-ExchangeOnline -AppId $AppId -CertificateThumbprint $CertificateThumbprint `
        -Organization $TenantDomain -ShowBanner:$false -ErrorAction Stop
    $conn = Get-ConnectionInformation
    if (!$conn -or $conn.State -ne 'Connected') { throw "Connection state: $($conn.State)" }
    $conn.Organization
}

Invoke-Check "Get accepted domains (Shared-MB-Creation surface)" {
    $domains = Get-AcceptedDomain -ErrorAction Stop
    "$(@($domains).Count) domain(s)"
}

Invoke-Check "Get organization config (Archive-Policies surface)" {
    $cfg = Get-OrganizationConfig -ErrorAction Stop
    $cfg.DisplayName
}

Invoke-Check "Get anti-phish policies (Anti-Phishing surface)" -WarnOnly {
    $pols = Get-AntiPhishPolicy -ErrorAction Stop
    "$(@($pols).Count) policy(ies)"
}

# ============================================================================
# Security & Compliance / Purview (warn-only: needs Compliance Administrator)
# ============================================================================
Write-Host "`n== Security & Compliance ==" -ForegroundColor Cyan

Invoke-Check "Connect-IPPSSession + list retention policies (Retention-Policies surface)" -WarnOnly {
    Connect-IPPSSession -AppId $AppId -CertificateThumbprint $CertificateThumbprint `
        -Organization $TenantDomain -ErrorAction Stop
    $pols = Get-RetentionCompliancePolicy -ErrorAction Stop
    "$(@($pols).Count) policy(ies)"
}

# ============================================================================
# Summary
# ============================================================================
Write-Host ""
Write-Host ("=" * 60)
Write-Host "Smoke test summary: $script:CoreFailures core failure(s), $script:Warnings warning(s)"
Write-Host ("=" * 60)

try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
try { $null = Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}

if ($script:CoreFailures -gt 0) {
    exit 1
}
exit 0
