#Requires -Version 7.0

<#
.SYNOPSIS
    End-to-end test: runs entra/Admin-Creation.ps1 unattended against the
    dedicated M365 test tenant and verifies the accounts, groups, and role
    assignments it creates.
.DESCRIPTION
    Connects to Microsoft Graph with certificate-based app-only auth, then:
      1. Runs entra/Security-Groups.ps1 non-interactively (E2E- prefix) to
         create the prerequisite groups Admin-Creation depends on
      2. Runs entra/Admin-Creation.ps1 non-interactively (E2E- prefix) —
         the real script, same file the menu calls
      3. Verifies each of the four accounts exists with correct attributes
      4. Verifies Entra ID directory role assignments for each account
      5. Verifies the one staticly-assignable group (NoMFA Exclusion Group)
         actually gained the BG02 member — dynamic groups (BITS Admin Users,
         Helpdesk Operator Group) are excluded from membership verification
         since Microsoft documents 5-10 minutes for dynamic rules to
         evaluate, too slow for a CI run
      6. Re-runs Admin-Creation.ps1 to prove idempotency
      7. Deletes every E2E- prefixed user and group, and the Intune Helpdesk
         role assignment, in a finally block that always runs

    Only objects whose displayName/UPN local-part starts with the E2E prefix
    are ever deleted.
.EXAMPLE
    ./Invoke-AdminCreationE2E.ps1 -TenantId $env:M365_TENANT_ID -AppId $env:M365_APP_ID -CertificateThumbprint $env:CERT_THUMBPRINT
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $TenantId,
    [Parameter(Mandatory)] [string] $AppId,
    [Parameter(Mandatory)] [string] $CertificateThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot         = $PSScriptRoot | Split-Path | Split-Path
$GroupConfigPath  = Join-Path $PSScriptRoot 'security-groups.e2e.json'
$AdminConfigPath  = Join-Path $PSScriptRoot 'admin-creation.e2e.json'
$GroupResultPath  = Join-Path ([IO.Path]::GetTempPath()) "sg-e2e-result-$([guid]::NewGuid().ToString('n')).json"
$AdminResultPath  = Join-Path ([IO.Path]::GetTempPath()) "ac-e2e-result-$([guid]::NewGuid().ToString('n')).json"

$E2EPrefix = (Get-Content $AdminConfigPath -Raw | ConvertFrom-Json).NamePrefix
if (!$E2EPrefix) { throw "E2E config must set a NamePrefix — refusing to run without test isolation" }

# Mirrors $EntraRoles in entra/Admin-Creation.ps1 — role template IDs are
# fixed and identical across all tenants
$EntraRoleIds = @{
    "Global Administrator"                       = "62e90394-69f5-4237-9190-012177145e10"
    "User Administrator"                         = "fe930be7-5e62-47db-91af-98c3a49a38b1"
    "Authentication Administrator"                = "c4e39bd9-1100-46d3-8c65-fb160da0071f"
    "Exchange Administrator"                     = "29232cdf-9323-42fd-ade2-1d097af3e4de"
    "Teams Administrator"                        = "69091246-20e8-4a56-aa4d-066075b2a7a8"
    "Intune Administrator"                       = "3a2c62db-5318-420d-8d74-23affee5d9d5"
    "SharePoint Administrator"                   = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"
    "Azure AD Joined Device Local Administrator" = "9f06204d-73c1-4d4c-880a-6edb90606fd8"
}

# The four accounts Admin-Creation.ps1 creates, with expected attributes
$ExpectedAccounts = @(
    @{ Role = 'Cloud'; DisplayName = 'BITS-Admin-Cloud'; JobTitle = 'Cloud Administrator'
       EntraRoles = @('Intune Administrator', 'Azure AD Joined Device Local Administrator') },
    @{ Role = 'HD'; DisplayName = 'BITS-Admin-HD'; JobTitle = 'Helpdesk Administrator'
       EntraRoles = @('User Administrator', 'Authentication Administrator', 'Exchange Administrator', 'Teams Administrator', 'Intune Administrator', 'SharePoint Administrator') },
    @{ Role = 'BG01'; DisplayName = 'BITS-Admin-BG01'; JobTitle = 'Emergency Access Account'
       EntraRoles = @('Global Administrator') },
    @{ Role = 'BG02'; DisplayName = 'BITS-Admin-BG02'; JobTitle = 'Emergency Access Account (NoMFA)'
       EntraRoles = @('Global Administrator') }
)

$failures = 0

function Write-Result {
    param([bool]$Pass, [string]$Message)
    if ($Pass) { Write-Host "  PASS  $Message" -ForegroundColor Green }
    else       { Write-Host "  FAIL  $Message" -ForegroundColor Red; $script:failures++ }
}

function Test-EntraRoleAssignment {
    param([string]$PrincipalId, [string]$RoleName)
    $roleId = $EntraRoleIds[$RoleName]
    $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$PrincipalId' and roleDefinitionId eq '$roleId'"
    $result = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
    return @($result.value).Count -gt 0
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

# App-only contexts have no signed-in user, so $ctx.Account is empty — get the
# tenant's default verified domain the same way Admin-Creation.ps1 does
$organization = Get-MgOrganization | Select-Object -First 1
$DefaultDomain = $organization.VerifiedDomains | Where-Object { $_.IsDefault -eq $true } | Select-Object -ExpandProperty Name
if ([string]::IsNullOrEmpty($DefaultDomain)) { throw "Could not determine tenant default domain" }
Write-Host "  Default domain: $DefaultDomain" -ForegroundColor Green

try {
    # ========================================================================
    # Prerequisite: create the groups Admin-Creation depends on
    # ========================================================================
    Write-Host "`n== Creating prerequisite groups (Security-Groups.ps1) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'entra/Security-Groups.ps1') `
        -NonInteractive -ConfigFile $GroupConfigPath -ResultPath $GroupResultPath

    Write-Host "`n== Waiting 30s for directory replication ==" -ForegroundColor Cyan
    Start-Sleep -Seconds 30

    # ========================================================================
    # Execute the real script, unattended, in this session
    # ========================================================================
    Write-Host "`n== Running Admin-Creation.ps1 (non-interactive) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'entra/Admin-Creation.ps1') `
        -NonInteractive -ConfigFile $AdminConfigPath -ResultPath $AdminResultPath

    # Graph directory reads lag writes — wait before verifying anything created above
    Write-Host "`n== Waiting 30s for directory replication ==" -ForegroundColor Cyan
    Start-Sleep -Seconds 30

    # ========================================================================
    # Assert on the script's own reported results
    # ========================================================================
    Write-Host "`n== Verifying script results ==" -ForegroundColor Cyan
    if (!(Test-Path $AdminResultPath)) {
        Write-Result $false "Script produced no results file — it likely aborted early"
    }
    else {
        $result = Get-Content $AdminResultPath -Raw | ConvertFrom-Json
        Write-Result ([bool]$result.Success) "Script reported success (created: $(@($result.Created).Count), skipped: $(@($result.Skipped).Count), failed: $(@($result.Failed).Count))"
        foreach ($fail in @($result.Failed)) {
            Write-Host "        failed account: $($fail.Name) — $($fail.Error)" -ForegroundColor Red
        }
    }

    # ========================================================================
    # Independently verify tenant state via Graph
    # ========================================================================
    Write-Host "`n== Verifying created accounts and role assignments ==" -ForegroundColor Cyan
    foreach ($expected in $ExpectedAccounts) {
        $upn  = "$E2EPrefix$($expected.DisplayName)@$DefaultDomain"
        $user = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue

        if (!$user) {
            Write-Result $false "$upn exists"
            continue
        }
        Write-Result $true "$upn exists"
        Write-Result ($user.JobTitle -eq $expected.JobTitle) "$upn has JobTitle '$($expected.JobTitle)'"

        foreach ($roleName in $expected.EntraRoles) {
            Write-Result (Test-EntraRoleAssignment -PrincipalId $user.Id -RoleName $roleName) "$upn has role '$roleName'"
        }
    }

    # NoMFA Exclusion Group is Assigned/Manual (not dynamic) — its membership
    # should reflect immediately, unlike the dynamic groups
    Write-Host "`n== Verifying static group membership (NoMFA Exclusion Group) ==" -ForegroundColor Cyan
    $noMfaGroup = Get-MgGroup -Filter "displayName eq '${E2EPrefix}NoMFA Exclusion Group'" -ErrorAction SilentlyContinue
    if (!$noMfaGroup) {
        Write-Result $false "${E2EPrefix}NoMFA Exclusion Group exists"
    }
    else {
        $bg02Upn     = "$E2EPrefix$(($ExpectedAccounts | Where-Object Role -eq 'BG02').DisplayName)@$DefaultDomain"
        $bg02User    = Get-MgUser -Filter "userPrincipalName eq '$bg02Upn'" -ErrorAction SilentlyContinue
        $members     = @(Get-MgGroupMember -GroupId $noMfaGroup.Id -All -ErrorAction Stop)
        $isMember    = $bg02User -and ($members.Id -contains $bg02User.Id)
        Write-Result $isMember "BG02 is a member of ${E2EPrefix}NoMFA Exclusion Group"
    }

    # ========================================================================
    # Idempotency: a second run must skip everything and create nothing
    # ========================================================================
    Write-Host "`n== Verifying idempotency (second run skips all) ==" -ForegroundColor Cyan
    & (Join-Path $RepoRoot 'entra/Admin-Creation.ps1') `
        -NonInteractive -ConfigFile $AdminConfigPath -ResultPath $AdminResultPath

    $second = Get-Content $AdminResultPath -Raw | ConvertFrom-Json
    Write-Result ([bool]$second.Success -and @($second.Created).Count -eq 0 -and @($second.Skipped).Count -eq $ExpectedAccounts.Count) `
        "Second run created nothing and skipped all $($ExpectedAccounts.Count) accounts"
}
finally {
    # ========================================================================
    # Cleanup — always runs; deletes ONLY prefix-matched objects
    # ========================================================================
    Write-Host "`n== Cleaning up E2E accounts ==" -ForegroundColor Cyan
    try {
        $e2eUsers = @(Get-MgUser -Filter "startsWith(displayName, '$E2EPrefix')" -All -ErrorAction Stop)

        # Deleting a user who holds a directory role requires the app itself to
        # hold Global Admin/Privileged Auth Admin/User Admin — this app
        # deliberately only holds Exchange Administrator, so the delete would be
        # denied for any account still holding a role. Strip role assignments
        # from every account first (phase 1), wait for the removal to propagate
        # to the deletion-authorization check, then delete (phase 2) — the first
        # attempt at this deleted the role assignments and tried to delete the
        # user within ~150ms, which is well inside Graph's directory
        # role-enforcement propagation window and got Authorization_RequestDenied
        # for every account whose roles had just been stripped.
        function Remove-DirectoryRoleAssignments {
            param([string]$UserId, [string]$DisplayName)
            # Returns the number of assignments removed. A GET returning zero
            # here isn't proof the account is role-less — the same read-lag
            # affecting every other Graph list endpoint in this project can
            # make a just-assigned role invisible to this exact query for a
            # few seconds, so callers that need to know "truly none left"
            # should retry rather than trust a single empty result.
            $assignUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$UserId'"
            $assignments = Invoke-MgGraphRequest -Uri $assignUri -Method GET -ErrorAction Stop
            $removed = 0
            foreach ($assignment in @($assignments.value)) {
                Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/$($assignment.id)" -Method DELETE -ErrorAction Stop
                Write-Host "  Removed role assignment $($assignment.id) from $DisplayName" -ForegroundColor Gray
                $removed++
            }
            return $removed
        }

        foreach ($user in $e2eUsers) {
            try {
                $null = Remove-DirectoryRoleAssignments -UserId $user.Id -DisplayName $user.DisplayName
            }
            catch {
                Write-Host "  WARNING: could not remove role assignments for $($user.DisplayName): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }

        if ($e2eUsers.Count -gt 0) {
            Write-Host "  Waiting 30s for role-removal to propagate before deleting users..." -ForegroundColor Gray
            Start-Sleep -Seconds 30
        }

        foreach ($user in $e2eUsers) {
            $deleted = $false
            for ($attempt = 1; $attempt -le 3; $attempt++) {
                try {
                    Remove-MgUser -UserId $user.Id -Confirm:$false -ErrorAction Stop
                    Write-Host "  Deleted user $($user.DisplayName)" -ForegroundColor Gray
                    $deleted = $true
                    break
                }
                catch {
                    if ($attempt -eq 3) {
                        Write-Host "  WARNING: could not delete user $($user.DisplayName): $($_.Exception.Message)" -ForegroundColor Yellow
                        break
                    }
                    # Authorization_RequestDenied here almost always means a role
                    # assignment the first pass's GET query didn't see yet — the
                    # live run this was built against showed exactly one account
                    # out of four with zero assignments found on the first pass,
                    # still holding a role at delete time. Re-check and strip
                    # before the next attempt instead of just waiting blindly.
                    Write-Host "  Delete denied for $($user.DisplayName), rechecking role assignments (attempt $attempt/3)..." -ForegroundColor Yellow
                    try { $null = Remove-DirectoryRoleAssignments -UserId $user.Id -DisplayName $user.DisplayName } catch { }
                    Start-Sleep -Seconds 20
                }
            }
        }
        Write-Host "  Removed $($e2eUsers.Count) user(s)" -ForegroundColor Green
    }
    catch {
        Write-Host "  WARNING: user cleanup query failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Manually delete users prefixed '$E2EPrefix' in the test tenant" -ForegroundColor Yellow
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

    # The Intune Helpdesk role assignment isn't prefix-named and would
    # otherwise orphan-reference a deleted group on every scheduled run
    Write-Host "`n== Cleaning up Intune Helpdesk role assignment ==" -ForegroundColor Cyan
    try {
        $assignUri = "https://graph.microsoft.com/beta/deviceManagement/roleAssignments?`$filter=displayName eq 'Helpdesk Operator Group Assignment'"
        $existing  = Invoke-MgGraphRequest -Uri $assignUri -Method GET -ErrorAction Stop
        foreach ($assignment in @($existing.value)) {
            Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/roleAssignments/$($assignment.id)" -Method DELETE -ErrorAction Stop
            Write-Host "  Deleted role assignment $($assignment.id)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  WARNING: could not clean up Intune role assignment: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Remove-Item $GroupResultPath, $AdminResultPath -ErrorAction SilentlyContinue
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
