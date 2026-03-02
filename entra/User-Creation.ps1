#Requires -Version 7.0

<#
.SYNOPSIS
    Creates user accounts in Entra ID
.DESCRIPTION
    Bulk user creation with license assignment and group membership.
    COMING SOON - This feature is under development.
.AUTHOR
    CB & Claude Partnership
.VERSION
    2.0 - Placeholder
#>

function Start-UserCreation {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  USER CREATION" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Status: COMING SOON" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  This feature is currently under development." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Planned Features:" -ForegroundColor White
    Write-Host "    - Single user creation wizard" -ForegroundColor Gray
    Write-Host "    - Bulk user import from CSV" -ForegroundColor Gray
    Write-Host "    - Automatic license assignment" -ForegroundColor Gray
    Write-Host "    - Group membership assignment" -ForegroundColor Gray
    Write-Host "    - Welcome email generation" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  For now, create users manually:" -ForegroundColor Yellow
    Write-Host "    https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
    try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 2 }
}

Start-UserCreation
