#Requires -Version 7.0

<#
.SYNOPSIS
    User Creation & Management — redirects to M365-UserProvisioning-Tool
.DESCRIPTION
    This stub is shown when an outdated Main-Menu.ps1 is running.
    The provisioning tool is integrated directly in Main-Menu.ps1 v1.2+.
.AUTHOR
    CB & Claude Partnership
.VERSION
    2.1 - Update notice
#>

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  USER CREATION & MANAGEMENT" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host ""
Write-Host "  Your Main-Menu.ps1 is out of date." -ForegroundColor Yellow
Write-Host "  User Creation is now built in to Main-Menu.ps1 v1.2+." -ForegroundColor White
Write-Host ""
Write-Host "  To update, run this in PowerShell:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Invoke-RestMethod 'https://raw.githubusercontent.com/cbro09/Complete-365Tenant-Creation/main/Main-Menu.ps1' | Out-File Main-Menu.ps1 -Encoding UTF8" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Then re-run .\Main-Menu.ps1" -ForegroundColor White
Write-Host ""
Write-Host "  Press any key to return to menu..." -ForegroundColor Gray
try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Start-Sleep -Seconds 3 }
