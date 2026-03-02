#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Local lint runner for Complete-365Tenant-Creation.

.DESCRIPTION
    Runs PSScriptAnalyzer across all PowerShell scripts in the repo.
    Run this before pushing to catch style/quality issues early.

.PARAMETER Severity
    Minimum severity to report. Default: Warning (also catches Errors).

.EXAMPLE
    ./Build/Build.ps1
    ./Build/Build.ps1 -Severity Error
#>

[CmdletBinding()]
param (
    [ValidateSet('Error', 'Warning', 'Information')]
    [string] $Severity = 'Warning'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = $PSScriptRoot | Split-Path

# Folders that contain scripts to lint (excludes Tests — those are analysed too but separately)
$SourceFolders = @(
    $RepoRoot,
    "$RepoRoot\entra",
    "$RepoRoot\Exchange",
    "$RepoRoot\Intune",
    "$RepoRoot\Purview",
    "$RepoRoot\Security",
    "$RepoRoot\Shared",
    "$RepoRoot\SharePoint"
)

Write-Host "`n==> PSScriptAnalyzer" -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) {
    Write-Host "Installing PSScriptAnalyzer..." -ForegroundColor Yellow
    Install-Module PSScriptAnalyzer -Scope CurrentUser -Force
}

$SettingsFile = Join-Path $RepoRoot 'PSScriptAnalyzerSettings.psd1'
$allResults = @()

foreach ($folder in $SourceFolders) {
    if (Test-Path $folder) {
        $analyzerParams = @{
            Path          = $folder
            Severity      = $Severity
            ErrorAction   = 'SilentlyContinue'
        }
        if (Test-Path $SettingsFile) {
            $analyzerParams['Settings'] = $SettingsFile
        }
        $results = Invoke-ScriptAnalyzer @analyzerParams
        $allResults += $results
    }
}

if ($allResults.Count -gt 0) {
    $allResults | Format-Table ScriptName, Line, Severity, RuleName, Message -AutoSize
    Write-Host "$($allResults.Count) issue(s) found." -ForegroundColor Red
    exit 1
}

Write-Host "No issues found." -ForegroundColor Green
