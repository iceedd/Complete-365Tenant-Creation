#Requires -Version 7.0

<#
.SYNOPSIS
    Creates comprehensive Intune configuration policies with full settings
.DESCRIPTION
    Creates 18 production-ready configuration policies using exported settings data
.AUTHOR
    CB & Claude Partnership
.VERSION
    1.1
#>

# Required Modules
$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.DeviceManagement',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Identity.DirectoryManagement'
)

# Policy assignment configuration
function Get-PolicyAssignments {
    return @{
        "Default Web Pages" = @("Windows Devices (Autopilot)")
        "Defender Configuration" = @("Windows Devices (Autopilot)")
        "Disable UAC for Quickassist" = @("Windows Devices (Autopilot)")
        "Edge Update Policy" = @("Windows Devices (Autopilot)")
        "EDR Policy" = @("Windows Devices (Autopilot)")
        "Enable Bitlocker" = @("Windows Devices (Autopilot)")
        "Enable Built-in Administrator Account" = @("Windows Devices (Autopilot)")
        "LAPS" = @("Windows Devices (Autopilot)")
        "Office Updates Configuration" = @("Windows Devices (Autopilot)")
        "OneDrive Configuration" = @("Windows Devices (Autopilot)")
        "Outlook Configuration" = @("Windows Devices (Autopilot)")
        "Power Options" = @("Windows Devices (Autopilot)")
        "Prevent Users From Unenrolling Devices" = @("Windows Devices (Autopilot)", "Corporate Owned Devices")
        "Sharepoint File Sync" = @("Windows Devices (Autopilot)")
        "System Services" = @("Windows Devices (Autopilot)")
        "Tamper Protection" = @("Windows Devices (Autopilot)")
        "Web Sign-in Policy" = @("Windows Devices (Autopilot)")
        "NGP Windows Default Policy" = @("Windows Devices (Autopilot)", "Corporate Owned Devices")
    }
}

# Auto-install and import required modules
function Initialize-Modules {
    Write-Host "🔧 Checking required modules..." -ForegroundColor Yellow
    
    foreach ($Module in $RequiredModules) {
        if (!(Get-Module -ListAvailable -Name $Module)) {
            Write-Host "Installing $Module..." -ForegroundColor Yellow
            Install-Module $Module -Force -Scope CurrentUser -AllowClobber
        }
        if (!(Get-Module -Name $Module)) {
            Write-Host "Importing $Module..." -ForegroundColor Yellow
            Import-Module $Module -Force
        }
    }
    Write-Host "✅ Modules ready!" -ForegroundColor Green
}

# Get tenant information for dynamic substitution
function Get-TenantInfo {
    try {
        $org = Get-MgOrganization | Select-Object -First 1
        $domain = $org.VerifiedDomains | Where-Object { $_.IsDefault -eq $true } | Select-Object -ExpandProperty Name
        $tenantName = ($domain -split '\.')[0]
        
        return @{
            TenantId = $org.Id
            Domain = $domain
            TenantName = $tenantName
            SharePointUrl = "https://$tenantName.sharepoint.com/"
        }
    }
    catch {
        Write-Error "Failed to get tenant info: $($_.Exception.Message)"
        return $null
    }
}

# Get device group ID by name
function Get-DeviceGroupId {
    param([string]$GroupName)
    
    try {
        $group = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction Stop
        if ($group) {
            return $group.Id
        } else {
            Write-Warning "Device group '$GroupName' not found"
            return $null
        }
    }
    catch {
        Write-Error "Failed to resolve group '$GroupName': $($_.Exception.Message)"
        return $null
    }
}

# Substitute dynamic values in policy settings
function Update-PolicyDynamicValues {
    param(
        [hashtable]$Policy,
        [hashtable]$TenantInfo,
        [string]$LapsAdminName = "Localadmin"
    )
    
    # Convert policy to JSON for easier string replacement
    $policyJson = $Policy | ConvertTo-Json -Depth 20
    
    # Replace SharePoint URLs
    $policyJson = $policyJson -replace "https://contoso\.sharepoint\.com/", $TenantInfo.SharePointUrl
    
    # Replace LAPS admin names
    $policyJson = $policyJson -replace '"Localadmin"', "`"$LapsAdminName`""
    
    # Replace tenant ID placeholders (if any)
    $policyJson = $policyJson -replace 'tenantId=', "tenantId=$($TenantInfo.TenantId)"
    
    # Convert back to hashtable
    return $policyJson | ConvertFrom-Json -AsHashtable
}

# Policy definitions loading function
function Get-PolicyDefinitions {
    try {
        Write-Host "  🔍 Attempting to load policy definitions..." -ForegroundColor Gray
        
        # Method 1: Try GitHub download first (most reliable for your hub system)
        try {
            Write-Host "  🌐 Downloading policies from GitHub..." -ForegroundColor Cyan
            # Ensure TLS 1.2 is used for SSL connections
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $url = "https://raw.githubusercontent.com/$Global:GitHubRepo/$Global:GitHubBranch/Intune/AllPolicies_Complete.json"
            $jsonContent = Invoke-RestMethod -Uri $url -ErrorAction Stop
            
            # Convert to hashtable if it's not already
            if ($jsonContent -is [string]) {
                $jsonContent = $jsonContent | ConvertFrom-Json -AsHashtable
            } elseif ($jsonContent -is [array] -or $jsonContent -is [PSCustomObject]) {
                $jsonContent = $jsonContent | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable
            }
            
            Write-Host "  ✅ Successfully downloaded $($jsonContent.Count) policies from GitHub" -ForegroundColor Green
            return $jsonContent
        }
        catch {
            Write-Host "  ⚠️ GitHub download failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        # Method 2: Try local file locations (fallback)
        $possiblePaths = @(
            ".\AllPolicies_Complete.json",
            ".\Intune\AllPolicies_Complete.json",
            "$PWD\AllPolicies_Complete.json"
        )
        
        # Only try local paths if we have a valid script path
        if ($MyInvocation.ScriptName -and $MyInvocation.ScriptName.Trim() -ne "") {
            $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
            if ($scriptDir -and $scriptDir.Trim() -ne "") {
                $possiblePaths += Join-Path $scriptDir "AllPolicies_Complete.json"
            }
        }
        
        foreach ($path in $possiblePaths) {
            if ($path -and (Test-Path $path -ErrorAction SilentlyContinue)) {
                Write-Host "  📁 Loading policies from local file: $path" -ForegroundColor Gray
                $jsonContent = Get-Content $path -Raw | ConvertFrom-Json -AsHashtable
                Write-Host "  ✅ Loaded $($jsonContent.Count) policies from local file" -ForegroundColor Green
                return $jsonContent
            }
        }
        
        throw "Unable to load policies from GitHub or local files"
    }
    catch {
        Write-Error "Failed to load policy definitions: $($_.Exception.Message)"
        Write-Host "  💡 Troubleshooting:" -ForegroundColor Yellow
        Write-Host "    - Check internet connection for GitHub download" -ForegroundColor Gray
        Write-Host "    - Verify GitHub repository URL is correct" -ForegroundColor Gray
        Write-Host "    - Ensure AllPolicies_Complete.json exists in repository" -ForegroundColor Gray
        return @()
    }
}

# Create configuration policy with assignments
function New-ConfigurationPolicy {
    param(
        [hashtable]$PolicyDefinition,
        [hashtable]$TenantInfo,
        [string]$LapsAdminName,
        [string[]]$DeviceGroupIds = @()
    )
    
    try {
        # Check if policy already exists
        $existingPolicy = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -Method GET | 
            Select-Object -ExpandProperty value | Where-Object { $_.name -eq $PolicyDefinition.name }
        
        if ($existingPolicy) {
            Write-Host "⚠️  Policy '$($PolicyDefinition.name)' already exists" -ForegroundColor Yellow
            return $existingPolicy
        }
        
        # Update dynamic values
        $updatedPolicy = Update-PolicyDynamicValues -Policy $PolicyDefinition -TenantInfo $TenantInfo -LapsAdminName $LapsAdminName
        
        # Create the policy
        $newPolicy = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -Method POST -Body ($updatedPolicy | ConvertTo-Json -Depth 20)
        
        Write-Host "✅ Created: $($PolicyDefinition.name)" -ForegroundColor Green
        Write-Host "   Policy ID: $($newPolicy.id)" -ForegroundColor Gray
        Write-Host "   Settings: $($updatedPolicy.settings.Count)" -ForegroundColor Gray
        
        # Assign to device groups
        if ($DeviceGroupIds.Count -gt 0) {
            $assignmentBody = @{
                assignments = @()
            }
            
            foreach ($groupId in $DeviceGroupIds) {
                if ($groupId) {
                    $assignmentBody.assignments += @{
                        target = @{
                            "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                            groupId = $groupId
                        }
                    }
                }
            }
            
            if ($assignmentBody.assignments.Count -gt 0) {
                Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($newPolicy.id)')/assign" -Method POST -Body ($assignmentBody | ConvertTo-Json -Depth 10)
                Write-Host "   Assigned to $($assignmentBody.assignments.Count) device groups" -ForegroundColor Gray
            }
        }
        
        return $newPolicy
    }
    catch {
        Write-Error "❌ Failed to create policy '$($PolicyDefinition.name)': $($_.Exception.Message)"
        return $null
    }
}

# Main execution function
function Start-ConfigurationPolicyCreation {
    Write-Host "`n🚀 Creating Intune Configuration Policies..." -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    
    # Verify connection
    $context = Get-MgContext
    if (!$context) {
        Write-Error "❌ Not connected to Microsoft Graph. Please connect first."
        return
    }
    
    # Get tenant information
    $tenantInfo = Get-TenantInfo
    if (!$tenantInfo) {
        Write-Error "❌ Failed to get tenant information"
        return
    }
    
    Write-Host "✅ Connected to: $($tenantInfo.Domain)" -ForegroundColor Green
    Write-Host "   SharePoint URL: $($tenantInfo.SharePointUrl)" -ForegroundColor Gray
    
    # Get LAPS admin name from user
    $lapsAdminName = Read-Host "Enter LAPS local admin name (default: Localadmin)"
    if ([string]::IsNullOrWhiteSpace($lapsAdminName)) {
        $lapsAdminName = "Localadmin"
    }
    
    # Get policy definitions
    $policies = Get-PolicyDefinitions
    $assignments = Get-PolicyAssignments
    
    Write-Host "`n📋 Found $($policies.Count) policy definitions" -ForegroundColor Yellow
    
    # Resolve device group IDs
    Write-Host "`n🔍 Resolving device groups..." -ForegroundColor Yellow
    $groupCache = @{}
    
    foreach ($assignment in $assignments.GetEnumerator()) {
        foreach ($groupName in $assignment.Value) {
            if (!$groupCache.ContainsKey($groupName)) {
                $groupId = Get-DeviceGroupId -GroupName $groupName
                $groupCache[$groupName] = $groupId
                if ($groupId) {
                    Write-Host "   ✅ $groupName" -ForegroundColor Green
                } else {
                    Write-Host "   ⚠️  $groupName (not found)" -ForegroundColor Yellow
                }
            }
        }
    }
    
    # Create policies
    Write-Host "`n⚙️  Creating configuration policies..." -ForegroundColor Yellow
    $createdPolicies = @()
    $failedPolicies = @()
    
    foreach ($policy in $policies) {
        Write-Host "`n📋 Creating: $($policy.name)" -ForegroundColor White
        
        # Get device group IDs for this policy
        $deviceGroupIds = @()
        if ($assignments.ContainsKey($policy.name)) {
            foreach ($groupName in $assignments[$policy.name]) {
                $groupId = $groupCache[$groupName]
                if ($groupId) {
                    $deviceGroupIds += $groupId
                }
            }
        }
        
        $result = New-ConfigurationPolicy -PolicyDefinition $policy -TenantInfo $tenantInfo -LapsAdminName $lapsAdminName -DeviceGroupIds $deviceGroupIds
        
        if ($result) {
            $createdPolicies += $result
        } else {
            $failedPolicies += $policy.name
        }
        
        # Small delay to avoid throttling
        Start-Sleep -Milliseconds 500
    }
    
    # Summary
    Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
    Write-Host "📊 SUMMARY" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host "✅ Successfully created: $($createdPolicies.Count) policies" -ForegroundColor Green
    
    if ($failedPolicies.Count -gt 0) {
        Write-Host "❌ Failed to create: $($failedPolicies.Count) policies" -ForegroundColor Red
        foreach ($failed in $failedPolicies) {
            Write-Host "   - $failed" -ForegroundColor Red
        }
        if ($failedPolicies -contains "EDR Policy") {
            Write-Host "`n⚠️  MANUAL ACTION REQUIRED FOR EDR POLICY:" -ForegroundColor Yellow
            Write-Host "   1. Go to: Intune Admin Center → Endpoint Security → Microsoft Defender for Endpoint" -ForegroundColor White
            Write-Host "   2. Click: 'Connect Microsoft Defender for Endpoint to Microsoft Intune'" -ForegroundColor White  
            Write-Host "   3. Complete setup in Defender Security Center" -ForegroundColor White
            Write-Host "   4. Re-run this script to create EDR policy" -ForegroundColor White
            Write-Host "💡 This is a one-time setup requirement" -ForegroundColor Gray
        }
    }
    
    Write-Host "`n💡 Next Steps:" -ForegroundColor Yellow
    Write-Host "   1. Verify policies in Intune admin center" -ForegroundColor Gray
    Write-Host "   2. Check policy assignments to device groups" -ForegroundColor Gray
    Write-Host "   3. Monitor policy deployment status" -ForegroundColor Gray
    Write-Host "   4. Test on pilot devices before full rollout" -ForegroundColor Gray
    
    Write-Host "`n🔧 Key Configurations Applied:" -ForegroundColor Yellow
    Write-Host "   - BitLocker encryption with 30-day LAPS rotation" -ForegroundColor Gray
    Write-Host "   - OneDrive Known Folder Move" -ForegroundColor Gray  
    Write-Host "   - Edge browser policies with SharePoint homepage" -ForegroundColor Gray
    Write-Host "   - Defender and EDR configurations" -ForegroundColor Gray
    Write-Host "   - Power management and system services" -ForegroundColor Gray
    
    return $createdPolicies
}

# Initialize and run
try {
    Initialize-Modules
    $results = Start-ConfigurationPolicyCreation
    
    if ($results) {
        Write-Host "`n🎉 Configuration policy creation completed!" -ForegroundColor Green
        Write-Host "📋 Created $($results.Count) policies with full settings" -ForegroundColor Green
    }
}
catch {
    Write-Error "❌ Script execution failed: $($_.Exception.Message)"
}

# ▼ CB & Claude | BITS 365 Automation | v1.0 | "Smarter not Harder"