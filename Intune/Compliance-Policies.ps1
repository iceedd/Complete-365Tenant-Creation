#Requires -Version 7.0

<#
.SYNOPSIS
    Creates comprehensive Intune compliance policies with device group assignments
.DESCRIPTION
    Creates 4 platform-specific compliance policies using exported settings data.
    Includes password/passcode requirements, encryption enforcement, OS version compliance,
    and security baseline settings for Android, iOS, macOS, and Windows devices.
.AUTHOR
    CB & Claude Partnership
.VERSION
    1.0
#>

# Required Modules
$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.DeviceManagement',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Identity.DirectoryManagement'
)

# Policy assignment configuration - maps to our dynamic device groups
function Get-PolicyAssignments {
    return @{
        "Android Basic Compliance" = @("Android Devices", "Corporate Owned Devices")
        "iOS Basic Compliance" = @("iOS Devices", "Corporate Owned Devices") 
        "macOS Basic Compliance" = @("macOS Devices", "Corporate Owned Devices")
        "Windows 10/11 Basic Compliance" = @("Windows Devices (Autopilot)", "Corporate Owned Devices")
    }
}

# Auto-install and import required modules
function Initialize-Modules {
    Write-Host "🔧 Checking required modules..." -ForegroundColor Yellow
    
    try {
        foreach ($Module in $RequiredModules) {
            try {
                if (!(Get-Module -ListAvailable -Name $Module)) {
                    Write-Host "Installing $Module..." -ForegroundColor Yellow
                    Install-Module $Module -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
                }
                if (!(Get-Module -Name $Module)) {
                    Write-Host "Importing $Module..." -ForegroundColor Yellow
                    Import-Module $Module -Force -ErrorAction Stop
                }
                Write-Host "✅ $Module ready!" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to initialize $Module : $($_.Exception.Message)"
                return $false
            }
        }
        Write-Host "✅ All modules ready!" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Module initialization error: $($_.Exception.Message)"
        return $false
    }
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
            OrganizationName = $org.DisplayName
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

# Load compliance policy definitions from GitHub or local fallback
function Get-PolicyDefinitions {
    try {
        Write-Host "  🔍 Attempting to load compliance policy definitions..." -ForegroundColor Gray
        
        # Method 1: Try GitHub download first (most reliable for hub system)
        try {
            Write-Host "  🌐 Downloading compliance policies from GitHub..." -ForegroundColor Cyan
            # Ensure TLS 1.2 is used for SSL connections
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $url = "https://raw.githubusercontent.com/$Global:GitHubRepo/$Global:GitHubBranch/Intune/CompliancePolicies_Complete.json"
            $jsonContent = Invoke-RestMethod -Uri $url -ErrorAction Stop
            
            # Convert to hashtable if it's not already
            if ($jsonContent -is [string]) {
                $jsonContent = $jsonContent | ConvertFrom-Json -AsHashtable
            } elseif ($jsonContent -is [array] -or $jsonContent -is [PSCustomObject]) {
                $jsonContent = $jsonContent | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable
            }
            
            Write-Host "  ✅ Successfully downloaded $($jsonContent.Count) compliance policies from GitHub" -ForegroundColor Green
            return $jsonContent
        }
        catch {
            Write-Host "  ⚠️ GitHub download failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        # Method 2: Try local file locations (fallback)
        $possiblePaths = @(
            ".\CompliancePolicies_Complete.json",
            ".\Intune\CompliancePolicies_Complete.json",
            "Intune\CompliancePolicies_Complete.json",
            "$PWD\CompliancePolicies_Complete.json",
            "$PWD\Intune\CompliancePolicies_Complete.json"
        )
        
        # Only try local paths if we have a valid script path
        if ($MyInvocation.ScriptName -and $MyInvocation.ScriptName.Trim() -ne "") {
            $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
            if ($scriptDir -and $scriptDir.Trim() -ne "") {
                $possiblePaths += Join-Path $scriptDir "CompliancePolicies_Complete.json"
            }
        }
        
        Write-Host "  🔍 Checking local file paths..." -ForegroundColor Gray
        foreach ($path in $possiblePaths) {
            if ($path -and (Test-Path $path -ErrorAction SilentlyContinue)) {
                Write-Host "  📁 Loading policies from local file: $path" -ForegroundColor Gray
                $jsonContent = Get-Content $path -Raw | ConvertFrom-Json -AsHashtable
                Write-Host "  ✅ Loaded $($jsonContent.Count) compliance policies from local file" -ForegroundColor Green
                return $jsonContent
            } else {
                Write-Host "  ❌ Not found: $path" -ForegroundColor DarkGray
            }
        }
        
        throw "Unable to load compliance policies from GitHub or local files"
    }
    catch {
        Write-Error "Failed to load compliance policy definitions: $($_.Exception.Message)"
        Write-Host "  💡 Troubleshooting:" -ForegroundColor Yellow
        Write-Host "    - Check internet connection for GitHub download" -ForegroundColor Gray
        Write-Host "    - Verify GitHub repository URL is correct" -ForegroundColor Gray
        Write-Host "    - Ensure CompliancePolicies_Complete.json exists in repository" -ForegroundColor Gray
        return @()
    }
}

# Create compliance policy with assignments
function New-CompliancePolicy {
    param(
        [hashtable]$PolicyDefinition,
        [hashtable]$TenantInfo,
        [string[]]$DeviceGroupIds = @()
    )
    
    try {
        # Check if policy already exists
        $existingPolicy = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies" -Method GET | 
            Select-Object -ExpandProperty value | Where-Object { $_.displayName -eq $PolicyDefinition.displayName }
        
        if ($existingPolicy) {
            Write-Host "⚠️  Policy '$($PolicyDefinition.displayName)' already exists" -ForegroundColor Yellow
            return $existingPolicy
        }
        
        # Clean the policy definition for creation (remove system fields)
        $cleanPolicy = $PolicyDefinition.Clone()
        $fieldsToRemove = @('id', 'createdDateTime', 'lastModifiedDateTime', 'version', '@odata.context', '@odata.type')
        foreach ($field in $fieldsToRemove) {
            if ($cleanPolicy.ContainsKey($field)) {
                $cleanPolicy.Remove($field)
            }
        }
        
        # Add the OData type back for proper policy creation
        $cleanPolicy.'@odata.type' = $PolicyDefinition.'@odata.type'
        
        # Create the policy
        $newPolicy = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies" -Method POST -Body ($cleanPolicy | ConvertTo-Json -Depth 20)
        
        Write-Host "✅ Created: $($PolicyDefinition.displayName)" -ForegroundColor Green
        Write-Host "   Policy ID: $($newPolicy.id)" -ForegroundColor Gray
        Write-Host "   Platform: $($PolicyDefinition.'@odata.type' -replace '#microsoft.graph.', '' -replace 'CompliancePolicy', '')" -ForegroundColor Gray
        
        # Assign to device groups
        if ($DeviceGroupIds.Count -gt 0) {
            $assignmentBody = @{
                deviceCompliancePolicyAssignments = @()
            }
            
            foreach ($groupId in $DeviceGroupIds) {
                if ($groupId) {
                    $assignmentBody.deviceCompliancePolicyAssignments += @{
                        target = @{
                            "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                            groupId = $groupId
                        }
                    }
                }
            }
            
            if ($assignmentBody.deviceCompliancePolicyAssignments.Count -gt 0) {
                Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$($newPolicy.id)')/assign" -Method POST -Body ($assignmentBody | ConvertTo-Json -Depth 10)
                Write-Host "   Assigned to $($assignmentBody.deviceCompliancePolicyAssignments.Count) device groups" -ForegroundColor Gray
            }
        }
        
        return $newPolicy
    }
    catch {
        Write-Error "❌ Failed to create compliance policy '$($PolicyDefinition.displayName)': $($_.Exception.Message)"
        Write-Host "   Error details: $($_.Exception.Response.Content.ReadAsStringAsync().Result)" -ForegroundColor Red
        return $null
    }
}

# Main execution function
function Start-CompliancePolicyCreation {
    Write-Host "`n🚀 Creating Intune Compliance Policies..." -ForegroundColor Cyan
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
    Write-Host "   Organization: $($tenantInfo.OrganizationName)" -ForegroundColor Gray
    
    # Get policy definitions
    $policies = Get-PolicyDefinitions
    $assignments = Get-PolicyAssignments
    
    Write-Host "`n📋 Found $($policies.Count) compliance policy definitions" -ForegroundColor Yellow
    
    if ($policies.Count -eq 0) {
        Write-Error "❌ No compliance policies found to deploy"
        return
    }
    
    # Show policy summary
    Write-Host "`n📱 Compliance Policies to Deploy:" -ForegroundColor Cyan
    foreach ($policy in $policies) {
        $platform = $policy.'@odata.type' -replace '#microsoft.graph.', '' -replace 'CompliancePolicy', ''
        Write-Host "   • $($policy.displayName) ($platform)" -ForegroundColor White
    }
    
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
    
    # User confirmation
    Write-Host "`n📋 Deployment Summary:" -ForegroundColor Yellow
    Write-Host "   📱 Compliance policies: $($policies.Count)" -ForegroundColor White
    Write-Host "   🎯 Device groups: $($groupCache.Keys.Count)" -ForegroundColor White
    Write-Host "   🏢 Target tenant: $($tenantInfo.OrganizationName)" -ForegroundColor White
    
    $confirm = Read-Host "`nProceed with compliance policy deployment? (Y/n)"
    if ($confirm -like "n*") {
        Write-Host "❌ Deployment cancelled by user" -ForegroundColor Yellow
        return
    }
    
    # Create policies
    Write-Host "`n🛡️ Creating compliance policies..." -ForegroundColor Yellow
    $createdPolicies = @()
    $failedPolicies = @()
    
    foreach ($policy in $policies) {
        Write-Host "`n📋 Creating: $($policy.displayName)" -ForegroundColor White
        
        # Get device group IDs for this policy
        $deviceGroupIds = @()
        if ($assignments.ContainsKey($policy.displayName)) {
            foreach ($groupName in $assignments[$policy.displayName]) {
                $groupId = $groupCache[$groupName]
                if ($groupId) {
                    $deviceGroupIds += $groupId
                }
            }
        }
        
        $result = New-CompliancePolicy -PolicyDefinition $policy -TenantInfo $tenantInfo -DeviceGroupIds $deviceGroupIds
        
        if ($result) {
            $createdPolicies += $result
        } else {
            $failedPolicies += $policy.displayName
        }
        
        # Small delay to avoid throttling
        Start-Sleep -Milliseconds 500
    }
    
    # Summary
    Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
    Write-Host "📊 DEPLOYMENT SUMMARY" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host "✅ Successfully created: $($createdPolicies.Count) policies" -ForegroundColor Green
    
    if ($failedPolicies.Count -gt 0) {
        Write-Host "❌ Failed to create: $($failedPolicies.Count) policies" -ForegroundColor Red
        foreach ($failed in $failedPolicies) {
            Write-Host "   - $failed" -ForegroundColor Red
        }
    }
    
    Write-Host "`n💡 Next Steps:" -ForegroundColor Yellow
    Write-Host "   1. Verify policies in Intune admin center" -ForegroundColor Gray
    Write-Host "   2. Check policy assignments to device groups" -ForegroundColor Gray
    Write-Host "   3. Monitor device compliance reporting" -ForegroundColor Gray
    Write-Host "   4. Test compliance evaluation on pilot devices" -ForegroundColor Gray
    
    Write-Host "`n🔒 Key Compliance Requirements Applied:" -ForegroundColor Yellow
    Write-Host "   - Device encryption mandatory (BitLocker, FileVault)" -ForegroundColor Gray  
    Write-Host "   - Strong password/passcode policies (6-8+ characters)" -ForegroundColor Gray
    Write-Host "   - 15-minute inactivity timeouts" -ForegroundColor Gray
    Write-Host "   - 90-day password expiration cycles" -ForegroundColor Gray
    Write-Host "   - Jailbreak/root detection for mobile devices" -ForegroundColor Gray
    Write-Host "   - Minimum OS version enforcement" -ForegroundColor Gray
    
    return $createdPolicies
}

# Initialize and run
try {
    Initialize-Modules
    $results = Start-CompliancePolicyCreation
    
    if ($results) {
        Write-Host "`n🎉 Compliance policy creation completed!" -ForegroundColor Green
        Write-Host "🛡️ Created $($results.Count) compliance policies with device assignments" -ForegroundColor Green
    }
}
catch {
    Write-Error "❌ Script execution failed: $($_.Exception.Message)"
}

# ▼ CB & Claude | BITS 365 Automation | v1.0 | "Smarter not Harder"
