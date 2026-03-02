#Requires -Version 7.0

Write-Host "🧪 Testing Authentication System..." -ForegroundColor Cyan

# Test 1: Check if Microsoft Graph modules are available
Write-Host "`n1. Testing Microsoft Graph modules..." -ForegroundColor Yellow
try {
    $modules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Identity.DirectoryManagement')
    foreach ($module in $modules) {
        if (Get-Module -ListAvailable -Name $module) {
            Write-Host "✅ $module is available" -ForegroundColor Green
        } else {
            Write-Host "❌ $module is NOT available" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "❌ Error checking modules: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 2: Try basic connection
Write-Host "`n2. Testing basic Graph connection..." -ForegroundColor Yellow
try {
    Import-Module Microsoft.Graph.Authentication -Force
    
    # Test basic scopes
    $basicScopes = @("Organization.Read.All")
    Write-Host "Attempting connection with basic scopes..." -ForegroundColor Gray
    
    Connect-MgGraph -Scopes $basicScopes -NoWelcome
    
    $context = Get-MgContext
    if ($context) {
        Write-Host "✅ Basic connection successful!" -ForegroundColor Green
        Write-Host "   Account: $($context.Account)" -ForegroundColor Gray
        Write-Host "   Tenant ID: $($context.TenantId)" -ForegroundColor Gray
        Write-Host "   Scopes: $($context.Scopes -join ', ')" -ForegroundColor Gray
        
        # Test getting organization info
        try {
            Import-Module Microsoft.Graph.Identity.DirectoryManagement -Force
            $org = Get-MgOrganization | Select-Object -First 1
            Write-Host "✅ Organization query successful: $($org.DisplayName)" -ForegroundColor Green
        } catch {
            Write-Host "❌ Organization query failed: $($_.Exception.Message)" -ForegroundColor Red
        }
        
    } else {
        Write-Host "❌ Connection failed - no context returned" -ForegroundColor Red
    }
    
} catch {
    Write-Host "❌ Connection error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 3: Try scope expansion
Write-Host "`n3. Testing scope expansion..." -ForegroundColor Yellow
try {
    $context = Get-MgContext
    if ($context) {
        $currentScopes = $context.Scopes
        $additionalScopes = @("User.Read.All", "Group.Read.All")
        
        Write-Host "Current scopes: $($currentScopes.Count)" -ForegroundColor Gray
        Write-Host "Adding scopes: $($additionalScopes -join ', ')" -ForegroundColor Gray
        
        $allScopes = @($currentScopes) + @($additionalScopes) | Sort-Object -Unique
        
        Connect-MgGraph -Scopes $allScopes -NoWelcome
        
        $newContext = Get-MgContext
        Write-Host "✅ Scope expansion successful!" -ForegroundColor Green
        Write-Host "   New scope count: $($newContext.Scopes.Count)" -ForegroundColor Gray
    } else {
        Write-Host "⚠️ No existing context for scope expansion test" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ Scope expansion error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 4: Cleanup
Write-Host "`n4. Cleanup..." -ForegroundColor Yellow
try {
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    Write-Host "✅ Disconnected successfully" -ForegroundColor Green
} catch {
    Write-Host "❌ Disconnect error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n🧪 Authentication test complete!" -ForegroundColor Cyan