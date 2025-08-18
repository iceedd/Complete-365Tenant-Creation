#Requires -Version 7.0

Write-Host "🔧 Simple Authentication Test" -ForegroundColor Cyan

# Test simplified connection
try {
    Write-Host "Testing basic Graph connection..." -ForegroundColor Yellow
    
    # Import required modules
    Import-Module Microsoft.Graph.Authentication -Force
    Import-Module Microsoft.Graph.Identity.DirectoryManagement -Force
    
    # Basic connection test
    Connect-MgGraph -Scopes "Organization.Read.All" -NoWelcome
    
    $context = Get-MgContext
    if ($context) {
        Write-Host "✅ Connection successful!" -ForegroundColor Green
        Write-Host "   Account: $($context.Account)" -ForegroundColor Gray
        Write-Host "   Tenant: $($context.TenantId)" -ForegroundColor Gray
        
        # Quick test
        $org = Get-MgOrganization | Select-Object -First 1
        Write-Host "   Organization: $($org.DisplayName)" -ForegroundColor Gray
        
        Disconnect-MgGraph
        Write-Host "✅ Test completed successfully!" -ForegroundColor Green
    } else {
        Write-Host "❌ No context returned" -ForegroundColor Red
    }
    
} catch {
    Write-Host "❌ Error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "Test finished." -ForegroundColor Cyan