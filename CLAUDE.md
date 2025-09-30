# Claude Code Context for Complete-365Tenant-Creation

## Project Overview
Microsoft 365 tenant automation project with PowerShell scripts for configuring M365 services including Entra ID, Intune, Exchange Online, SharePoint, Security/Defender, and Purview compliance.

## Project Structure
```
├── Main-Menu.ps1                 # Main entry point with interactive menu system
├── entra/                        # Entra ID (Identity & Access) scripts
├── Intune/                       # Device management scripts  
├── Exchange/                     # Email & collaboration scripts
├── SharePoint/                   # File sharing & sites scripts
├── Security/                     # Threat protection scripts
├── Purview/                      # Data governance scripts
├── test-auth.ps1                 # Authentication testing utilities
├── test-simple-auth.ps1          # Simple auth test
└── STANDARDIZATION_GUIDE.md      # Guide for standardizing existing tenants
```

## Current Project Status
Based on recent commits and analysis:
- **Authentication System**: Recently fixed authentication token access issues (commit 814c86f) ✅
- **EDR Policy Tracking**: Improved to ensure manual setup isn't forgotten (commit ad87a4e) ✅
- **Compliance Policies**: Fixed Microsoft Graph SDK assignment bug with REST API workaround (commit 07759a2) ✅
- **Documentation**: Added comprehensive EDR manual setup guide to STANDARDIZATION_GUIDE.md ✅
- **Script Analysis**: Claude Code settings updated to allow `rg` commands for analysis (commit c8c333e) ✅
- **Status**: Production-ready with all known issues resolved

## Key Commands for This Project

### Testing & Analysis
```powershell
# Test authentication system
./test-auth.ps1                   # Comprehensive auth testing
./test-simple-auth.ps1            # Simple connection test

# Run main menu system
./Main-Menu.ps1                   # Interactive tenant configuration hub

# Check git status and recent changes
git status                        # Current working tree status
git log --oneline -10             # Recent commits
```

### Common Issues & Solutions
1. **Authentication Issues**: Use test-auth.ps1 to diagnose Graph connectivity
2. **Module Dependencies**: Main-Menu.ps1 auto-installs required modules
3. **Script Updates**: Scripts are downloaded from GitHub on-demand
4. **Permission Issues**: Scripts require Global Administrator access

### Development Workflow
1. Test authentication with test scripts
2. Use Main-Menu.ps1 for interactive configuration
3. Check logs and status frequently
4. Follow prerequisite chains (Security Groups → Admin Accounts → Conditional Access)

## Recent Changes (January 2025)
- **Auto-Scope Expansion**: Fixed "run twice" issue - scripts now auto-request permissions on first run
- **Compliance Policies SDK Bug Fix**: Implemented REST API workaround for Microsoft Graph SDK assignment failures
- **EDR Policy Documentation**: Added detailed manual setup guide with step-by-step instructions
- **Authentication System**: Multiple fixes for token access and multi-service authentication
- **Authentication Status Checker**: Added debug option to verify connection status across all services
- **Smart Recommendations**: Improved logic to guide users through setup workflow

## Known Issues & Limitations

### ~~First-Run Scope Issues~~ (FIXED - January 2025)
- **Previous Issue**: Scripts failed on first run, required running twice
- **Cause**: Main menu connected with basic scopes, scripts needed additional permissions
- **Solution**: Implemented auto-scope expansion in Set-ServiceScopes()
- **Status**: ✅ Fixed - Scripts now auto-request permissions on first run

### Microsoft Graph SDK Bug (2025)
- **Issue**: Compliance policy assignments fail with Invoke-MgGraphRequest
- **Solution**: Implemented REST API workaround using Invoke-RestMethod
- **Location**: Intune/Compliance-Policies.ps1 lines 227-256
- **Status**: ✅ Fixed with fallback mechanism

### EDR Policy (Manual Setup Required)
- **Issue**: EDR policies cannot be automated via Graph API
- **Solution**: Must be configured manually in Microsoft Defender portal
- **Documentation**: See STANDARDIZATION_GUIDE.md → Manual Setup Requirements
- **Tracking**: System tracks EDR status and shows 80%/20% completion split

### P2 License Detection
- **Coverage**: Detects 23+ Microsoft license SKUs
- **Note**: New license types may require periodic updates
- **Location**: Main-Menu.ps1 lines 46-134

## Maintenance Checklist
- ✅ All known bugs fixed
- ✅ Authentication system verified
- ✅ Documentation up to date
- ✅ GitHub script delivery working
- ⚠️ Monitor for new Microsoft Graph API changes
- ⚠️ Update P2 license detection as Microsoft releases new SKUs

## PowerShell Version Requirements
- Requires PowerShell 7.0+ (specified in #Requires directives)
- Uses Microsoft.Graph PowerShell modules
- Interactive menu system with arrow key navigation

## Security Context
This project creates and manages administrative configurations for Microsoft 365 tenants. All scripts are defensive in nature, focused on proper security configuration and compliance setup.