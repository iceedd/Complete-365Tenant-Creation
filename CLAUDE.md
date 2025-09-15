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
- **Authentication System**: Recently fixed authentication token access issues (commit 814c86f)
- **EDR Policy Tracking**: Improved to ensure manual setup isn't forgotten (commit ad87a4e)
- **Script Analysis**: Claude Code settings updated to allow `rg` commands for analysis (commit c8c333e)
- **Status**: Project appears stable with recent authentication and tracking improvements

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

## Recent Changes to Monitor
- Distribution Lists script authentication fixes
- EDR Policy manual setup tracking improvements  
- Authentication status checker enhancements
- Smart recommendations logic updates

## Next Recommended Tasks
1. **Test Authentication**: Run authentication tests to ensure recent fixes work
2. **EDR Policy Review**: Check if EDR policy implementation needs attention
3. **Script Analysis**: Review individual scripts for potential improvements
4. **Documentation**: Update any outdated comments or documentation

## PowerShell Version Requirements
- Requires PowerShell 7.0+ (specified in #Requires directives)
- Uses Microsoft.Graph PowerShell modules
- Interactive menu system with arrow key navigation

## Security Context
This project creates and manages administrative configurations for Microsoft 365 tenants. All scripts are defensive in nature, focused on proper security configuration and compliance setup.