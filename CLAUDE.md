# Claude Code Context for Complete-365Tenant-Creation

## Project Overview
Microsoft 365 tenant automation project with PowerShell scripts for configuring M365 services including Entra ID, Intune, Exchange Online, SharePoint, Security/Defender, and Purview compliance.

## Project Structure
```
├── Main-Menu.ps1                   # Main entry point with interactive menu system
├── entra/                          # Entra ID (Identity & Access) scripts
├── Intune/                         # Device management scripts (+ policy JSON, ADMX)
├── Exchange/                       # Email & collaboration scripts
├── SharePoint/                     # File sharing & sites scripts
├── Security/                       # Threat protection scripts
├── Purview/                        # Data governance scripts
├── Shared/ScriptHelpers.ps1        # Shared helper functions (logging, retry, scopes)
├── Build/Build.ps1                 # Local PSScriptAnalyzer lint runner
├── Tests/Unit/                     # Pester unit tests (ScriptHelpers coverage)
├── Tests/Integration/              # Manual auth tests (test-auth.ps1, test-simple-auth.ps1)
├── Tests/Smoke/                    # App-only live API smoke test (runs in CI)
├── .github/workflows/ci.yml        # Lint + unit tests (push to main/dev/feature/claude, PRs)
├── .github/workflows/smoke-test.yml # Live test-tenant smoke test (PRs to main)
└── Docs/STANDARDIZATION_GUIDE.md   # Guide for standardizing existing tenants
```

## How Scripts Are Delivered
- `Main-Menu.ps1` self-updates from GitHub `main` on startup (version compared via `.VERSION` header) and relaunches automatically when newer.
- Sub-scripts are downloaded from GitHub `main` at runtime by `Invoke-GitHubScript` and cached **in memory for the session only** (menu option 9 clears the cache mid-session).
- Consequence: fixes only reach users once merged to `main`.

## CI / Verification
- **ci.yml**: PSScriptAnalyzer (windows-latest, settings in `PSScriptAnalyzerSettings.psd1`) + Pester unit tests (ubuntu). Triggers: push to `main`/`dev`/`feature/**`/`claude/**`, PRs to `main`.
- **smoke-test.yml**: on PRs to `main`, connects to a dedicated test tenant with certificate-based app-only auth (M365_* repository secrets) on windows-latest and exercises the read-only API surface the scripts depend on (Graph, Exchange Online, Intune, SharePoint, IPPS). It does NOT execute the interactive scripts themselves.
- Local lint: `./Build/Build.ps1` (installs PSScriptAnalyzer if needed).

## Key Commands
```powershell
./Main-Menu.ps1                          # Interactive tenant configuration hub
./Build/Build.ps1                        # Lint all scripts locally
./Tests/Integration/test-auth.ps1        # Manual comprehensive auth test (real tenant)
./Tests/Integration/test-simple-auth.ps1 # Manual simple connection test
```

### Common Issues & Solutions
1. **Authentication Issues**: Use Tests/Integration/test-auth.ps1 to diagnose Graph connectivity
2. **Module Dependencies**: Main-Menu.ps1 auto-installs required modules
3. **WAM broker crash** (`NullReferenceException` in `RuntimeBroker`): Connect-ExchangeOnline / Connect-IPPSSession conflict with Connect-MgGraph in the same session. Fixed by `-DisableWAM`, which requires ExchangeOnlineManagement **3.7.2+** (version-guarded in Main-Menu.ps1 and Purview/Retention-Policies.ps1)
4. **Permission Issues**: Scripts require Global Administrator access (delegated) — CI smoke tests use app-only permissions instead

### Development Workflow
1. Branch, edit, lint locally (`./Build/Build.ps1`)
2. Push — CI lints on `claude/**`/`feature/**` branches
3. PR to `main` — lint + unit tests + live smoke test must pass
4. Merge — fixes go live immediately (runtime script delivery from `main`)
5. Follow prerequisite chains (Security Groups → Admin Accounts → Conditional Access)

## Known Issues & Limitations

### Placeholder Scripts (COMING SOON)
Five menu options are placeholders that print manual-setup guidance and exit
(marked "(COMING SOON)" in the menus): Purview DLP-Policies, Purview
Sensitivity-Labels, Intune App-Deployment, Intune Autopilot-Config, Exchange
Mail-Flow-Rules.

### Interactive-Only Scripts
Sub-scripts use Read-Host prompts and cannot run unattended, so CI smoke tests
cover the API surface, not script logic end-to-end. A non-interactive mode
(-ConfigFile / -NonInteractive) is planned to enable full E2E testing against
the test tenant.

### ExchangeOnlineManagement 3.10.0 Regression (Connect-IPPSSession)
- **Issue**: ExchangeOnlineManagement 3.10.0 has a regression where
  `Connect-IPPSSession` with certificate-based app-only auth crashes with
  `Object reference not set to an instance of an object` inside its
  internal `NewEXOModule.ProcessRecord()`, even with fully correct Entra
  role assignments (Compliance Administrator) — confirmed live by decoding
  the actual access token's `wids` claim, which correctly contained the
  role, yet the connection still failed on 3.10.0. The identical call
  succeeds on 3.9.0.
- **Solution**: CI workflows (`e2e-test.yml`, `smoke-test.yml`) pin
  `Install-Module ExchangeOnlineManagement -RequiredVersion 3.9.0` (an
  exact version, not `-MinimumVersion`) until Microsoft fixes the
  regression in a later release.
- **Status**: Workaround in place. Re-test with a newer module version
  periodically and lift the pin once `Connect-IPPSSession` app-only auth
  is confirmed fixed.

### Microsoft Graph SDK Bug (2025)
- **Issue**: Compliance policy assignments fail via the SDK cmdlets
- **Solution**: REST/Invoke-MgGraphRequest workaround in Intune/Compliance-Policies.ps1
- **Status**: ✅ Fixed with fallback mechanism

### EDR Policy (Manual Setup Required)
- **Issue**: EDR policies cannot be automated via Graph API
- **Solution**: Must be configured manually in Microsoft Defender portal
- **Documentation**: See Docs/STANDARDIZATION_GUIDE.md → Manual Setup Requirements
- **Tracking**: System tracks EDR status and shows 80%/20% completion split

### Web Content Filtering (Manual Setup Required)
- **Issue**: Defender for Endpoint's "Web content filtering" feature has no Microsoft Graph API at all — confirmed live (the tenant's Settings Catalog has no matching `device_vendor_msft_defender_configuration_webcontentfiltering_*` setting IDs, only unrelated Microsoft Edge browser policy settings under a similar name) and via Microsoft Learn (every doc for this feature says to use the Defender portal wizard exclusively)
- **Solution**: Security/Web-Filtering.ps1 detects this and always falls back to manual setup instructions (security.microsoft.com > Settings > Endpoints > Web content filtering) rather than attempting a POST that can never succeed
- **Status**: This is a permanent Microsoft platform limitation, not a stale/fixable setting ID

### P2 License Detection
- **Coverage**: Detects 23+ Microsoft license SKUs in Main-Menu.ps1 (Test-EntraP2License)
- **Note**: New license types may require periodic updates

### Beta Graph Endpoints
Intune scripts (and some Entra role/licensing calls) use `graph.microsoft.com/beta`,
which Microsoft can change without notice. Some calls have v1.0 equivalents and
should migrate over time.

## Maintenance Checklist
- ⚠️ Monitor for new Microsoft Graph API changes (beta endpoints especially)
- ⚠️ Update P2 license detection as Microsoft releases new SKUs
- ⚠️ Renew the smoke-test certificate yearly (Claude-SmokeTest app registration)
- ⚠️ Keep ExchangeOnlineManagement minimum version guards in sync with module releases

## PowerShell Version Requirements
- Requires PowerShell 7.0+ (specified in #Requires directives)
- Uses Microsoft.Graph PowerShell modules
- ExchangeOnlineManagement 3.7.2+ (for -DisableWAM)
- Interactive menu system with arrow key navigation

## Security Context
This project creates and manages administrative configurations for Microsoft 365 tenants. All scripts are defensive in nature, focused on proper security configuration and compliance setup. CI smoke tests run against a dedicated test tenant only — never a production tenant.
