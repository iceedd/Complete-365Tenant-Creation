# Complete-365Tenant-Creation

An interactive PowerShell hub for automating full Microsoft 365 tenant configuration. The entry point is `Main-Menu.ps1`, which presents an arrow-key driven menu, handles authentication against Microsoft Graph and related services, and downloads sub-scripts from GitHub on demand as they are needed.

---

## Prerequisites

| Requirement | Details |
|---|---|
| PowerShell | 7.0 or later |
| M365 account | Global Administrator |
| Microsoft.Graph SDK | Auto-installed on first run |
| Microsoft.Online.SharePoint.PowerShell | Required for SharePoint scripts only |

---

## Quick Start

```powershell
git clone https://github.com/cbro09/Complete-365Tenant-Creation.git
cd Complete-365Tenant-Creation
pwsh -File Main-Menu.ps1
```

From the menu, select **option 8 (Connect to Tenant)** before running any configuration scripts. This establishes the Microsoft Graph session and installs any missing modules automatically.

---

## Project Structure

```
Complete-365Tenant-Creation/
├── Main-Menu.ps1                   # Entry point — interactive menu and auth
├── Shared/
│   └── ScriptHelpers.ps1           # Shared helper library, dot-sourced by all scripts
├── entra/
│   ├── Security-Groups.ps1
│   ├── Admin-Creation.ps1
│   ├── CA-Policies.ps1
│   ├── Password-Policies.ps1
│   └── User-Creation.ps1
├── Intune/
│   ├── Device-Groups.ps1
│   ├── Configuration-Policies.ps1
│   ├── Compliance-Policies.ps1
│   ├── App-Deployment.ps1
│   ├── Autopilot-Config.ps1
│   └── WAU-Deployment.ps1
├── Exchange/
│   ├── Shared-MB-Creation.ps1
│   ├── Archive-Policies.ps1
│   ├── Mail-Flow-Rules.ps1
│   └── Distribution-Lists.ps1
├── Security/
│   ├── Anti-Phishing.ps1
│   ├── Safe-Attachments.ps1
│   └── Web-Filtering.ps1
├── SharePoint/
│   └── External-Sharing.ps1
├── Purview/
│   ├── Retention-Policies.ps1
│   ├── DLP-Policies.ps1
│   └── Sensitivity-Labels.ps1
├── Tests/
│   └── Integration/                # Auth test scripts
├── Build/
│   └── Build.ps1                   # Local lint runner
└── .github/
    └── workflows/
        └── ci.yml                  # CI pipeline (PSScriptAnalyzer)
```

---

## Module Overview

| Module | Scripts | Purpose |
|---|---|---|
| **Entra ID** | Security-Groups, Admin-Creation, CA-Policies, Password-Policies, User-Creation | Identity, access control, and conditional access |
| **Intune** | Device-Groups, Configuration-Policies, Compliance-Policies, App-Deployment, Autopilot-Config, WAU-Deployment | Device management and endpoint configuration |
| **Exchange** | Shared-MB-Creation, Archive-Policies, Mail-Flow-Rules, Distribution-Lists | Email infrastructure and routing |
| **Security** | Anti-Phishing, Safe-Attachments, Web-Filtering | Defender for Office 365 threat protection |
| **SharePoint** | External-Sharing | External collaboration settings |
| **Purview** | Retention-Policies, DLP-Policies, Sensitivity-Labels | Compliance and data governance |

---

## Recommended Execution Order

Run scripts in this sequence to satisfy dependency chains. Conditional Access requires groups to exist; compliance policies require device groups; and so on.

1. Security Groups (`entra/Security-Groups.ps1`)
2. Admin Accounts (`entra/Admin-Creation.ps1`)
3. Device Groups (`Intune/Device-Groups.ps1`)
4. Conditional Access Policies (`entra/CA-Policies.ps1`) — enable in pilot/report-only mode first
5. Configuration Policies (`Intune/Configuration-Policies.ps1`)
6. Compliance Policies (`Intune/Compliance-Policies.ps1`)
7. EDR Policy — **manual step**, see Known Limitations below
8. Exchange (`Exchange/`)
9. Security (`Security/`)
10. SharePoint and Purview (`SharePoint/`, `Purview/`)

---

## Known Limitations

**EDR Policy (manual configuration required)**
Microsoft Graph API does not expose endpoints for creating Endpoint Detection and Response policies. This step must be completed manually in the Microsoft Defender portal. The menu tracks EDR status and reflects it in the overall completion percentage.

**SharePoint authentication**
SharePoint scripts require a separate `Connect-SPOService` connection in addition to the Microsoft Graph session. The main auth flow does not establish this automatically.

**SharePoint scripts not yet implemented**
`Permission-Groups.ps1` and `Site-Creation.ps1` are planned but not yet available. The menu entries for these are placeholders.

**Script delivery from main branch**
`Main-Menu.ps1` downloads sub-scripts from the `main` branch on GitHub at runtime. Scripts are not bundled locally in the repository.

---

## Development

### Running Lint Locally

```powershell
./Build/Build.ps1
```

This runs PSScriptAnalyzer against the project using the settings defined in `PSScriptAnalyzerSettings.psd1`. Fix all errors and warnings before opening a pull request.

### CI

PSScriptAnalyzer runs automatically on every push and pull request to `main` via `.github/workflows/ci.yml`.

### Contributing

1. Branch off `main`.
2. Make changes and run `./Build/Build.ps1` locally to verify no lint issues.
3. Open a pull request back to `main`.
4. CI must pass before merging.
