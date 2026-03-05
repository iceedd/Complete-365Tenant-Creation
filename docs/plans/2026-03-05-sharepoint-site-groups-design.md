# SharePoint Site Groups Design
Date: 2026-03-05

## Overview

New script `SharePoint/Site-Groups.ps1` that creates three Entra security groups per
SharePoint site and assigns them with appropriate permissions. Works for both new and
existing sites.

## Goals

- Create `SPO-<SiteName>-Owners`, `SPO-<SiteName>-Members`, `SPO-<SiteName>-Guests`
  Entra security groups for each site
- Assign groups to the site via Graph API (Owners = Full Control, Members = Edit, Guests = Read)
- Support two modes: create a new site first, or target existing sites
- Optionally override per-site external sharing
- Confirm/set site collection admin
- Groups created empty (members added separately via User Provisioning Tool)

## Modules Required

- `Microsoft.Online.SharePoint.PowerShell` — site creation, external sharing per site
- `Microsoft.Graph.Authentication` + `Microsoft.Graph.Groups` + `Microsoft.Graph.Sites`
  — Entra group creation, Graph site permission assignment

## Flow

```
Step 1: Prerequisites
  - Verify SPO connection (Get-SPOTenant)
  - Verify Graph connection (Get-MgContext)
  - Detect tenant root URL

Step 2: Mode selection
  A. New site  — enter site details (title, type, alias, owner, description)
  B. Existing  — discover all sites OR enter specific URL(s)

Step 3: Site creation (Mode A only)
  - New-SPOSite with Team or Communication template
  - Skip if URL already exists

Step 4: Group definitions preview
  - Show table: site → 3 group names → permission level
  - Confirm before creating

Step 5: Create Entra security groups
  - New-MgGroup (SecurityEnabled=$true, MailEnabled=$false)
  - Skip (warn) if group with that name already exists
  - Name format: SPO-<SiteAlias>-Owners / Members / Guests

Step 6: Assign groups to site via Graph API
  - GET /v1.0/sites?search=<alias> to resolve siteId
  - POST /v1.0/sites/{siteId}/permissions per group
    - Owners  → roles: ["owner"]
    - Members → roles: ["write"]
    - Guests  → roles: ["read"]

Step 7: Per-site external sharing (optional, ask per site)
  - Set-SPOSite -SharingCapability <level>
  - Options: Disabled / ExistingExternalUserSharingOnly /
    ExternalUserSharingOnly / ExternalUserAndGuestSharing

Step 8: Site collection admin confirmation
  - Show current admin(s) via Get-SPOSite
  - Optionally set/add via Set-SPOSite -Owner or Set-SPOUser

Step 9: Summary
  - Sites created / skipped
  - Groups created / skipped
  - Permissions assigned / failed
  - Sharing overrides applied
```

## Group Naming

`SPO-<SiteAlias>-Owners` where `<SiteAlias>` is the URL slug, sanitised to
alphanumeric + hyphens, max 40 chars. Example:

| Site Title       | URL Alias     | Groups Created                          |
|------------------|---------------|-----------------------------------------|
| Marketing Team   | marketing     | SPO-marketing-Owners/Members/Guests     |
| HR Policies      | hr-policies   | SPO-hr-policies-Owners/Members/Guests   |

## Error Handling

- Site already exists → skip creation, continue to group step
- Group already exists → skip creation, log warning, still attempt assignment
- Graph permission assignment fails → log error, continue to next site
- SPO sharing override fails → log error, continue

## Out of Scope

- Adding members to groups (handled by User Provisioning Tool)
- Subsites or hub site association
- Site template customisation beyond Team/Communication
