# Standardizing Existing Microsoft 365 Tenants to Project Defaults

## Overview

This guide outlines the process for standardizing existing Microsoft 365 tenants using the defaults and configurations defined in the Complete-365Tenant-Creation project. The automation scripts can be adapted to audit existing configurations and apply standardized settings where feasible.

## Project Default Standards

### Entra ID (Identity & Access Management)
- **Security Groups**: Dynamic and static groups for licensing, MFA exclusions, and admin management
- **Admin Accounts**: BITS-Admin-* prefixed accounts with proper break-glass access
- **Conditional Access**: 5-policy framework (C001-C005) with risk-based controls
- **Password Policies**: Enhanced password complexity and lifecycle management

### Intune (Device Management)
- **Device Groups**: OS-based categorization (Windows, macOS, iOS, Android)
- **Configuration Policies**: 18 standardized policies including Defender, BitLocker, Office settings
- **Compliance Policies**: Platform-specific compliance requirements
- **Application Deployment**: Managed app distribution with proper targeting

### Exchange Online
- **Shared Mailboxes**: Standardized naming and permission structures
- **Archive Policies**: Automated retention and archiving rules
- **Mail Flow Rules**: Security-focused transport rules
- **Distribution Lists**: Organized communication groups

### Security & Defender
- **Safe Attachments**: ATP protection for email attachments
- **Anti-Phishing**: Advanced threat protection policies
- **Web Filtering**: Content filtering and URL protection

### SharePoint Online
- **Site Collections**: Standardized site structures and permissions
- **External Sharing**: Controlled sharing policies
- **Permission Groups**: Consistent access control frameworks

### Purview Compliance
- **Retention Policies**: Data lifecycle management
- **DLP Policies**: Data loss prevention controls
- **Sensitivity Labels**: Information classification system

## Standardization Approach

### Phase 1: Discovery & Assessment
1. **Tenant Analysis**
   - Run assessment scripts to inventory existing configurations
   - Compare current state against project defaults
   - Identify gaps and conflicts

2. **Risk Assessment**
   - Evaluate impact of proposed changes
   - Document potential service disruptions
   - Plan rollback procedures

### Phase 2: Prerequisites & Foundation
1. **Security Groups** (Always First)
   - Create missing security groups
   - Migrate existing groups to dynamic membership rules where appropriate
   - Ensure proper group nesting and permissions

2. **Admin Accounts**
   - Audit existing admin accounts
   - Create standardized BITS-Admin-* accounts if needed
   - Configure proper break-glass procedures

### Phase 3: Core Services Standardization

#### Entra ID Standardization
- **Conditional Access Policies**
  - Audit existing CA policies
  - Disable Security Defaults if still enabled
  - Implement 5-policy framework with proper exclusions
  - Test with pilot groups before full deployment

- **Password Policies**
  - Update password complexity requirements
  - Configure self-service password reset (SSPR)
  - Implement authentication methods

#### Intune Standardization
- **Device Management**
  - Create standardized device groups
  - Apply 18 configuration policies to appropriate groups
  - Implement compliance policies per platform
  - Configure Autopilot for new device provisioning

#### Exchange Online Standardization
- **Email Security**
  - Implement shared mailbox naming conventions
  - Configure archive policies for data retention
  - Deploy mail flow rules for security

#### Security Standardization
- **Microsoft Defender**
  - Configure Safe Attachments policies
  - Implement anti-phishing protection
  - Set up web content filtering

## Scope Considerations & Limitations

### What Can Be Standardized
✅ **Security Groups**: Can be created/modified without disruption
✅ **Conditional Access**: Can be implemented alongside existing policies
✅ **Device Configuration**: Can be applied to specific groups
✅ **Email Settings**: Most settings can be updated safely
✅ **Compliance Policies**: Can be phased in gradually

### What Requires Careful Planning
⚠️ **Existing User Accounts**: May conflict with new admin account naming
⚠️ **Current CA Policies**: May need modification rather than replacement
⚠️ **Device Compliance**: Could impact currently non-compliant devices
⚠️ **Mail Flow Changes**: Could affect existing mail routing
⚠️ **SharePoint Permissions**: May disrupt existing access patterns

### What Cannot Be Easily Standardized
❌ **User Principal Names**: Existing users cannot be easily renamed
❌ **Historical Data**: Cannot retroactively apply new retention policies
❌ **Third-party Integrations**: May not work with standardized settings
❌ **Custom Applications**: May require specific configurations

## Implementation Strategy

### 1. Pilot Group Approach
- Start with a small pilot group (5-10% of users)
- Apply all standardizations to pilot group first
- Monitor for issues before broader deployment
- Use feedback to refine standardization process

### 2. Phased Rollout
1. **Week 1-2**: Security Groups and Admin Accounts
2. **Week 3-4**: Conditional Access (pilot group only)
3. **Week 5-6**: Device Management (pilot devices)
4. **Week 7-8**: Exchange and Security policies
5. **Week 9-10**: Full deployment with monitoring

### 3. Prerequisites for Standardization
- **Global Administrator** access to all services
- **Change management** approval for security policy changes
- **Communication plan** for end users
- **Rollback procedures** documented and tested
- **Backup/export** of existing configurations

## Recommended Execution Order

1. **Security Groups Creation** (`entra/Security-Groups.ps1`)
2. **Admin Account Standardization** (`entra/Admin-Creation.ps1`)
3. **Device Group Setup** (`Intune/Device-Groups.ps1`)
4. **Conditional Access Policies** (`entra/CA-Policies.ps1`) - Pilot First
5. **Device Configuration Policies** (`Intune/Configuration-Policies.ps1`)
6. **Compliance Policies** (`Intune/Compliance-Policies.ps1`)
7. **Exchange Configuration** (`Exchange/*` scripts)
8. **Security Policies** (`Security/*` scripts)
9. **SharePoint and Purview** (as business requirements allow)

## Monitoring and Validation

### Post-Implementation Monitoring
- **Sign-in Logs**: Monitor Conditional Access policy impacts
- **Compliance Reports**: Track device compliance improvements
- **Security Alerts**: Watch for policy-related security events
- **User Feedback**: Collect and address user experience issues

### Success Metrics
- Reduction in risky sign-ins
- Improved device compliance rates
- Standardized group membership patterns
- Consistent policy enforcement across tenant

## Rollback Procedures

### Quick Rollback Options
1. **Conditional Access**: Disable policies, re-enable Security Defaults
2. **Device Policies**: Remove policy assignments from groups
3. **Group Changes**: Restore from exported group configurations
4. **Exchange Settings**: Revert transport rules and policies

### Documentation Requirements
- Export all existing configurations before changes
- Document every change made during standardization
- Maintain change log with timestamps and responsible parties
- Keep rollback scripts ready for each service area

## Best Practices

### Before Starting
- Export current tenant configuration
- Create comprehensive change management plan
- Establish communication channels with stakeholders
- Prepare support resources for end users

### During Implementation
- Monitor closely for unexpected impacts
- Communicate progress regularly
- Be prepared to pause/rollback if issues arise
- Document lessons learned for future implementations

### After Completion
- Conduct post-implementation review
- Update documentation with actual vs. planned changes
- Establish ongoing maintenance procedures
- Plan regular compliance reviews

---

**Note**: This standardization process should be thoroughly tested in a development/test tenant before applying to production environments. The scope of changes possible depends heavily on the current state of the tenant and organizational requirements.