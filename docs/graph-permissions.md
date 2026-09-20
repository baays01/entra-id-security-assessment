# Microsoft Graph Permissions

## Purpose

This project uses Microsoft Graph read permissions only.

The assessment framework is designed to inventory, assess, and report Microsoft Entra ID configuration without changing tenant settings.

## Core Delegated Permissions

### RoleManagement.Read.Directory

Used for:

- ENTRA-PRIV-001 Privileged Role Inventory
- ENTRA-PRIV-002 Guest Privileged Identity Review

Purpose: Read Microsoft Entra directory role definitions and active role assignments.

### AuditLog.Read.All

Used for:

- ENTRA-AUTH-001 MFA Registration Review

Purpose: Read authentication-method registration reporting data, including user registration details.

This permission may also be required later for sign-in activity or stale-account analysis.

### Policy.Read.All

Used for:

- ENTRA-CA-001 Conditional Access Policy Inventory
- ENTRA-CA-002 Conditional Access Exclusion Review

Purpose: Read Microsoft Entra Conditional Access policy configuration.

### User.Read.All

Used for:

- ENTRA-ACCT-001 Disabled Account Inventory
- ENTRA-GUEST-001 Guest Account Inventory
- Supporting identity correlation across assessment modules

Purpose: Read user-account properties required for account status, account type, guest identity, and other assessment logic.

### Application.Read.All

Used for:

- ENTRA-APP-001 Application Registration Inventory
- ENTRA-APP-002 Application Credential Expiration Review

Purpose: Read application-registration and related application metadata.

## Optional Permissions

### IdentityRiskyUser.Read.All

Used for:

- ENTRA-RISK-001 Identity Risk Review

Purpose: Read Microsoft Entra risky-user information.

This assessment remains disabled by default because availability depends on tenant licensing and permissions.

### IdentityRiskEvent.Read.All

Reserved for a future risk-detection assessment module.

Purpose: Read identity-risk detection information.

## Permission Philosophy

- Use delegated read-only scopes during interactive assessment development.
- Request only the permissions needed by enabled modules.
- Do not request Directory.ReadWrite.All.
- Do not request RoleManagement.ReadWrite.Directory.
- Do not request Policy.ReadWrite.ConditionalAccess.
- Do not request Application.ReadWrite.All.
- Do not request IdentityRiskyUser.ReadWrite.All.
- Do not store access tokens or refresh tokens in repository files.
- Do not commit tenant IDs, user data, policy exports, or production assessment reports.

## Role and Consent Considerations

Graph scopes alone may not be sufficient for every delegated operation.

Microsoft Entra role requirements can also apply to the signed-in user. For example, role-management and security-reporting APIs may require an appropriate directory role such as Global Reader, Security Reader, Reports Reader, or another supported least-privilege role.

Admin consent may also be required for some delegated scopes depending on Microsoft Graph permission requirements and tenant policy.

## Initial Development Scope Set

The planned initial interactive connection will use:

- RoleManagement.Read.Directory
- AuditLog.Read.All
- Policy.Read.All
- User.Read.All
- Application.Read.All

IdentityRiskyUser.Read.All will remain optional and will not be requested in the baseline connection.

## Safety Boundary

This repository is an assessment toolkit, not an automated remediation toolkit.

No write permissions are required for the current design.
