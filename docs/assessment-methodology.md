# Microsoft Entra ID Security Assessment Methodology

## Purpose

This project provides a read-only security assessment framework for reviewing Microsoft Entra ID identity posture, administrative access, authentication controls, Conditional Access coverage, external identities, application identities, and account hygiene.

The toolkit is designed for lab, demonstration, and authorized assessment use.

## Design Principles

- Read-only by default
- Least-privilege access
- No configuration changes
- No password or secret collection
- No token storage in repository files
- Sanitized reporting
- Clear separation between findings and remediation
- Evidence-based assessment results

## Assessment Domains

### 1. Privileged Role Exposure

Review privileged directory-role assignments and identify accounts with elevated administrative access.

Assessment considerations include:

- Number of privileged identities
- Permanent versus eligible assignments where available
- Highly privileged directory roles
- Privileged accounts that also appear to be normal day-to-day user accounts
- Unexpected guest or external privileged identities

### 2. Authentication and MFA Posture

Assess available authentication-registration information and identify accounts that may require further review.

Assessment considerations include:

- MFA registration posture
- Authentication-method registration
- Administrative accounts requiring stronger authentication review
- Accounts with incomplete authentication-registration information

### 3. Conditional Access

Review Conditional Access policy configuration and coverage without modifying policies.

Assessment considerations include:

- Enabled policies
- Report-only policies
- Disabled policies
- User and group targeting
- Application targeting
- Grant controls
- Authentication-strength requirements where available
- Policy exclusions requiring review

### 4. Account Hygiene

Review user-account posture for indicators requiring administrative review.

Assessment considerations include:

- Enabled and disabled accounts
- Guest accounts
- Accounts with incomplete identity information
- Potentially stale accounts when activity data is available
- Administrative accounts
- Unusual account classifications

### 5. External Identities

Review guest and external-user presence.

Assessment considerations include:

- Guest-account inventory
- External identities with privileged access
- External identities requiring ownership review
- Long-lived guest accounts when activity information is available

### 6. Application and Service Principal Posture

Review application registrations and enterprise application identities where authorized.

Assessment considerations include:

- Application inventory
- Service-principal inventory
- Credential-expiration metadata
- High-privilege application permissions requiring review
- Application ownership information
- Orphaned or poorly documented application identities

### 7. Identity Risk Indicators

Where licensing, permissions, and tenant capabilities permit, optionally review identity-risk information.

This domain remains optional so the core toolkit does not depend on premium licensing.

## Finding Classification

Assessment results should use the following classifications:

- PASS: Expected control or condition was observed
- REVIEW: Requires administrator validation or contextual review
- WARNING: Security condition should be investigated
- INFORMATIONAL: Inventory or contextual information
- NOT ASSESSED: Required data, permission, licensing, or capability was unavailable

## Evidence Handling

Assessment output may contain sensitive identity and configuration information.

Real tenant reports must not be committed to this public repository.

Only fictional or sanitized sample data may be stored under examples/sample-output.

## Permissions Model

The assessment will use Microsoft Graph read permissions only.

Required permissions will be documented per assessment module before implementation. The toolkit will avoid write permissions unless a separate future remediation component is explicitly designed and documented.

## Remediation Philosophy

This project reports security observations but does not automatically change tenant configuration.

Remediation guidance will be documented separately so administrators can review business impact, dependencies, exclusions, rollback requirements, and change-control requirements before making changes.

## Current Project Status

Phase 1: Assessment framework and read-only methodology.

PowerShell and Microsoft Graph assessment modules will be added incrementally and validated using sanitized or lab data.
