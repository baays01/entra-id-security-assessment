# Microsoft Entra ID Security Assessment

Read-only PowerShell security assessment framework for Microsoft Entra ID identity posture, privileged access, authentication, Conditional Access, external identities, application registrations, and credential lifecycle.

The current baseline runs completely offline against fictional data so the assessment logic can be developed, tested, and demonstrated safely before live Microsoft Graph integration is introduced.

## Project Goals

- Demonstrate structured Microsoft Entra ID security assessment methodology
- Use least-privilege, read-only assessment principles
- Separate data collection from security evaluation
- Produce repeatable and evidence-based findings
- Generate structured CSV and JSON reports
- Prevent production tenant data from entering the public repository
- Provide sanitized examples suitable for a public technical portfolio

## Current Capabilities

The assessment framework currently implements controlled behavior for 10 security rules across seven Microsoft Entra ID assessment domains.

| Rule | Assessment | Current Baseline Behavior |
| --- | --- | --- |
| ENTRA-PRIV-001 | Privileged Role Inventory | INFORMATIONAL |
| ENTRA-PRIV-002 | Guest Privileged Identity Review | REVIEW when guest privileged assignments exist |
| ENTRA-AUTH-001 | MFA Registration Review | REVIEW when enabled identities are not MFA registered |
| ENTRA-CA-001 | Conditional Access Policy Inventory | INFORMATIONAL |
| ENTRA-CA-002 | Conditional Access Exclusion Review | REVIEW for exclusions in enabled or report-only policies |
| ENTRA-ACCT-001 | Disabled Account Inventory | INFORMATIONAL |
| ENTRA-GUEST-001 | Guest Account Inventory | INFORMATIONAL |
| ENTRA-APP-001 | Application Registration Inventory | INFORMATIONAL |
| ENTRA-APP-002 | Application Credential Expiration Review | WARNING for expired or soon-to-expire credentials |
| ENTRA-RISK-001 | Identity Risk Review | NOT ASSESSED by default |

## Assessment Architecture

The project separates collection, normalization, assessment, configuration, and reporting.

```text
Fictional / Authorized Input Data
            |
            v
     Inventory Collectors
            |
            v
     Normalized Objects
            |
            v
      Assessment Rules
            |
            v
    Consolidated Findings
            |
            +----> CSV
            |
            +----> JSON
```

This separation makes it possible to replace the current offline JSON collectors with Microsoft Graph collectors later without redesigning the assessment logic.

## Repository Structure

```text
entra-id-security-assessment/
|
|-- config/
|   `-- assessment-rules.json
|
|-- docs/
|   |-- assessment-methodology.md
|   |-- graph-permissions.md
|   `-- output-safety.md
|
|-- examples/
|   |-- sample-input/
|   `-- sample-output/
|
|-- src/
|   |-- Get-EntraApplicationInventory.ps1
|   |-- Get-EntraAuthenticationRegistrationInventory.ps1
|   |-- Get-EntraConditionalAccessInventory.ps1
|   |-- Get-EntraPrivilegedRoleInventory.ps1
|   |-- Get-EntraUserInventory.ps1
|   |-- Invoke-EntraAccountAssessment.ps1
|   |-- Invoke-EntraApplicationAssessment.ps1
|   |-- Invoke-EntraAuthenticationAssessment.ps1
|   |-- Invoke-EntraConditionalAccessAssessment.ps1
|   |-- Invoke-EntraIdentityRiskAssessment.ps1
|   |-- Invoke-EntraPrivilegedRoleAssessment.ps1
|   `-- Invoke-EntraSecurityAssessment.ps1
|
|-- .gitignore
`-- README.md
```

## Master Assessment Runner

The primary entry point is:

```powershell
.\src\Invoke-EntraSecurityAssessment.ps1
```

The master runner:

1. Loads the assessment rule configuration.
2. Executes all implemented assessment modules.
3. Verifies that every configured rule returns exactly one result.
4. Normalizes findings into a common reporting structure.
5. Generates consolidated CSV and JSON reports.
6. Returns an assessment summary object to PowerShell.

Example:

```powershell
$Assessment = .\src\Invoke-EntraSecurityAssessment.ps1

$Assessment.Findings |
    Format-Table RuleId,FindingName,Status,RecordCount,PopulationCount -AutoSize

$Assessment.StatusSummary |
    Format-List
```

## Current Fictional Baseline

The bundled sample data intentionally contains several security conditions so assessment logic can be demonstrated.

Examples include:

- A guest identity holding a privileged Microsoft Entra role
- An enabled user who is not registered for MFA
- Conditional Access exclusions requiring administrator validation
- A report-only administrator authentication-strength policy
- A disabled Conditional Access policy
- A Microsoft Entra application with no listed owner
- An expired application credential
- An application credential expiring within the configured warning period
- An optional identity-risk domain that correctly reports NOT ASSESSED

The sample findings are not intended to represent a real organization.

## Example Baseline Results

The current fictional dataset produces:

```text
Total Findings:  10
PASS:             0
REVIEW:           3
WARNING:          1
INFORMATIONAL:    5
NOT ASSESSED:     1
```

These values are deterministic for the included fictional sample dataset and are used to validate the assessment engine.

## Finding Classifications

| Status | Meaning |
| --- | --- |
| PASS | Expected control or condition was observed |
| REVIEW | Administrator or contextual validation is required |
| WARNING | A security condition should be investigated |
| INFORMATIONAL | Inventory or contextual information |
| NOT ASSESSED | Required data, permission, licensing, or capability was unavailable |

The framework deliberately avoids treating every observation as a vulnerability. For example, Conditional Access exclusions are reported for review because exclusions can be legitimate when properly governed.

## Application Credential Assessment

Application credential evaluation supports both password credentials and certificate credentials.

The fictional application dataset contains a fixed reference date and warning threshold so test results remain repeatable over time.

Credential states include:

- Valid
- Expiring Soon
- Expired

## Microsoft Graph Direction

The current implementation does not authenticate to a live Microsoft Entra tenant.

Future live collection is designed around Microsoft Graph read-only permissions such as:

- RoleManagement.Read.Directory
- AuditLog.Read.All
- Policy.Read.All
- User.Read.All
- Application.Read.All

Optional Identity Protection assessment may require:

- IdentityRiskyUser.Read.All
- IdentityRiskEvent.Read.All

See `docs/graph-permissions.md` for the documented permissions model.

## Security and Privacy

This is a public repository.

Real tenant data must not be committed.

The repository includes safeguards for excluding common local output locations, credential artifacts, token files, environment files, private keys, logs, and temporary files.

Publishable demonstration data is limited to:

```text
examples/sample-input/
examples/sample-output/
```

Those directories must contain only fictional or thoroughly sanitized information.

Real assessment output should be written to ignored local directories such as:

```text
reports/
output/
exports/
assessment-output/
tenant-data/
live-data/
private-data/
```

See `docs/output-safety.md` for the full public-repository safety model.

## Assessment Philosophy

This project separates assessment from remediation.

The framework inventories and evaluates security posture but does not automatically change Microsoft Entra ID configuration.

Potential remediation should be reviewed for business impact, dependencies, exclusions, rollback requirements, and organizational change-control requirements before implementation.

## Requirements

Current offline baseline:

- Windows PowerShell 5.1 or PowerShell 7+
- No Microsoft Graph connection required
- No tenant credentials required
- No production Microsoft Entra ID environment required

Future live-tenant collection will introduce Microsoft Graph PowerShell dependencies separately.

## Documentation

- `docs/assessment-methodology.md` describes the assessment domains and methodology.
- `docs/graph-permissions.md` documents the planned least-privilege Microsoft Graph permission model.
- `docs/output-safety.md` defines public-repository data-handling and publication safeguards.

## Project Status

Current phase: offline assessment engine complete for the initial 10-rule baseline.

Planned development includes live Microsoft Graph collectors, additional validation tests, richer reporting, configurable thresholds, and expanded identity-security assessment modules.

## Author

**Adebayo Ayorinde**

Systems Administration | Cloud | Cybersecurity | PowerShell Automation

GitHub: https://github.com/baays01

LinkedIn: https://www.linkedin.com/in/adebayo-ayorinde-91b79a354

## Disclaimer

This project is intended for authorized security assessment, administrative learning, lab use, and professional portfolio demonstration.

Only assess Microsoft Entra ID environments for which you have appropriate authorization.
