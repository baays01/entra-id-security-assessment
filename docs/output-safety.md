# Assessment Output Safety

## Purpose

This repository is public. Assessment output generated from a real Microsoft Entra ID tenant may contain sensitive identity, security, configuration, application, and access-control information.

Real tenant assessment output must not be committed to this repository.

## Safe to Publish

The following repository locations are intentionally designed for fictional or sanitized demonstration data:

- examples/sample-input/
- examples/sample-output/

Files committed to these directories must contain only fictional, synthetic, or thoroughly sanitized information.

Current sample data uses fictional identities, fictional GUIDs, and the reserved contoso-lab.example domain.

## Keep Local

The following types of data must remain outside version control:

- Real tenant assessment reports
- Microsoft Entra tenant exports
- Real user and guest identities
- Tenant IDs and production identifiers when not required for public documentation
- Real Conditional Access policy exports
- Privileged role assignment exports
- Authentication registration reports
- Identity Protection or risky-user reports
- Application and service-principal exports
- Credential metadata from production applications
- Access tokens
- Refresh tokens
- Client secrets
- Certificates containing private keys
- Authentication caches
- Environment files containing credentials or tenant configuration

## Local Output Directories

The .gitignore file excludes the following repository-root directories:

- reports/
- output/
- exports/
- assessment-output/
- tenant-data/
- live-data/
- private-data/

Use one of these locations when running assessments against real environments.

## Sample Output Rule

Never copy a production report directly into examples/sample-output.

If a production result is being converted into a portfolio example, recreate it using fictional identities, domains, IDs, applications, groups, policy names, and other identifiers rather than attempting partial redaction of the original report.

## Credential Handling

This project does not require passwords, client secrets, private keys, or stored Microsoft Graph access tokens in source control.

Authentication material must never be embedded in scripts, configuration files, examples, documentation, or committed command output.

## Pre-Commit Validation

Before publishing significant changes:

1. Review git status.
2. Review staged files.
3. Search for real organization names and domains.
4. Search for real email addresses.
5. Search for tokens, passwords, secrets, and private-key material.
6. Confirm generated reports contain only fictional or sanitized data.
7. Run git diff --cached --check before committing.

## Public Repository Boundary

The public repository demonstrates assessment logic and methodology.

Real assessment evidence belongs in appropriately secured organizational systems, not in this GitHub repository.
