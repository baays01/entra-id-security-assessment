<#
.SYNOPSIS
    Handles the optional Microsoft Entra ID identity-risk assessment domain.

.DESCRIPTION
    Evaluates whether the ENTRA-RISK-001 assessment rule is enabled.

    Identity-risk assessment remains disabled by default because access
    can depend on Microsoft Entra licensing, Graph permissions, and tenant
    capabilities.

    When disabled, the script returns a structured NOT ASSESSED result
    instead of fabricating or inferring identity-risk information.

.NOTES
    Author: Adebayo Ayorinde
    Project: Microsoft Entra ID Security Assessment

    Read-only assessment tooling.
#>

[CmdletBinding()]
param()

$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$RulesPath = Join-Path $RepositoryRoot "config\assessment-rules.json"

try {

    if (-not (Test-Path -LiteralPath $RulesPath)) {
        throw "Assessment rule configuration not found: $RulesPath"
    }

    $Rules = Get-Content -LiteralPath $RulesPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop

    $Rule = $Rules.Rules |
        Where-Object Id -eq "ENTRA-RISK-001"

    if (-not $Rule) {
        throw "Rule ENTRA-RISK-001 was not found in assessment-rules.json."
    }

    if (-not $Rule.Enabled) {

        [PSCustomObject]@{
            RuleId          = $Rule.Id
            Domain          = $Rule.Domain
            FindingName     = $Rule.Name
            Status          = "NOT ASSESSED"
            RecordCount     = 0
            PopulationCount = 0
            Summary         = "Identity-risk assessment is disabled by default and was not performed."
            Evidence        = "Requires supported tenant licensing, permissions, and Microsoft Graph identity-risk data."
            Source          = "Assessment Configuration"
            ReadOnly        = $true
            Enabled         = $false
        }

        return
    }

    [PSCustomObject]@{
        RuleId          = $Rule.Id
        Domain          = $Rule.Domain
        FindingName     = $Rule.Name
        Status          = "NOT ASSESSED"
        RecordCount     = 0
        PopulationCount = 0
        Summary         = "Identity-risk assessment is enabled, but no live risk-data collector has been configured."
        Evidence        = "Live Microsoft Graph identity-risk collection is required before this assessment can execute."
        Source          = "Assessment Configuration"
        ReadOnly        = $true
        Enabled         = $true
    }
}
catch {
    Write-Error "Identity-risk assessment handling failed. $($_.Exception.Message)"
}
