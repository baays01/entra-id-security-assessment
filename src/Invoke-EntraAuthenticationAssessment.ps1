<#
.SYNOPSIS
    Evaluates Microsoft Entra ID authentication and MFA posture.

.DESCRIPTION
    Uses the normalized authentication-registration inventory to identify
    enabled identities that are not registered for MFA.

    Current implemented rule:
    - ENTRA-AUTH-001 MFA Registration Review

.PARAMETER InputPath
    Optional path to a sanitized or authorized authentication-registration dataset.

.NOTES
    Author: Adebayo Ayorinde
    Project: Microsoft Entra ID Security Assessment

    Assessment only. No Microsoft Entra configuration changes are made.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$InputPath
)

$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$InventoryScript = Join-Path $PSScriptRoot "Get-EntraAuthenticationRegistrationInventory.ps1"
$RulesPath = Join-Path $RepositoryRoot "config\assessment-rules.json"

try {

    if (-not (Test-Path -LiteralPath $InventoryScript)) {
        throw "Authentication inventory collector not found: $InventoryScript"
    }

    if (-not (Test-Path -LiteralPath $RulesPath)) {
        throw "Assessment rule configuration not found: $RulesPath"
    }

    $Rules = Get-Content -LiteralPath $RulesPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop

    if ($InputPath) {
        $AuthInventory = @(
            & $InventoryScript -InputPath $InputPath
        )
    }
    else {
        $AuthInventory = @(
            & $InventoryScript
        )
    }

    if ($AuthInventory.Count -eq 0) {
        throw "No authentication-registration records were returned."
    }

    $InvalidRecords = @(
        $AuthInventory |
            Where-Object { $_.DataValid -eq $false }
    )

    if ($InvalidRecords.Count -gt 0) {
        throw "$($InvalidRecords.Count) invalid authentication-registration record(s) detected."
    }

    $Rule = $Rules.Rules |
        Where-Object Id -eq "ENTRA-AUTH-001"

    if (-not $Rule) {
        throw "Rule ENTRA-AUTH-001 was not found in assessment-rules.json."
    }

    if (-not $Rule.Enabled) {
        return
    }

    $EnabledUsers = @(
        $AuthInventory |
            Where-Object { $_.AccountEnabled -eq $true }
    )

    $EnabledWithoutMfa = @(
        $AuthInventory |
            Where-Object { $_.EnabledWithoutMfa -eq $true }
    )

    $Status = if ($EnabledWithoutMfa.Count -gt 0) {
        $Rule.DefaultStatus
    }
    else {
        "PASS"
    }

    $Evidence = $EnabledWithoutMfa |
        ForEach-Object {
            "$($_.DisplayName) [$($_.UserPrincipalName)]"
        }

    [PSCustomObject]@{
        RuleId          = $Rule.Id
        Domain          = $Rule.Domain
        FindingName     = $Rule.Name
        Status          = $Status
        RecordCount     = $EnabledWithoutMfa.Count
        PopulationCount = $EnabledUsers.Count
        Summary         = if ($EnabledWithoutMfa.Count -gt 0) {
            "$($EnabledWithoutMfa.Count) of $($EnabledUsers.Count) enabled identity(ies) are not registered for MFA and require review."
        }
        else {
            "All enabled identities in the assessed dataset are registered for MFA."
        }
        Evidence        = ($Evidence -join "; ")
        Source          = "Normalized Authentication Registration Inventory"
        ReadOnly        = $true
    }
}
catch {
    Write-Error "Authentication and MFA assessment failed. $($_.Exception.Message)"
}
