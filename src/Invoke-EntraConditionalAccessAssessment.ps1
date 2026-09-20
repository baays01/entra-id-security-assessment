<#
.SYNOPSIS
    Evaluates Microsoft Entra ID Conditional Access assessment rules.

.DESCRIPTION
    Uses the normalized Conditional Access inventory to evaluate
    policy-state and exclusion-review controls.

    Current implemented rules:
    - ENTRA-CA-001 Conditional Access Policy Inventory
    - ENTRA-CA-002 Conditional Access Exclusion Review

.PARAMETER InputPath
    Optional path to a sanitized or authorized Conditional Access dataset.

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
$InventoryScript = Join-Path $PSScriptRoot "Get-EntraConditionalAccessInventory.ps1"
$RulesPath = Join-Path $RepositoryRoot "config\assessment-rules.json"

try {

    if (-not (Test-Path -LiteralPath $InventoryScript)) {
        throw "Conditional Access inventory collector not found: $InventoryScript"
    }

    if (-not (Test-Path -LiteralPath $RulesPath)) {
        throw "Assessment rule configuration not found: $RulesPath"
    }

    $Rules = Get-Content -LiteralPath $RulesPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop

    if ($InputPath) {
        $CAInventory = @(
            & $InventoryScript -InputPath $InputPath
        )
    }
    else {
        $CAInventory = @(
            & $InventoryScript
        )
    }

    if ($CAInventory.Count -eq 0) {
        throw "No Conditional Access policies were returned."
    }

    $InvalidPolicies = @(
        $CAInventory |
            Where-Object { $_.DataValid -eq $false }
    )

    if ($InvalidPolicies.Count -gt 0) {
        throw "$($InvalidPolicies.Count) invalid Conditional Access policy record(s) detected."
    }

    $Findings = @()

    # ---------------------------------------------------------
    # ENTRA-CA-001 - Conditional Access Policy Inventory
    # ---------------------------------------------------------

    $Rule = $Rules.Rules |
        Where-Object Id -eq "ENTRA-CA-001"

    if ($Rule -and $Rule.Enabled) {

        $EnabledPolicies = @(
            $CAInventory |
                Where-Object { $_.IsEnabled -eq $true }
        )

        $ReportOnlyPolicies = @(
            $CAInventory |
                Where-Object { $_.IsReportOnly -eq $true }
        )

        $DisabledPolicies = @(
            $CAInventory |
                Where-Object { $_.IsDisabled -eq $true }
        )

        $Evidence = $CAInventory |
            ForEach-Object {
                "$($_.DisplayName) [$($_.State)]"
            }

        $Findings += [PSCustomObject]@{
            RuleId          = $Rule.Id
            Domain          = $Rule.Domain
            FindingName     = $Rule.Name
            Status          = $Rule.DefaultStatus
            RecordCount     = $CAInventory.Count
            PopulationCount = $CAInventory.Count
            ExclusionCount  = 0
            Summary         = "$($CAInventory.Count) Conditional Access policy(ies) identified: $($EnabledPolicies.Count) enabled, $($ReportOnlyPolicies.Count) report-only, and $($DisabledPolicies.Count) disabled."
            Evidence        = ($Evidence -join "; ")
            Source          = "Normalized Conditional Access Inventory"
            ReadOnly        = $true
        }
    }

    # ---------------------------------------------------------
    # ENTRA-CA-002 - Conditional Access Exclusion Review
    # ---------------------------------------------------------

    $Rule = $Rules.Rules |
        Where-Object Id -eq "ENTRA-CA-002"

    if ($Rule -and $Rule.Enabled) {

        $ApplicablePolicies = @(
            $CAInventory |
                Where-Object { $_.IsDisabled -eq $false }
        )

        $PoliciesWithActiveExclusions = @(
            $ApplicablePolicies |
                Where-Object { $_.HasExclusions -eq $true }
        )

        $TotalActiveExclusions = 0

        foreach ($Policy in $PoliciesWithActiveExclusions) {
            $TotalActiveExclusions += [int]$Policy.TotalExclusions
        }

        $Status = if ($PoliciesWithActiveExclusions.Count -gt 0) {
            $Rule.DefaultStatus
        }
        else {
            "PASS"
        }

        $Evidence = $PoliciesWithActiveExclusions |
            ForEach-Object {

                $Details = @()

                if ($_.ExcludedUserCount -gt 0) {
                    $Details += "Users: $($_.ExcludedUsers)"
                }

                if ($_.ExcludedGroupCount -gt 0) {
                    $Details += "Groups: $($_.ExcludedGroups)"
                }

                if ($_.ExcludedRoleCount -gt 0) {
                    $Details += "Roles: $($_.ExcludedRoles)"
                }

                "$($_.DisplayName) [$($_.State)] {$($Details -join ' | ')}"
            }

        $Findings += [PSCustomObject]@{
            RuleId          = $Rule.Id
            Domain          = $Rule.Domain
            FindingName     = $Rule.Name
            Status          = $Status
            RecordCount     = $PoliciesWithActiveExclusions.Count
            PopulationCount = $ApplicablePolicies.Count
            ExclusionCount  = $TotalActiveExclusions
            Summary         = if ($PoliciesWithActiveExclusions.Count -gt 0) {
                "$($PoliciesWithActiveExclusions.Count) active or report-only Conditional Access policy(ies) contain $TotalActiveExclusions exclusion(s) requiring administrative validation."
            }
            else {
                "No exclusions were identified in enabled or report-only Conditional Access policies."
            }
            Evidence        = ($Evidence -join "; ")
            Source          = "Normalized Conditional Access Inventory"
            ReadOnly        = $true
        }
    }

    $Findings
}
catch {
    Write-Error "Conditional Access assessment failed. $($_.Exception.Message)"
}
