<#
.SYNOPSIS
    Evaluates Microsoft Entra ID privileged-role assessment rules.

.DESCRIPTION
    Uses the normalized privileged-role inventory to evaluate
    read-only Microsoft Entra ID privileged-access controls.

    Current implemented rules:
    - ENTRA-PRIV-001 Privileged Role Inventory
    - ENTRA-PRIV-002 Guest Privileged Identity Review

.PARAMETER InputPath
    Optional path to a sanitized or authorized role-assignment JSON dataset.

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
$InventoryScript = Join-Path $PSScriptRoot "Get-EntraPrivilegedRoleInventory.ps1"
$RulesPath = Join-Path $RepositoryRoot "config\assessment-rules.json"

try {

    if (-not (Test-Path -LiteralPath $InventoryScript)) {
        throw "Privileged-role inventory collector not found: $InventoryScript"
    }

    if (-not (Test-Path -LiteralPath $RulesPath)) {
        throw "Assessment rule configuration not found: $RulesPath"
    }

    $Rules = Get-Content -LiteralPath $RulesPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop

    if ($InputPath) {
        $RoleInventory = @(
            & $InventoryScript -InputPath $InputPath
        )
    }
    else {
        $RoleInventory = @(
            & $InventoryScript
        )
    }

    if ($RoleInventory.Count -eq 0) {
        throw "No privileged-role inventory records were returned."
    }

    $InvalidRecords = @(
        $RoleInventory |
            Where-Object { $_.DataValid -eq $false }
    )

    if ($InvalidRecords.Count -gt 0) {
        throw "$($InvalidRecords.Count) invalid privileged-role record(s) detected."
    }

    $Findings = @()

    # ---------------------------------------------------------
    # ENTRA-PRIV-001 - Privileged Role Inventory
    # ---------------------------------------------------------

    $Rule = $Rules.Rules |
        Where-Object Id -eq "ENTRA-PRIV-001"

    if ($Rule -and $Rule.Enabled) {

        $ActiveAssignments = @(
            $RoleInventory |
                Where-Object { $_.AssignmentType -eq "Active" }
        )

        $EligibleAssignments = @(
            $RoleInventory |
                Where-Object { $_.AssignmentType -eq "Eligible" }
        )

        $Evidence = $RoleInventory |
            ForEach-Object {
                "$($_.PrincipalName) [$($_.RoleName) - $($_.AssignmentType)]"
            }

        $Findings += [PSCustomObject]@{
            RuleId          = $Rule.Id
            Domain          = $Rule.Domain
            FindingName     = $Rule.Name
            Status          = $Rule.DefaultStatus
            RecordCount     = $RoleInventory.Count
            Summary         = "$($RoleInventory.Count) privileged role assignment(s) identified: $($ActiveAssignments.Count) active and $($EligibleAssignments.Count) eligible."
            Evidence        = ($Evidence -join "; ")
            Source          = "Normalized Privileged Role Inventory"
            ReadOnly        = $true
        }
    }

    # ---------------------------------------------------------
    # ENTRA-PRIV-002 - Guest Privileged Identity Review
    # ---------------------------------------------------------

    $Rule = $Rules.Rules |
        Where-Object Id -eq "ENTRA-PRIV-002"

    if ($Rule -and $Rule.Enabled) {

        $GuestPrivilegedAssignments = @(
            $RoleInventory |
                Where-Object { $_.IsGuest -eq $true }
        )

        $Status = if ($GuestPrivilegedAssignments.Count -gt 0) {
            $Rule.DefaultStatus
        }
        else {
            "PASS"
        }

        $Evidence = $GuestPrivilegedAssignments |
            ForEach-Object {
                "$($_.PrincipalName) [$($_.RoleName) - $($_.AssignmentType)]"
            }

        $Findings += [PSCustomObject]@{
            RuleId          = $Rule.Id
            Domain          = $Rule.Domain
            FindingName     = $Rule.Name
            Status          = $Status
            RecordCount     = $GuestPrivilegedAssignments.Count
            Summary         = if ($GuestPrivilegedAssignments.Count -gt 0) {
                "$($GuestPrivilegedAssignments.Count) guest or external privileged assignment(s) require administrative review."
            }
            else {
                "No guest or external privileged role assignments were identified."
            }
            Evidence        = ($Evidence -join "; ")
            Source          = "Normalized Privileged Role Inventory"
            ReadOnly        = $true
        }
    }

    $Findings
}
catch {
    Write-Error "Privileged-role assessment failed. $($_.Exception.Message)"
}
