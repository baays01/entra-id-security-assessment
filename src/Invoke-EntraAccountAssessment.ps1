<#
.SYNOPSIS
    Evaluates Microsoft Entra ID account-hygiene rules.

.DESCRIPTION
    Uses normalized Entra user inventory data to evaluate selected
    read-only assessment rules.

    Current implemented rules:
    - ENTRA-ACCT-001 Disabled Account Inventory
    - ENTRA-GUEST-001 Guest Account Inventory

.PARAMETER InputPath
    Optional path to a sanitized or authorized JSON user dataset.

.NOTES
    Author: Adebayo Ayorinde
    Project: Microsoft Entra ID Security Assessment

    This script performs assessment only and makes no tenant changes.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$InputPath
)

$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$InventoryScript = Join-Path $PSScriptRoot "Get-EntraUserInventory.ps1"
$RulesPath = Join-Path $RepositoryRoot "config\assessment-rules.json"

try {

    if (-not (Test-Path -LiteralPath $InventoryScript)) {
        throw "Inventory collector not found: $InventoryScript"
    }

    if (-not (Test-Path -LiteralPath $RulesPath)) {
        throw "Assessment rule configuration not found: $RulesPath"
    }

    $Rules = Get-Content -LiteralPath $RulesPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop

    if ($InputPath) {
        $Inventory = & $InventoryScript -InputPath $InputPath
    }
    else {
        $Inventory = & $InventoryScript
    }

    if (-not $Inventory) {
        throw "No normalized Entra user inventory was returned."
    }

    $Findings = @()

    # ---------------------------------------------------------
    # ENTRA-ACCT-001 - Disabled Account Inventory
    # ---------------------------------------------------------

    $Rule = $Rules.Rules |
        Where-Object Id -eq "ENTRA-ACCT-001"

    if ($Rule -and $Rule.Enabled) {

        $DisabledAccounts = @(
            $Inventory |
                Where-Object { $_.AccountEnabled -eq $false }
        )

        $Status = if ($DisabledAccounts.Count -gt 0) {
            $Rule.DefaultStatus
        }
        else {
            "PASS"
        }

        $Findings += [PSCustomObject]@{
            RuleId          = $Rule.Id
            Domain          = $Rule.Domain
            FindingName     = $Rule.Name
            Status          = $Status
            RecordCount     = $DisabledAccounts.Count
            Summary         = if ($DisabledAccounts.Count -gt 0) {
                "$($DisabledAccounts.Count) disabled account(s) identified for lifecycle review."
            }
            else {
                "No disabled accounts identified in the assessed dataset."
            }
            Evidence        = ($DisabledAccounts.DisplayName -join "; ")
            Source          = "Normalized Entra User Inventory"
            ReadOnly        = $true
        }
    }

    # ---------------------------------------------------------
    # ENTRA-GUEST-001 - Guest Account Inventory
    # ---------------------------------------------------------

    $Rule = $Rules.Rules |
        Where-Object Id -eq "ENTRA-GUEST-001"

    if ($Rule -and $Rule.Enabled) {

        $GuestAccounts = @(
            $Inventory |
                Where-Object UserType -eq "Guest"
        )

        $Status = if ($GuestAccounts.Count -gt 0) {
            $Rule.DefaultStatus
        }
        else {
            "PASS"
        }

        $Findings += [PSCustomObject]@{
            RuleId          = $Rule.Id
            Domain          = $Rule.Domain
            FindingName     = $Rule.Name
            Status          = $Status
            RecordCount     = $GuestAccounts.Count
            Summary         = if ($GuestAccounts.Count -gt 0) {
                "$($GuestAccounts.Count) guest account(s) identified for ownership and lifecycle review."
            }
            else {
                "No guest accounts identified in the assessed dataset."
            }
            Evidence        = ($GuestAccounts.DisplayName -join "; ")
            Source          = "Normalized Entra User Inventory"
            ReadOnly        = $true
        }
    }

    $Findings
}
catch {

    Write-Error "Entra account assessment failed. $($_.Exception.Message)"
}
