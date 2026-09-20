<#
.SYNOPSIS
    Evaluates Microsoft Entra ID application-registration assessment rules.

.DESCRIPTION
    Uses the normalized application and credential inventory to assess
    application registration inventory and credential expiration posture.

    Current implemented rules:
    - ENTRA-APP-001 Application Registration Inventory
    - ENTRA-APP-002 Application Credential Expiration Review

.PARAMETER InputPath
    Optional path to a sanitized or authorized application-registration dataset.

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

$RepositoryRoot  = Split-Path -Parent $PSScriptRoot
$InventoryScript = Join-Path $PSScriptRoot "Get-EntraApplicationInventory.ps1"
$RulesPath       = Join-Path $RepositoryRoot "config\assessment-rules.json"

try {

    if (-not (Test-Path -LiteralPath $InventoryScript)) {
        throw "Application inventory collector not found: $InventoryScript"
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
        throw "No application inventory was returned."
    }

    $Applications = @($Inventory.Applications)
    $Credentials  = @($Inventory.Credentials)

    if ($Applications.Count -eq 0) {
        throw "No normalized application records were returned."
    }

    $InvalidApplications = @(
        $Applications |
            Where-Object { $_.DataValid -eq $false }
    )

    if ($InvalidApplications.Count -gt 0) {
        throw "$($InvalidApplications.Count) invalid application record(s) detected."
    }

    $Findings = @()

    # ---------------------------------------------------------
    # ENTRA-APP-001 - Application Registration Inventory
    # ---------------------------------------------------------

    $Rule = $Rules.Rules |
        Where-Object Id -eq "ENTRA-APP-001"

    if ($Rule -and $Rule.Enabled) {

        $OwnerlessApplications = @(
            $Applications |
                Where-Object { $_.HasOwners -eq $false }
        )

        $Evidence = $Applications |
            ForEach-Object {
                "$($_.DisplayName) [Owners=$($_.OwnerCount); Credentials=$($_.TotalCredentialCount); ServicePrincipal=$($_.ServicePrincipalPresent)]"
            }

        $Findings += [PSCustomObject]@{
            RuleId                    = $Rule.Id
            Domain                    = $Rule.Domain
            FindingName               = $Rule.Name
            Status                    = $Rule.DefaultStatus
            RecordCount               = $Applications.Count
            PopulationCount           = $Applications.Count
            OwnerlessApplicationCount = $OwnerlessApplications.Count
            ExpiredCredentialCount    = 0
            ExpiringSoonCount         = 0
            Summary                   = "$($Applications.Count) application registration(s) identified. $($OwnerlessApplications.Count) application(s) have no listed owner and may require ownership review."
            Evidence                  = ($Evidence -join "; ")
            Source                    = "Normalized Application Inventory"
            ReadOnly                  = $true
        }
    }

    # ---------------------------------------------------------
    # ENTRA-APP-002 - Application Credential Expiration Review
    # ---------------------------------------------------------

    $Rule = $Rules.Rules |
        Where-Object Id -eq "ENTRA-APP-002"

    if ($Rule -and $Rule.Enabled) {

        $ExpiredCredentials = @(
            $Credentials |
                Where-Object { $_.CredentialState -eq "Expired" }
        )

        $ExpiringSoonCredentials = @(
            $Credentials |
                Where-Object { $_.CredentialState -eq "Expiring Soon" }
        )

        $CredentialsRequiringReview = @(
            $Credentials |
                Where-Object { $_.RequiresReview -eq $true }
        )

        $Status = if ($CredentialsRequiringReview.Count -gt 0) {
            $Rule.DefaultStatus
        }
        else {
            "PASS"
        }

        $Evidence = $CredentialsRequiringReview |
            ForEach-Object {
                "$($_.ApplicationName) [$($_.CredentialType): $($_.CredentialName); State=$($_.CredentialState); Days=$($_.DaysUntilExpiration)]"
            }

        $Findings += [PSCustomObject]@{
            RuleId                    = $Rule.Id
            Domain                    = $Rule.Domain
            FindingName               = $Rule.Name
            Status                    = $Status
            RecordCount               = $CredentialsRequiringReview.Count
            PopulationCount           = $Credentials.Count
            OwnerlessApplicationCount = 0
            ExpiredCredentialCount    = $ExpiredCredentials.Count
            ExpiringSoonCount         = $ExpiringSoonCredentials.Count
            Summary                   = if ($CredentialsRequiringReview.Count -gt 0) {
                "$($CredentialsRequiringReview.Count) of $($Credentials.Count) application credential(s) require review: $($ExpiredCredentials.Count) expired and $($ExpiringSoonCredentials.Count) expiring within the configured warning window."
            }
            else {
                "No expired or soon-to-expire application credentials were identified."
            }
            Evidence                  = ($Evidence -join "; ")
            Source                    = "Normalized Application Credential Inventory"
            ReadOnly                  = $true
        }
    }

    $Findings
}
catch {
    Write-Error "Application assessment failed. $($_.Exception.Message)"
}
