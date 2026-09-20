<#
.SYNOPSIS
    Builds a normalized Microsoft Entra ID privileged-role inventory.

.DESCRIPTION
    Reads Microsoft Entra privileged-role assignment data from JSON
    and returns structured PowerShell objects for assessment and reporting.

    The current version operates offline against fictional sample data.

.PARAMETER InputPath
    Optional path to the role-assignment JSON dataset.

.NOTES
    Author: Adebayo Ayorinde
    Project: Microsoft Entra ID Security Assessment

    Read-only assessment tooling.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$InputPath
)

$RepositoryRoot = Split-Path -Parent $PSScriptRoot

if (-not $InputPath) {
    $InputPath = Join-Path $RepositoryRoot "examples\sample-input\entra-role-assignments.json"
}

try {

    if (-not (Test-Path -LiteralPath $InputPath)) {
        throw "Role-assignment input file not found: $InputPath"
    }

    $ParsedAssignments = Get-Content -LiteralPath $InputPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop

    $Assignments = @()

    foreach ($ParsedAssignment in $ParsedAssignments) {
        $Assignments += $ParsedAssignment
    }

    if ($Assignments.Count -eq 0) {
        throw "Role-assignment dataset contains no records."
    }

    foreach ($Assignment in $Assignments) {

        $MissingFields = @()

        foreach ($RequiredField in @(
            "AssignmentId",
            "PrincipalId",
            "PrincipalName",
            "UserPrincipalName",
            "UserType",
            "RoleName",
            "AssignmentType",
            "AssignmentState",
            "Scope"
        )) {

            if ($null -eq $Assignment.$RequiredField -or
                [string]::IsNullOrWhiteSpace([string]$Assignment.$RequiredField)) {

                $MissingFields += $RequiredField
            }
        }

        $IdentityType = if ($Assignment.UserType -eq "Guest") {
            "External / Guest"
        }
        elseif ($Assignment.UserType -eq "Member") {
            "Internal / Member"
        }
        else {
            "Unknown"
        }

        [PSCustomObject]@{
            AssignmentId      = $Assignment.AssignmentId
            PrincipalId       = $Assignment.PrincipalId
            PrincipalName     = $Assignment.PrincipalName
            UserPrincipalName = $Assignment.UserPrincipalName
            UserType          = $Assignment.UserType
            IdentityType      = $IdentityType
            RoleName          = $Assignment.RoleName
            AssignmentType    = $Assignment.AssignmentType
            AssignmentState   = $Assignment.AssignmentState
            Scope             = $Assignment.Scope
            IsGuest           = ($Assignment.UserType -eq "Guest")
            DataValid         = ($MissingFields.Count -eq 0)
            ValidationNote    = if ($MissingFields.Count -gt 0) {
                "Missing required fields: $($MissingFields -join ', ')"
            }
            else {
                "Role-assignment record validated."
            }
            Source            = "Offline JSON Dataset"
        }
    }
}
catch {
    Write-Error "Privileged-role inventory collection failed. $($_.Exception.Message)"
}
