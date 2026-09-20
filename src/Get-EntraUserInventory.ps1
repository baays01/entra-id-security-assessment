<#
.SYNOPSIS
    Builds a normalized Microsoft Entra ID user inventory from JSON input.

.DESCRIPTION
    Reads Microsoft Entra ID user data from a JSON file and returns
    structured PowerShell objects suitable for assessment and reporting.

    The current version operates completely offline using sanitized
    sample data. Microsoft Graph connectivity will be added separately.

.PARAMETER InputPath
    Path to the JSON user dataset.

.EXAMPLE
    .\src\Get-EntraUserInventory.ps1

.EXAMPLE
    .\src\Get-EntraUserInventory.ps1 -InputPath .\examples\sample-input\entra-users.json

.NOTES
    Author: Adebayo Ayorinde
    Project: Microsoft Entra ID Security Assessment

    Read-only assessment tooling.
    No credentials, access tokens, or production tenant data are embedded.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$InputPath
)

$RepositoryRoot = Split-Path -Parent $PSScriptRoot

if (-not $InputPath) {
    $InputPath = Join-Path $RepositoryRoot "examples\sample-input\entra-users.json"
}

try {

    if (-not (Test-Path -LiteralPath $InputPath)) {
        throw "Input file not found: $InputPath"
    }

    Write-Verbose "Reading Entra user data from $InputPath"

    $Users = Get-Content -LiteralPath $InputPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop

    if (-not $Users) {
        throw "Input dataset contains no user records."
    }

    foreach ($User in $Users) {

        $MissingFields = @()

        foreach ($RequiredField in @(
            "Id",
            "DisplayName",
            "UserPrincipalName",
            "UserType",
            "AccountEnabled"
        )) {

            if ($null -eq $User.$RequiredField -or
                [string]::IsNullOrWhiteSpace([string]$User.$RequiredField)) {

                $MissingFields += $RequiredField
            }
        }

        $AccountState = if ($User.AccountEnabled -eq $true) {
            "Enabled"
        }
        else {
            "Disabled"
        }

        $IdentityType = if ($User.UserType -eq "Guest") {
            "External / Guest"
        }
        elseif ($User.UserType -eq "Member") {
            "Internal / Member"
        }
        else {
            "Unknown"
        }

        $AssessmentNote = if ($MissingFields.Count -gt 0) {
            "Required identity fields missing: $($MissingFields -join ', ')"
        }
        elseif ($User.UserType -eq "Guest") {
            "Guest identity included for lifecycle and ownership review."
        }
        elseif ($User.AccountEnabled -eq $false) {
            "Disabled identity included for account hygiene inventory."
        }
        else {
            "Standard enabled member identity."
        }

        $AssessmentStatus = if ($MissingFields.Count -gt 0) {
            "REVIEW"
        }
        else {
            "INFORMATIONAL"
        }

        [PSCustomObject]@{
            Id                = $User.Id
            DisplayName       = $User.DisplayName
            UserPrincipalName = $User.UserPrincipalName
            UserType          = $User.UserType
            IdentityType      = $IdentityType
            AccountEnabled    = [bool]$User.AccountEnabled
            AccountState      = $AccountState
            Department        = $User.Department
            JobTitle          = $User.JobTitle
            AssessmentStatus  = $AssessmentStatus
            AssessmentNote    = $AssessmentNote
            Source            = "Offline JSON Dataset"
        }
    }
}
catch {

    Write-Error "Entra user inventory collection failed. $($_.Exception.Message)"
}
