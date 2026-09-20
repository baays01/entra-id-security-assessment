<#
.SYNOPSIS
    Builds a normalized Microsoft Entra ID authentication-registration inventory.

.DESCRIPTION
    Reads Microsoft Entra authentication-registration data from JSON and
    returns structured PowerShell objects for assessment and reporting.

    The current version operates offline against fictional sample data.

.PARAMETER InputPath
    Optional path to the authentication-registration JSON dataset.

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
    $InputPath = Join-Path $RepositoryRoot "examples\sample-input\entra-auth-registration.json"
}

try {

    if (-not (Test-Path -LiteralPath $InputPath)) {
        throw "Authentication-registration input file not found: $InputPath"
    }

    $ParsedRecords = Get-Content -LiteralPath $InputPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop

    $RegistrationRecords = @()

    foreach ($ParsedRecord in $ParsedRecords) {
        $RegistrationRecords += $ParsedRecord
    }

    if ($RegistrationRecords.Count -eq 0) {
        throw "Authentication-registration dataset contains no records."
    }

    foreach ($Registration in $RegistrationRecords) {

        $MissingFields = @()

        foreach ($RequiredField in @(
            "Id",
            "DisplayName",
            "UserPrincipalName",
            "UserType",
            "AccountEnabled",
            "IsMfaRegistered",
            "IsMfaCapable",
            "IsPasswordlessCapable"
        )) {

            if ($null -eq $Registration.$RequiredField -or
                [string]::IsNullOrWhiteSpace([string]$Registration.$RequiredField)) {

                $MissingFields += $RequiredField
            }
        }

        $Methods = @(
            $Registration.MethodsRegistered
        )

        $AccountState = if ($Registration.AccountEnabled -eq $true) {
            "Enabled"
        }
        else {
            "Disabled"
        }

        $IdentityType = if ($Registration.UserType -eq "Guest") {
            "External / Guest"
        }
        elseif ($Registration.UserType -eq "Member") {
            "Internal / Member"
        }
        else {
            "Unknown"
        }

        $MfaState = if ($Registration.IsMfaRegistered -eq $true) {
            "Registered"
        }
        else {
            "Not Registered"
        }

        [PSCustomObject]@{
            Id                    = $Registration.Id
            DisplayName           = $Registration.DisplayName
            UserPrincipalName     = $Registration.UserPrincipalName
            UserType              = $Registration.UserType
            IdentityType          = $IdentityType
            AccountEnabled        = [bool]$Registration.AccountEnabled
            AccountState          = $AccountState
            IsMfaRegistered       = [bool]$Registration.IsMfaRegistered
            MfaState              = $MfaState
            IsMfaCapable          = [bool]$Registration.IsMfaCapable
            IsPasswordlessCapable = [bool]$Registration.IsPasswordlessCapable
            MethodsRegistered     = ($Methods -join ", ")
            MethodCount           = $Methods.Count
            EnabledWithoutMfa     = (
                $Registration.AccountEnabled -eq $true -and
                $Registration.IsMfaRegistered -eq $false
            )
            DataValid             = ($MissingFields.Count -eq 0)
            ValidationNote        = if ($MissingFields.Count -gt 0) {
                "Missing required fields: $($MissingFields -join ', ')"
            }
            else {
                "Authentication-registration record validated."
            }
            Source                = "Offline JSON Dataset"
        }
    }
}
catch {
    Write-Error "Authentication-registration inventory collection failed. $($_.Exception.Message)"
}
