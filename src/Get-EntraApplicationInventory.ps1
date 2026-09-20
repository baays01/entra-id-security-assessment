<#
.SYNOPSIS
    Builds normalized Microsoft Entra ID application and credential inventories.

.DESCRIPTION
    Reads fictional or authorized Microsoft Entra application-registration data
    from JSON and normalizes application ownership, service-principal presence,
    and credential-expiration information for security assessment.

    The current version operates completely offline.

.PARAMETER InputPath
    Optional path to the application-registration JSON dataset.

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
    $InputPath = Join-Path $RepositoryRoot "examples\sample-input\entra-applications.json"
}

try {

    if (-not (Test-Path -LiteralPath $InputPath)) {
        throw "Application input file not found: $InputPath"
    }

    $Dataset = Get-Content -LiteralPath $InputPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop

    if (-not $Dataset.AssessmentReferenceDate) {
        throw "AssessmentReferenceDate is missing from the application dataset."
    }

    if ($null -eq $Dataset.CredentialWarningDays) {
        throw "CredentialWarningDays is missing from the application dataset."
    }

    $ReferenceDate = [datetimeoffset]$Dataset.AssessmentReferenceDate
    $WarningDays   = [int]$Dataset.CredentialWarningDays

    $Applications = @()

    foreach ($Application in $Dataset.Applications) {
        $Applications += $Application
    }

    if ($Applications.Count -eq 0) {
        throw "Application dataset contains no application records."
    }

    $NormalizedApplications = @()
    $NormalizedCredentials  = @()

    foreach ($Application in $Applications) {

        $MissingFields = @()

        foreach ($RequiredField in @(
            "Id",
            "AppId",
            "DisplayName",
            "SignInAudience",
            "PublisherDomain"
        )) {

            if ($null -eq $Application.$RequiredField -or
                [string]::IsNullOrWhiteSpace([string]$Application.$RequiredField)) {

                $MissingFields += $RequiredField
            }
        }

        $Owners              = @($Application.Owners)
        $PasswordCredentials = @($Application.PasswordCredentials)
        $KeyCredentials      = @($Application.KeyCredentials)

        $NormalizedApplications += [PSCustomObject]@{
            Id                      = $Application.Id
            AppId                   = $Application.AppId
            DisplayName             = $Application.DisplayName
            SignInAudience          = $Application.SignInAudience
            PublisherDomain         = $Application.PublisherDomain
            Owners                  = ($Owners -join "; ")
            OwnerCount              = $Owners.Count
            HasOwners               = ($Owners.Count -gt 0)
            PasswordCredentialCount = $PasswordCredentials.Count
            KeyCredentialCount      = $KeyCredentials.Count
            TotalCredentialCount    = ($PasswordCredentials.Count + $KeyCredentials.Count)
            ServicePrincipalPresent = [bool]$Application.ServicePrincipalPresent
            ServicePrincipalId      = $Application.ServicePrincipalId
            DataValid               = ($MissingFields.Count -eq 0)
            ValidationNote          = if ($MissingFields.Count -gt 0) {
                "Missing required fields: $($MissingFields -join ', ')"
            }
            else {
                "Application record validated."
            }
            Source                  = "Offline JSON Dataset"
        }

        foreach ($Credential in $PasswordCredentials) {

            $EndDate = [datetimeoffset]$Credential.EndDateTime

            $DaysUntilExpiration = (
                $EndDate.UtcDateTime.Date -
                $ReferenceDate.UtcDateTime.Date
            ).Days

            $CredentialState = if ($EndDate -lt $ReferenceDate) {
                "Expired"
            }
            elseif ($EndDate -le $ReferenceDate.AddDays($WarningDays)) {
                "Expiring Soon"
            }
            else {
                "Valid"
            }

            $NormalizedCredentials += [PSCustomObject]@{
                ApplicationId       = $Application.Id
                AppId               = $Application.AppId
                ApplicationName     = $Application.DisplayName
                CredentialType      = "Password"
                CredentialId        = $Credential.KeyId
                CredentialName      = $Credential.DisplayName
                StartDateTime       = [datetimeoffset]$Credential.StartDateTime
                EndDateTime         = $EndDate
                DaysUntilExpiration = $DaysUntilExpiration
                CredentialState     = $CredentialState
                RequiresReview      = ($CredentialState -ne "Valid")
                Source              = "Offline JSON Dataset"
            }
        }

        foreach ($Credential in $KeyCredentials) {

            $EndDate = [datetimeoffset]$Credential.EndDateTime

            $DaysUntilExpiration = (
                $EndDate.UtcDateTime.Date -
                $ReferenceDate.UtcDateTime.Date
            ).Days

            $CredentialState = if ($EndDate -lt $ReferenceDate) {
                "Expired"
            }
            elseif ($EndDate -le $ReferenceDate.AddDays($WarningDays)) {
                "Expiring Soon"
            }
            else {
                "Valid"
            }

            $NormalizedCredentials += [PSCustomObject]@{
                ApplicationId       = $Application.Id
                AppId               = $Application.AppId
                ApplicationName     = $Application.DisplayName
                CredentialType      = "Certificate"
                CredentialId        = $Credential.KeyId
                CredentialName      = $Credential.DisplayName
                StartDateTime       = [datetimeoffset]$Credential.StartDateTime
                EndDateTime         = $EndDate
                DaysUntilExpiration = $DaysUntilExpiration
                CredentialState     = $CredentialState
                RequiresReview      = ($CredentialState -ne "Valid")
                Source              = "Offline JSON Dataset"
            }
        }
    }

    [PSCustomObject]@{
        AssessmentReferenceDate = $ReferenceDate
        CredentialWarningDays   = $WarningDays
        Applications            = $NormalizedApplications
        Credentials             = $NormalizedCredentials
    }
}
catch {
    Write-Error "Application inventory collection failed. $($_.Exception.Message)"
}
