<#
.SYNOPSIS
    Builds a normalized Microsoft Entra ID Conditional Access policy inventory.

.DESCRIPTION
    Reads Microsoft Entra Conditional Access policy data from JSON and
    returns structured PowerShell objects for assessment and reporting.

    The current version operates offline against fictional sample data.

.PARAMETER InputPath
    Optional path to the Conditional Access policy JSON dataset.

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
    $InputPath = Join-Path $RepositoryRoot "examples\sample-input\entra-conditional-access-policies.json"
}

try {

    if (-not (Test-Path -LiteralPath $InputPath)) {
        throw "Conditional Access input file not found: $InputPath"
    }

    $ParsedPolicies = Get-Content -LiteralPath $InputPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop

    $Policies = @()

    foreach ($ParsedPolicy in $ParsedPolicies) {
        $Policies += $ParsedPolicy
    }

    if ($Policies.Count -eq 0) {
        throw "Conditional Access dataset contains no policies."
    }

    foreach ($Policy in $Policies) {

        $MissingFields = @()

        foreach ($RequiredField in @(
            "Id",
            "DisplayName",
            "State"
        )) {

            if ($null -eq $Policy.$RequiredField -or
                [string]::IsNullOrWhiteSpace([string]$Policy.$RequiredField)) {

                $MissingFields += $RequiredField
            }
        }

        $IncludeUsers        = @($Policy.IncludeUsers)
        $IncludeGroups       = @($Policy.IncludeGroups)
        $IncludeRoles        = @($Policy.IncludeRoles)
        $ExcludeUsers        = @($Policy.ExcludeUsers)
        $ExcludeGroups       = @($Policy.ExcludeGroups)
        $ExcludeRoles        = @($Policy.ExcludeRoles)
        $IncludeApplications = @($Policy.IncludeApplications)
        $ExcludeApplications = @($Policy.ExcludeApplications)
        $ClientAppTypes      = @($Policy.ClientAppTypes)
        $GrantControls       = @($Policy.GrantControls)

        $ExcludedUserCount  = $ExcludeUsers.Count
        $ExcludedGroupCount = $ExcludeGroups.Count
        $ExcludedRoleCount  = $ExcludeRoles.Count

        $TotalExclusions = (
            $ExcludedUserCount +
            $ExcludedGroupCount +
            $ExcludedRoleCount
        )

        $NormalizedState = switch ($Policy.State) {
            "enabled" { "Enabled" }
            "enabledForReportingButNotEnforced" { "Report Only" }
            "disabled" { "Disabled" }
            default { "Unknown" }
        }

        [PSCustomObject]@{
            Id                     = $Policy.Id
            DisplayName            = $Policy.DisplayName
            RawState               = $Policy.State
            State                  = $NormalizedState
            IsEnabled              = ($Policy.State -eq "enabled")
            IsReportOnly           = ($Policy.State -eq "enabledForReportingButNotEnforced")
            IsDisabled             = ($Policy.State -eq "disabled")

            IncludedUsers          = ($IncludeUsers -join "; ")
            IncludedGroups         = ($IncludeGroups -join "; ")
            IncludedRoles          = ($IncludeRoles -join "; ")

            ExcludedUsers          = ($ExcludeUsers -join "; ")
            ExcludedGroups         = ($ExcludeGroups -join "; ")
            ExcludedRoles          = ($ExcludeRoles -join "; ")

            ExcludedUserCount      = $ExcludedUserCount
            ExcludedGroupCount     = $ExcludedGroupCount
            ExcludedRoleCount      = $ExcludedRoleCount
            TotalExclusions        = $TotalExclusions
            HasExclusions          = ($TotalExclusions -gt 0)

            IncludedApplications   = ($IncludeApplications -join "; ")
            ExcludedApplications   = ($ExcludeApplications -join "; ")
            ClientAppTypes         = ($ClientAppTypes -join "; ")
            GrantControls          = ($GrantControls -join "; ")
            AuthenticationStrength = $Policy.AuthenticationStrength
            Description            = $Policy.Description

            DataValid              = ($MissingFields.Count -eq 0)
            ValidationNote         = if ($MissingFields.Count -gt 0) {
                "Missing required fields: $($MissingFields -join ', ')"
            }
            else {
                "Conditional Access policy record validated."
            }

            Source                 = "Offline JSON Dataset"
        }
    }
}
catch {
    Write-Error "Conditional Access inventory collection failed. $($_.Exception.Message)"
}
