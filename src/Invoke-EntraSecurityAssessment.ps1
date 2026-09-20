<#
.SYNOPSIS
    Runs the complete Microsoft Entra ID security assessment.

.DESCRIPTION
    Executes all implemented assessment modules and consolidates their
    findings into a single normalized assessment report.

    The current baseline operates against fictional offline datasets.

.PARAMETER OutputDirectory
    Directory used for consolidated assessment output.

.NOTES
    Author: Adebayo Ayorinde
    Project: Microsoft Entra ID Security Assessment

    Read-only assessment tooling.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory
)

$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$RulesPath = Join-Path $RepositoryRoot "config\assessment-rules.json"

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $RepositoryRoot "examples\sample-output"
}

function Get-OptionalPropertyValue {
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$PropertyName,

        [Parameter()]
        $DefaultValue = $null
    )

    $Property = $InputObject.PSObject.Properties[$PropertyName]

    if ($null -ne $Property) {
        return $Property.Value
    }

    return $DefaultValue
}

try {

    if (-not (Test-Path -LiteralPath $RulesPath)) {
        throw "Assessment rule configuration not found: $RulesPath"
    }

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    $RulesConfiguration = Get-Content -LiteralPath $RulesPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop

    $AssessmentScripts = @(
        "Invoke-EntraPrivilegedRoleAssessment.ps1",
        "Invoke-EntraAuthenticationAssessment.ps1",
        "Invoke-EntraConditionalAccessAssessment.ps1",
        "Invoke-EntraAccountAssessment.ps1",
        "Invoke-EntraApplicationAssessment.ps1",
        "Invoke-EntraIdentityRiskAssessment.ps1"
    )

    $RawFindings = @()

    foreach ($ScriptName in $AssessmentScripts) {

        $ScriptPath = Join-Path $PSScriptRoot $ScriptName

        if (-not (Test-Path -LiteralPath $ScriptPath)) {
            throw "Required assessment module not found: $ScriptPath"
        }

        Write-Verbose "Running assessment module: $ScriptName"

        $ModuleFindings = @(
            & $ScriptPath
        )

        $RawFindings += $ModuleFindings
    }

    $ConfiguredRules = @($RulesConfiguration.Rules)

    $NormalizedFindings = @()

    foreach ($ConfiguredRule in $ConfiguredRules) {

        $MatchingFindings = @(
            $RawFindings |
                Where-Object { $_.RuleId -eq $ConfiguredRule.Id }
        )

        if ($MatchingFindings.Count -eq 0) {
            throw "No assessment result was returned for configured rule $($ConfiguredRule.Id)."
        }

        if ($MatchingFindings.Count -gt 1) {
            throw "Multiple assessment results were returned for configured rule $($ConfiguredRule.Id)."
        }

        $Finding = $MatchingFindings[0]

        $NormalizedFindings += [PSCustomObject]@{
            RuleId          = $Finding.RuleId
            Domain          = $Finding.Domain
            FindingName     = $Finding.FindingName
            Status          = $Finding.Status
            RecordCount     = Get-OptionalPropertyValue -InputObject $Finding -PropertyName "RecordCount" -DefaultValue 0
            PopulationCount = Get-OptionalPropertyValue -InputObject $Finding -PropertyName "PopulationCount" -DefaultValue $null
            Summary         = $Finding.Summary
            Evidence        = $Finding.Evidence
            Source          = $Finding.Source
            ReadOnly        = $Finding.ReadOnly
            RuleEnabled     = $ConfiguredRule.Enabled
        }
    }

    $CsvPath  = Join-Path $OutputDirectory "Entra-Security-Assessment-Sample.csv"
    $JsonPath = Join-Path $OutputDirectory "Entra-Security-Assessment-Sample.json"

    $NormalizedFindings |
        Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8

    $NormalizedFindings |
        ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $JsonPath -Encoding UTF8

    $StatusSummary = [PSCustomObject]@{
        Total         = $NormalizedFindings.Count
        Pass          = @($NormalizedFindings | Where-Object Status -eq "PASS").Count
        Review        = @($NormalizedFindings | Where-Object Status -eq "REVIEW").Count
        Warning       = @($NormalizedFindings | Where-Object Status -eq "WARNING").Count
        Informational = @($NormalizedFindings | Where-Object Status -eq "INFORMATIONAL").Count
        NotAssessed   = @($NormalizedFindings | Where-Object Status -eq "NOT ASSESSED").Count
    }

    [PSCustomObject]@{
        Project         = $RulesConfiguration.Project
        SchemaVersion   = $RulesConfiguration.SchemaVersion
        Findings        = $NormalizedFindings
        StatusSummary   = $StatusSummary
        CsvOutputPath   = $CsvPath
        JsonOutputPath  = $JsonPath
        AssessmentMode  = "Offline Fictional Dataset"
        ReadOnly        = $true
    }
}
catch {
    Write-Error "Master Entra security assessment failed. $($_.Exception.Message)"
}
