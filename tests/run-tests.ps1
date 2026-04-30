# File Description: Lightweight test runner for validating EventGuard-PS detections and report output.
# Author: Alhasan Al-Hmondi
# Version: 0.2.0

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$moduleManifestPath = Join-Path $PSScriptRoot "..\src\EventGuard.psd1"
$samplePath = Join-Path $PSScriptRoot "..\examples\security-events.json"
$suppressionPath = Join-Path $PSScriptRoot "..\examples\suppressions.json"
Import-Module $moduleManifestPath -Force

function Assert-Equal {
    <#
    .SYNOPSIS
    Verifies that two values are equal.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Actual,

        [Parameter(Mandatory = $true)]
        $Expected,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($Actual -ne $Expected) {
        throw "$Message. Expected '$Expected' but received '$Actual'."
    }
}

function Assert-Match {
    <#
    .SYNOPSIS
    Verifies that a string matches a regular expression.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Pattern,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($Value -notmatch $Pattern) {
        throw "$Message. Pattern '$Pattern' was not found."
    }
}

$report = Invoke-EventGuardScan -Path $samplePath
$textReport = Format-EventGuardTextReport -Report $report
$suppressedReport = Invoke-EventGuardScan -Path $samplePath -SuppressionsPath $suppressionPath

Assert-Equal -Actual $report.EventCount -Expected 8 -Message "Sample event count should match"
Assert-Equal -Actual $report.Findings.Count -Expected 5 -Message "Sample findings count should match"
Assert-Equal -Actual $report.SeveritySummary.High -Expected 3 -Message "High severity summary should match"
Assert-Equal -Actual $report.SeveritySummary.Medium -Expected 2 -Message "Medium severity summary should match"
Assert-Equal -Actual $report.ExitCode -Expected 20 -Message "Exit code should reflect high severity findings"
Assert-Equal -Actual $report.Findings[0].TechniqueId -Expected "T1110" -Message "ATT&CK technique mapping should be included"
Assert-Match -Value $textReport -Pattern "ATT&CK: Credential Access / T1110 Brute Force" -Message "ATT&CK metadata should appear in text report"
Assert-Match -Value $textReport -Pattern "Recommendation:" -Message "Analyst recommendation should appear in text report"
Assert-Match -Value $textReport -Pattern "Repeated failed logons detected" -Message "Burst detection should appear in text report"
Assert-Match -Value $textReport -Pattern "Severity Summary: High=3; Medium=2; Low=0" -Message "Severity summary should appear in text report"
Assert-Match -Value $textReport -Pattern "Privileged group membership changed" -Message "Privileged group change should appear in text report"
Assert-Equal -Actual $suppressedReport.Findings.Count -Expected 2 -Message "Suppression rules should reduce the finding count"
Assert-Equal -Actual $suppressedReport.SeveritySummary.High -Expected 0 -Message "Suppression rules should remove high severity findings"
Assert-Equal -Actual $suppressedReport.SeveritySummary.Medium -Expected 2 -Message "Suppression rules should retain only medium severity findings"
Assert-Equal -Actual $suppressedReport.ExitCode -Expected 10 -Message "Exit code should reflect the highest remaining severity"

Write-Output "All EventGuard-PS tests passed."
