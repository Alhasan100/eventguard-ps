# File Description: Lightweight test runner for validating EventGuard-PS detections and report output.
# Author: Alhasan Al-Hmondi
# Version: 0.4.0

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$moduleManifestPath = Join-Path $PSScriptRoot "..\src\EventGuard.psd1"
$samplePath = Join-Path $PSScriptRoot "..\examples\security-events.json"
$xmlSamplePath = Join-Path $PSScriptRoot "..\examples\security-events.xml"
$suppressionPath = Join-Path $PSScriptRoot "..\examples\suppressions.json"
$htmlOutputPath = Join-Path $env:TEMP "eventguard-test-report.html"
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
$htmlReport = Format-EventGuardHtmlReport -Report $report
$xmlReport = Invoke-EventGuardScan -Path $xmlSamplePath
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
Assert-Match -Value $htmlReport -Pattern "<!DOCTYPE html>" -Message "HTML report should be a full document"
Assert-Match -Value $htmlReport -Pattern "EventGuard-PS Security Triage Report" -Message "HTML report title should be present"
Assert-Match -Value $htmlReport -Pattern "Repeated failed logons detected" -Message "HTML report should include findings"
Assert-Equal -Actual $xmlReport.EventCount -Expected 8 -Message "XML event count should match"
Assert-Equal -Actual $xmlReport.Findings.Count -Expected 5 -Message "XML findings count should match JSON behavior"
Assert-Equal -Actual $xmlReport.ExitCode -Expected 20 -Message "XML report should preserve severity-based exit codes"
Assert-Equal -Actual $xmlReport.Findings[0].RuleId -Expected $report.Findings[0].RuleId -Message "XML and JSON ordering should match for the sample dataset"
Assert-Equal -Actual $suppressedReport.Findings.Count -Expected 2 -Message "Suppression rules should reduce the finding count"
Assert-Equal -Actual $suppressedReport.SeveritySummary.High -Expected 0 -Message "Suppression rules should remove high severity findings"
Assert-Equal -Actual $suppressedReport.SeveritySummary.Medium -Expected 2 -Message "Suppression rules should retain only medium severity findings"
Assert-Equal -Actual $suppressedReport.ExitCode -Expected 10 -Message "Exit code should reflect the highest remaining severity"

& (Join-Path $PSScriptRoot "..\scripts\invoke-eventguard.ps1") -Path $samplePath -Format Html -OutputPath $htmlOutputPath | Out-Null
Assert-Equal -Actual (Test-Path -LiteralPath $htmlOutputPath) -Expected $true -Message "CLI HTML export should write an output file"
$savedHtmlReport = Get-Content -LiteralPath $htmlOutputPath -Raw
Assert-Match -Value $savedHtmlReport -Pattern "Exit Code: 20" -Message "Saved HTML report should include exit code context"
Remove-Item -LiteralPath $htmlOutputPath -Force

Write-Output "All EventGuard-PS tests passed."
