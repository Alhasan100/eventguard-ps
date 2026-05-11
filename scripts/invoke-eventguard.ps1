# File Description: CLI entrypoint for running EventGuard-PS against exported Windows security events.
# Author: Alhasan Al-Hmondi
# Version: 1.0.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$SuppressionsPath,

    [ValidateSet("Text", "Json", "Html")]
    [string]$Format = "Text",

    [string]$OutputPath,

    [switch]$StrictParsing
)

$moduleManifestPath = Join-Path $PSScriptRoot "..\src\EventGuard.psd1"
Import-Module $moduleManifestPath -Force

$report = Invoke-EventGuardScan -Path $Path -SuppressionsPath $SuppressionsPath -StrictParsing:$StrictParsing

if ($Format -eq "Json") {
    $jsonOutput = $report | ConvertTo-Json -Depth 6
    if ($OutputPath) {
        $jsonOutput | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    }
    else {
        $jsonOutput
    }
    exit $report.ExitCode
}

$renderedOutput = if ($Format -eq "Html") {
    Format-EventGuardHtmlReport -Report $report
}
else {
    Format-EventGuardTextReport -Report $report
}

if ($OutputPath) {
    $renderedOutput | Set-Content -LiteralPath $OutputPath -Encoding UTF8
}
else {
    $renderedOutput
}

exit $report.ExitCode
