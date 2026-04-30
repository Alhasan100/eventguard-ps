# File Description: CLI entrypoint for running EventGuard-PS against exported Windows security events.
# Author: Alhasan Al-Hmondi
# Version: 0.1.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [ValidateSet("Text", "Json")]
    [string]$Format = "Text"
)

$moduleManifestPath = Join-Path $PSScriptRoot "..\src\EventGuard.psd1"
Import-Module $moduleManifestPath -Force

$report = Invoke-EventGuardScan -Path $Path

if ($Format -eq "Json") {
    $report | ConvertTo-Json -Depth 6
    exit $report.ExitCode
}

Format-EventGuardTextReport -Report $report
exit $report.ExitCode
