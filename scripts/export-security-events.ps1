# File Description: Collection helper for exporting recent Windows Security events into EventGuard-PS input formats.
# Author: Alhasan Al-Hmondi
# Version: 1.0.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [ValidateSet("Json", "Xml", "Evtx")]
    [string]$Format = "Json",

    [int]$HoursBack = 24,

    [int]$MaxEvents = 500,

    [int[]]$EventIds
)

$moduleManifestPath = Join-Path $PSScriptRoot "..\src\EventGuard.psd1"
Import-Module $moduleManifestPath -Force

$exportParams = @{
    OutputPath = $OutputPath
    Format     = $Format
    HoursBack  = $HoursBack
    MaxEvents  = $MaxEvents
}

if ($PSBoundParameters.ContainsKey("EventIds")) {
    $exportParams["EventIds"] = $EventIds
}

$result = Export-EventGuardCollectedEvents @exportParams
$result
