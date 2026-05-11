# File Description: PowerShell module manifest for EventGuard-PS exports and metadata.
# Author: Alhasan Al-Hmondi
# Version: 1.0.0

@{
    RootModule        = 'EventGuard.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '4ea937f1-3f97-4a4e-9841-f1473e3ef6d4'
    Author            = 'Alhasan Al-Hmondi'
    CompanyName       = 'Personal Portfolio'
    Copyright         = '(c) Alhasan Al-Hmondi. Licensed under GPL-3.0.'
    Description       = 'Windows security event triage module for offline detection and reporting.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Export-EventGuardCollectedEvents',
        'Import-EventGuardEvents',
        'Invoke-EventGuardScan',
        'Format-EventGuardTextReport',
        'Format-EventGuardHtmlReport'
    )
}
