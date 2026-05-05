# File Description: PowerShell module manifest for EventGuard-PS exports and metadata.
# Author: Alhasan Al-Hmondi
# Version: 0.8.0

@{
    RootModule        = 'EventGuard.psm1'
    ModuleVersion     = '0.8.0'
    GUID              = '4ea937f1-3f97-4a4e-9841-f1473e3ef6d4'
    Author            = 'Alhasan Al-Hmondi'
    CompanyName       = 'Personal Portfolio'
    Copyright         = '(c) Alhasan Al-Hmondi. All rights reserved.'
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
