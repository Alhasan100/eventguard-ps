# File Description: Core module functions for loading exported Windows event data and producing security triage findings.
# Author: Alhasan Al-Hmondi
# Version: 0.1.0

Set-StrictMode -Version Latest

function Import-EventGuardEvents {
    <#
    .SYNOPSIS
    Loads exported event data from a JSON file.

    .DESCRIPTION
    Reads a JSON array of Windows security events, normalizes timestamps,
    and returns the events sorted in chronological order.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Event input file not found: $Path"
    }

    $rawContent = Get-Content -LiteralPath $Path -Raw
    $events = $rawContent | ConvertFrom-Json

    foreach ($event in $events) {
        $event | Add-Member -NotePropertyName ParsedTimestamp -NotePropertyValue ([DateTime]::Parse($event.Timestamp)) -Force
    }

    return @($events | Sort-Object -Property ParsedTimestamp)
}

function New-EventGuardFinding {
    <#
    .SYNOPSIS
    Creates a standardized finding object.

    .DESCRIPTION
    Produces a consistent data structure for detections so text and JSON
    rendering can share the same underlying finding shape.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RuleId,

        [Parameter(Mandatory = $true)]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$Summary,

        [Parameter(Mandatory = $true)]
        [object]$Evidence
    )

    return [PSCustomObject]@{
        RuleId   = $RuleId
        Severity = $Severity
        Title    = $Title
        Summary  = $Summary
        Evidence = $Evidence
    }
}

function Find-FailedLogonBursts {
    <#
    .SYNOPSIS
    Detects repeated failed logons within a short time window.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Events,

        [int]$Threshold = 4,

        [int]$WindowMinutes = 10
    )

    $failedEvents = @($Events | Where-Object { $_.EventId -eq 4625 })
    $groupedEvents = $failedEvents | Group-Object -Property TargetUserName, IpAddress
    $findings = @()

    foreach ($group in $groupedEvents) {
        $orderedGroup = @($group.Group | Sort-Object -Property ParsedTimestamp)
        if ($orderedGroup.Count -lt $Threshold) {
            continue
        }

        $windowStart = $orderedGroup[0].ParsedTimestamp
        $windowEnd = $orderedGroup[$Threshold - 1].ParsedTimestamp
        $windowSize = ($windowEnd - $windowStart).TotalMinutes

        if ($windowSize -le $WindowMinutes) {
            $findings += New-EventGuardFinding `
                -RuleId "EVG-4625-BURST" `
                -Severity "High" `
                -Title "Repeated failed logons detected" `
                -Summary "Detected $($orderedGroup.Count) failed logons for $($orderedGroup[0].TargetUserName) from $($orderedGroup[0].IpAddress)." `
                -Evidence ([PSCustomObject]@{
                    UserName     = $orderedGroup[0].TargetUserName
                    IpAddress    = $orderedGroup[0].IpAddress
                    Count        = $orderedGroup.Count
                    FirstSeenUtc = $orderedGroup[0].Timestamp
                    LastSeenUtc  = $orderedGroup[-1].Timestamp
                })
        }
    }

    return $findings
}

function Find-SuccessAfterFailures {
    <#
    .SYNOPSIS
    Detects successful logons that follow recent failed attempts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Events,

        [int]$LookbackMinutes = 15
    )

    $findings = @()
    $failedEvents = @($Events | Where-Object { $_.EventId -eq 4625 })
    $successfulEvents = @($Events | Where-Object { $_.EventId -eq 4624 })

    foreach ($successEvent in $successfulEvents) {
        $recentFailures = @(
            $failedEvents | Where-Object {
                $_.TargetUserName -eq $successEvent.TargetUserName -and
                $_.IpAddress -eq $successEvent.IpAddress -and
                $_.ParsedTimestamp -lt $successEvent.ParsedTimestamp -and
                (($successEvent.ParsedTimestamp - $_.ParsedTimestamp).TotalMinutes -le $LookbackMinutes)
            }
        )

        if ($recentFailures.Count -gt 0) {
            $findings += New-EventGuardFinding `
                -RuleId "EVG-4624-AFTER-4625" `
                -Severity "Medium" `
                -Title "Successful logon followed recent failures" `
                -Summary "User $($successEvent.TargetUserName) logged on successfully after $($recentFailures.Count) recent failures from $($successEvent.IpAddress)." `
                -Evidence ([PSCustomObject]@{
                    UserName         = $successEvent.TargetUserName
                    IpAddress        = $successEvent.IpAddress
                    SuccessTimeUtc   = $successEvent.Timestamp
                    FailureCount     = $recentFailures.Count
                    EarliestFailure  = $recentFailures[0].Timestamp
                    LatestFailure    = $recentFailures[-1].Timestamp
                })
        }
    }

    return $findings
}

function Find-AccountLockouts {
    <#
    .SYNOPSIS
    Detects account lockout events.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Events
    )

    $findings = foreach ($event in ($Events | Where-Object { $_.EventId -eq 4740 })) {
        New-EventGuardFinding `
            -RuleId "EVG-4740-LOCKOUT" `
            -Severity "Medium" `
            -Title "Account lockout detected" `
            -Summary "Account $($event.TargetUserName) was locked out from caller $($event.CallerComputerName)." `
            -Evidence ([PSCustomObject]@{
                UserName           = $event.TargetUserName
                CallerComputerName = $event.CallerComputerName
                TimeUtc            = $event.Timestamp
            })
    }

    return @($findings)
}

function Find-NewUsers {
    <#
    .SYNOPSIS
    Detects new user creation events.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Events
    )

    $findings = foreach ($event in ($Events | Where-Object { $_.EventId -eq 4720 })) {
        New-EventGuardFinding `
            -RuleId "EVG-4720-NEW-USER" `
            -Severity "High" `
            -Title "New user account created" `
            -Summary "Account $($event.TargetUserName) was created by $($event.SubjectUserName)." `
            -Evidence ([PSCustomObject]@{
                UserName       = $event.TargetUserName
                CreatedBy      = $event.SubjectUserName
                TimeUtc        = $event.Timestamp
                MachineName    = $event.MachineName
            })
    }

    return @($findings)
}

function Find-PrivilegedGroupChanges {
    <#
    .SYNOPSIS
    Detects changes to privileged local or domain groups.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Events
    )

    $privilegedGroupNames = @("Administrators", "Domain Admins", "Enterprise Admins", "Remote Desktop Users")
    $supportedEventIds = @(4728, 4732, 4756)

    $findings = foreach ($event in ($Events | Where-Object { $_.EventId -in $supportedEventIds -and $_.GroupName -in $privilegedGroupNames })) {
        New-EventGuardFinding `
            -RuleId "EVG-PRIV-GROUP-CHANGE" `
            -Severity "High" `
            -Title "Privileged group membership changed" `
            -Summary "User $($event.TargetUserName) was added to privileged group $($event.GroupName) by $($event.SubjectUserName)." `
            -Evidence ([PSCustomObject]@{
                UserName    = $event.TargetUserName
                GroupName   = $event.GroupName
                ChangedBy   = $event.SubjectUserName
                TimeUtc     = $event.Timestamp
                MachineName = $event.MachineName
            })
    }

    return @($findings)
}

function Format-EventGuardTextReport {
    <#
    .SYNOPSIS
    Renders a human-readable text report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Report
    )

    $severitySummary = "High=$($Report.SeveritySummary.High); Medium=$($Report.SeveritySummary.Medium); Low=$($Report.SeveritySummary.Low)"

    $lines = @(
        "EventGuard-PS Security Triage Report"
        "Input Path: $($Report.InputPath)"
        "Event Count: $($Report.EventCount)"
        "Generated At (UTC): $($Report.GeneratedAtUtc)"
        "Finding Count: $($Report.Findings.Count)"
        "Severity Summary: $severitySummary"
        ""
    )

    if ($Report.Findings.Count -eq 0) {
        $lines += "No findings detected."
        return ($lines -join [Environment]::NewLine)
    }

    foreach ($finding in $Report.Findings) {
        $lines += "[$($finding.Severity)] $($finding.Title)"
        $lines += "Rule: $($finding.RuleId)"
        $lines += "Summary: $($finding.Summary)"
        $lines += "Evidence: $($finding.Evidence | ConvertTo-Json -Compress)"
        $lines += ""
    }

    return ($lines -join [Environment]::NewLine)
}

function Invoke-EventGuardScan {
    <#
    .SYNOPSIS
    Executes the end-to-end security event triage workflow.

    .DESCRIPTION
    Loads event data, executes all enabled detections, and returns a
    report object suitable for text or JSON rendering.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $events = Import-EventGuardEvents -Path $Path
    $findings = @()
    $findings += Find-FailedLogonBursts -Events $events
    $findings += Find-SuccessAfterFailures -Events $events
    $findings += Find-AccountLockouts -Events $events
    $findings += Find-NewUsers -Events $events
    $findings += Find-PrivilegedGroupChanges -Events $events

    $sortedFindings = @($findings | Sort-Object -Property Severity, RuleId)
    $severitySummary = [PSCustomObject]@{
        High   = @($sortedFindings | Where-Object { $_.Severity -eq "High" }).Count
        Medium = @($sortedFindings | Where-Object { $_.Severity -eq "Medium" }).Count
        Low    = @($sortedFindings | Where-Object { $_.Severity -eq "Low" }).Count
    }

    $exitCode = 0
    if ($severitySummary.High -gt 0) {
        $exitCode = 20
    }
    elseif ($severitySummary.Medium -gt 0) {
        $exitCode = 10
    }

    return [PSCustomObject]@{
        ToolName       = "EventGuard-PS"
        Version        = "0.1.0"
        InputPath      = (Resolve-Path -LiteralPath $Path).Path
        GeneratedAtUtc = [DateTime]::UtcNow.ToString("o")
        EventCount     = $events.Count
        SeveritySummary = $severitySummary
        ExitCode        = $exitCode
        Findings       = $sortedFindings
    }
}

Export-ModuleMember -Function @(
    "Import-EventGuardEvents",
    "Invoke-EventGuardScan",
    "Format-EventGuardTextReport"
)
