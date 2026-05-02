# File Description: Core module functions for loading exported Windows event data and producing security triage findings.
# Author: Alhasan Al-Hmondi
# Version: 0.4.0

Set-StrictMode -Version Latest

function Get-EventGuardRuleCatalog {
    <#
    .SYNOPSIS
    Returns metadata for built-in detection rules.

    .DESCRIPTION
    Centralizes ATT&CK mappings and analyst recommendations so findings
    stay consistent across text and JSON output.
    #>
    [CmdletBinding()]
    param()

    return @{
        "EVG-4625-BURST" = @{
            Tactic         = "Credential Access"
            TechniqueId    = "T1110"
            TechniqueName  = "Brute Force"
            Recommendation = "Review the source host, confirm whether the account should receive network logons, and consider blocking or resetting credentials."
        }
        "EVG-4624-AFTER-4625" = @{
            Tactic         = "Initial Access"
            TechniqueId    = "T1078"
            TechniqueName  = "Valid Accounts"
            Recommendation = "Validate whether the successful logon was expected, review adjacent host activity, and rotate credentials if compromise is suspected."
        }
        "EVG-4740-LOCKOUT" = @{
            Tactic         = "Impact"
            TechniqueId    = "T1531"
            TechniqueName  = "Account Access Removal"
            Recommendation = "Confirm whether the lockout was caused by user error, stale services, or hostile activity before unlocking the account."
        }
        "EVG-4720-NEW-USER" = @{
            Tactic         = "Persistence"
            TechniqueId    = "T1136"
            TechniqueName  = "Create Account"
            Recommendation = "Verify the request path for the new account, confirm approval records, and disable the account if it was not authorized."
        }
        "EVG-PRIV-GROUP-CHANGE" = @{
            Tactic         = "Privilege Escalation"
            TechniqueId    = "T1098"
            TechniqueName  = "Account Manipulation"
            Recommendation = "Review the change ticket, validate the actor identity, and remove the membership if the addition was not approved."
        }
    }
}

function Get-EventGuardInputFormat {
    <#
    .SYNOPSIS
    Determines which input format should be used for the event file.

    .DESCRIPTION
    Uses the file extension first and falls back to lightweight content
    inspection so analysts can process JSON or XML exports reliably.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $extension = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    switch ($extension) {
        ".json" { return "Json" }
        ".xml" { return "Xml" }
    }

    $rawContent = Get-Content -LiteralPath $Path -Raw
    $trimmedContent = $rawContent.TrimStart()

    if ($trimmedContent.StartsWith("[")) {
        return "Json"
    }

    if ($trimmedContent.StartsWith("<")) {
        return "Xml"
    }

    throw "Unsupported event input format for file: $Path"
}

function Convert-EventGuardXmlEvent {
    <#
    .SYNOPSIS
    Converts a Windows Event XML node into the normalized event shape.

    .DESCRIPTION
    Extracts core system metadata and named EventData fields so the
    detection engine can reuse the same logic across JSON and XML input.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$EventNode
    )

    $systemNode = $EventNode.System
    $eventDataValues = @{}

    if ($EventNode.EventData) {
        foreach ($dataNode in @($EventNode.EventData.Data)) {
            $fieldName = [string]$dataNode.Name
            if ([string]::IsNullOrWhiteSpace($fieldName)) {
                continue
            }

            $eventDataValues[$fieldName] = [string]$dataNode.InnerText
        }
    }

    return [PSCustomObject]@{
        Timestamp          = [string]$systemNode.TimeCreated.SystemTime
        EventId            = [int][string]$systemNode.EventID
        MachineName        = [string]$systemNode.Computer
        TargetUserName     = $eventDataValues["TargetUserName"]
        IpAddress          = $eventDataValues["IpAddress"]
        LogonType          = $eventDataValues["LogonType"]
        Status             = $eventDataValues["Status"]
        CallerComputerName = $eventDataValues["CallerComputerName"]
        SubjectUserName    = $eventDataValues["SubjectUserName"]
        GroupName          = $eventDataValues["GroupName"]
    }
}

function Import-EventGuardJsonEvents {
    <#
    .SYNOPSIS
    Loads exported event data from a JSON file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $rawContent = Get-Content -LiteralPath $Path -Raw
    return @($rawContent | ConvertFrom-Json)
}

function Import-EventGuardXmlEvents {
    <#
    .SYNOPSIS
    Loads exported event data from an XML file.

    .DESCRIPTION
    Supports Windows Event Viewer or `wevtutil` style XML exports with
    one or more `Event` nodes under a common root element.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    [xml]$xmlDocument = Get-Content -LiteralPath $Path -Raw
    $eventNodes = @($xmlDocument.SelectNodes("//*[local-name()='Event']"))

    if ($eventNodes.Count -eq 0) {
        throw "No Event nodes were found in XML input: $Path"
    }

    return @($eventNodes | ForEach-Object { Convert-EventGuardXmlEvent -EventNode $_ })
}

function Import-EventGuardEvents {
    <#
    .SYNOPSIS
    Loads exported event data from a supported file.

    .DESCRIPTION
    Reads JSON or XML Windows security event exports, normalizes
    timestamps, and returns the events sorted in chronological order.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Event input file not found: $Path"
    }

    $inputFormat = Get-EventGuardInputFormat -Path $Path
    switch ($inputFormat) {
        "Json" { $events = Import-EventGuardJsonEvents -Path $Path }
        "Xml" { $events = Import-EventGuardXmlEvents -Path $Path }
        default { throw "Unsupported event input format: $inputFormat" }
    }

    foreach ($event in $events) {
        $event | Add-Member -NotePropertyName ParsedTimestamp -NotePropertyValue ([DateTime]::Parse($event.Timestamp)) -Force
    }

    return @($events | Sort-Object -Property ParsedTimestamp)
}

function Import-EventGuardSuppressions {
    <#
    .SYNOPSIS
    Loads suppression filters from a JSON file.

    .DESCRIPTION
    Reads optional suppression criteria that can hide known-benign
    findings by rule identifier, user name, machine name, or IP address.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Suppression input file not found: $Path"
    }

    $rawContent = Get-Content -LiteralPath $Path -Raw
    $config = $rawContent | ConvertFrom-Json

    return [PSCustomObject]@{
        RuleIds      = @($config.RuleIds)
        Users        = @($config.Users)
        MachineNames = @($config.MachineNames)
        IpAddresses  = @($config.IpAddresses)
    }
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

    $ruleCatalog = Get-EventGuardRuleCatalog
    $ruleMetadata = $ruleCatalog[$RuleId]
    if (-not $ruleMetadata) {
        throw "Unknown rule metadata for RuleId: $RuleId"
    }

    return [PSCustomObject]@{
        RuleId         = $RuleId
        Severity       = $Severity
        Title          = $Title
        Summary        = $Summary
        Tactic         = $ruleMetadata.Tactic
        TechniqueId    = $ruleMetadata.TechniqueId
        TechniqueName  = $ruleMetadata.TechniqueName
        Recommendation = $ruleMetadata.Recommendation
        Evidence       = $Evidence
    }
}

function Test-EventGuardSuppressionMatch {
    <#
    .SYNOPSIS
    Determines whether a finding matches suppression criteria.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Finding,

        [Parameter(Mandatory = $true)]
        [object]$Suppressions
    )

    if ($Finding.RuleId -in $Suppressions.RuleIds) {
        return $true
    }

    if ($Finding.Evidence.PSObject.Properties.Name -contains "UserName" -and $Finding.Evidence.UserName -in $Suppressions.Users) {
        return $true
    }

    if ($Finding.Evidence.PSObject.Properties.Name -contains "MachineName" -and $Finding.Evidence.MachineName -in $Suppressions.MachineNames) {
        return $true
    }

    if ($Finding.Evidence.PSObject.Properties.Name -contains "IpAddress" -and $Finding.Evidence.IpAddress -in $Suppressions.IpAddresses) {
        return $true
    }

    return $false
}

function Remove-SuppressedEventGuardFindings {
    <#
    .SYNOPSIS
    Filters findings using optional suppression criteria.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Findings,

        [Parameter(Mandatory = $false)]
        [object]$Suppressions
    )

    if (-not $Suppressions) {
        return @($Findings)
    }

    return @(
        $Findings | Where-Object {
            -not (Test-EventGuardSuppressionMatch -Finding $_ -Suppressions $Suppressions)
        }
    )
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
        $lines += "ATT&CK: $($finding.Tactic) / $($finding.TechniqueId) $($finding.TechniqueName)"
        $lines += "Summary: $($finding.Summary)"
        $lines += "Recommendation: $($finding.Recommendation)"
        $lines += "Evidence: $($finding.Evidence | ConvertTo-Json -Compress)"
        $lines += ""
    }

    return ($lines -join [Environment]::NewLine)
}

function ConvertTo-EventGuardHtmlEncoded {
    <#
    .SYNOPSIS
    Encodes values for safe HTML rendering.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ""
    }

    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Format-EventGuardHtmlReport {
    <#
    .SYNOPSIS
    Renders a standalone HTML report.

    .DESCRIPTION
    Produces a portable HTML document for private case notes, screenshots,
    and portfolio-ready reporting without external dependencies.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Report
    )

    $findingSections = @()
    foreach ($finding in $Report.Findings) {
        $evidenceRows = foreach ($property in $finding.Evidence.PSObject.Properties) {
            $propertyName = ConvertTo-EventGuardHtmlEncoded -Value $property.Name
            $propertyValue = ConvertTo-EventGuardHtmlEncoded -Value $property.Value
            "<tr><th>$propertyName</th><td>$propertyValue</td></tr>"
        }

        $severityClass = $finding.Severity.ToLowerInvariant()
        $findingSections += @"
        <section class="finding $severityClass">
            <div class="finding-header">
                <span class="badge">$($finding.Severity)</span>
                <h2>$(ConvertTo-EventGuardHtmlEncoded -Value $finding.Title)</h2>
            </div>
            <p class="summary">$(ConvertTo-EventGuardHtmlEncoded -Value $finding.Summary)</p>
            <dl class="metadata">
                <div>
                    <dt>Rule</dt>
                    <dd>$(ConvertTo-EventGuardHtmlEncoded -Value $finding.RuleId)</dd>
                </div>
                <div>
                    <dt>ATT&amp;CK</dt>
                    <dd>$(ConvertTo-EventGuardHtmlEncoded -Value $finding.Tactic) / $(ConvertTo-EventGuardHtmlEncoded -Value $finding.TechniqueId) $(ConvertTo-EventGuardHtmlEncoded -Value $finding.TechniqueName)</dd>
                </div>
            </dl>
            <div class="recommendation">
                <h3>Analyst Recommendation</h3>
                <p>$(ConvertTo-EventGuardHtmlEncoded -Value $finding.Recommendation)</p>
            </div>
            <table>
                <thead>
                    <tr><th>Evidence Field</th><th>Value</th></tr>
                </thead>
                <tbody>
                    $($evidenceRows -join [Environment]::NewLine)
                </tbody>
            </table>
        </section>
"@
    }

    if ($findingSections.Count -eq 0) {
        $findingsMarkup = '<section class="empty-state"><p>No findings detected.</p></section>'
    }
    else {
        $findingsMarkup = $findingSections -join [Environment]::NewLine
    }

    $suppressionsPath = if ($Report.SuppressionsPath) {
        ConvertTo-EventGuardHtmlEncoded -Value $Report.SuppressionsPath
    }
    else {
        "None"
    }

    return @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>EventGuard-PS Security Triage Report</title>
    <style>
        :root {
            color-scheme: light;
            --bg: #f4f7f6;
            --panel: #ffffff;
            --ink: #17212b;
            --muted: #526171;
            --border: #d4dde6;
            --accent: #0f766e;
            --high: #b42318;
            --medium: #b54708;
            --low: #175cd3;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: "Segoe UI", Tahoma, sans-serif;
            background: linear-gradient(180deg, #edf6f3 0%, #f8fafc 100%);
            color: var(--ink);
        }
        .page {
            max-width: 1120px;
            margin: 0 auto;
            padding: 32px 20px 48px;
        }
        .hero, .finding, .empty-state {
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 18px;
            box-shadow: 0 12px 30px rgba(15, 23, 42, 0.08);
        }
        .hero {
            padding: 28px;
            margin-bottom: 24px;
        }
        h1, h2, h3, p { margin-top: 0; }
        h1 {
            margin-bottom: 10px;
            font-size: 2rem;
        }
        .lede, .summary, .recommendation p, .footer-note {
            color: var(--muted);
            line-height: 1.6;
        }
        .report-meta, .summary-grid, .metadata {
            display: grid;
            gap: 12px;
        }
        .report-meta {
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            margin-top: 24px;
        }
        .summary-grid {
            grid-template-columns: repeat(3, minmax(0, 1fr));
            margin: 24px 0;
        }
        .metadata {
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            margin: 16px 0;
        }
        .meta-card, .summary-card, .metadata div {
            background: #f8fafc;
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 14px 16px;
        }
        .meta-card .label, .summary-card .label, dt {
            display: block;
            margin-bottom: 6px;
            font-size: 0.82rem;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }
        .meta-card .value, .summary-card .value, dd {
            font-weight: 600;
            margin: 0;
            word-break: break-word;
        }
        .summary-card {
            border-top: 4px solid var(--accent);
        }
        .summary-card.high { border-top-color: var(--high); }
        .summary-card.medium { border-top-color: var(--medium); }
        .summary-card.low { border-top-color: var(--low); }
        .summary-card .value { font-size: 1.6rem; }
        .findings {
            display: grid;
            gap: 18px;
        }
        .finding, .empty-state {
            padding: 22px;
        }
        .finding.high { border-left: 6px solid var(--high); }
        .finding.medium { border-left: 6px solid var(--medium); }
        .finding.low { border-left: 6px solid var(--low); }
        .finding-header {
            display: flex;
            gap: 12px;
            align-items: center;
            margin-bottom: 12px;
        }
        .badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 78px;
            padding: 6px 10px;
            border-radius: 999px;
            font-size: 0.85rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }
        .finding.high .badge { background: #fdecea; color: var(--high); }
        .finding.medium .badge { background: #fff1e6; color: var(--medium); }
        .finding.low .badge { background: #e8f1ff; color: var(--low); }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 14px;
        }
        th, td {
            text-align: left;
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }
        th {
            width: 34%;
            color: var(--muted);
            font-weight: 600;
        }
        @media (max-width: 720px) {
            .summary-grid {
                grid-template-columns: 1fr;
            }
            .finding-header {
                flex-direction: column;
                align-items: flex-start;
            }
        }
    </style>
</head>
<body>
    <main class="page">
        <section class="hero">
            <h1>EventGuard-PS Security Triage Report</h1>
            <p class="lede">Offline Windows security event triage output for analyst review, private documentation, and portfolio-ready reporting.</p>
            <div class="report-meta">
                <article class="meta-card">
                    <span class="label">Input Path</span>
                    <span class="value">$(ConvertTo-EventGuardHtmlEncoded -Value $Report.InputPath)</span>
                </article>
                <article class="meta-card">
                    <span class="label">Generated At (UTC)</span>
                    <span class="value">$(ConvertTo-EventGuardHtmlEncoded -Value $Report.GeneratedAtUtc)</span>
                </article>
                <article class="meta-card">
                    <span class="label">Event Count</span>
                    <span class="value">$($Report.EventCount)</span>
                </article>
                <article class="meta-card">
                    <span class="label">Suppressions</span>
                    <span class="value">$suppressionsPath</span>
                </article>
            </div>
            <div class="summary-grid">
                <article class="summary-card high">
                    <span class="label">High</span>
                    <span class="value">$($Report.SeveritySummary.High)</span>
                </article>
                <article class="summary-card medium">
                    <span class="label">Medium</span>
                    <span class="value">$($Report.SeveritySummary.Medium)</span>
                </article>
                <article class="summary-card low">
                    <span class="label">Low</span>
                    <span class="value">$($Report.SeveritySummary.Low)</span>
                </article>
            </div>
            <p class="footer-note">Findings: $($Report.Findings.Count) | Exit Code: $($Report.ExitCode)</p>
        </section>
        <section class="findings">
            $findingsMarkup
        </section>
    </main>
</body>
</html>
"@
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
        [string]$Path,

        [string]$SuppressionsPath
    )

    $events = Import-EventGuardEvents -Path $Path
    $suppressions = $null
    if ($SuppressionsPath) {
        $suppressions = Import-EventGuardSuppressions -Path $SuppressionsPath
    }

    $findings = @()
    $findings += Find-FailedLogonBursts -Events $events
    $findings += Find-SuccessAfterFailures -Events $events
    $findings += Find-AccountLockouts -Events $events
    $findings += Find-NewUsers -Events $events
    $findings += Find-PrivilegedGroupChanges -Events $events

    $filteredFindings = Remove-SuppressedEventGuardFindings -Findings $findings -Suppressions $suppressions
    $sortedFindings = @($filteredFindings | Sort-Object -Property Severity, RuleId)
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
        Version        = "0.4.0"
        InputPath      = (Resolve-Path -LiteralPath $Path).Path
        GeneratedAtUtc = [DateTime]::UtcNow.ToString("o")
        EventCount     = $events.Count
        SuppressionsPath = $(if ($SuppressionsPath) { (Resolve-Path -LiteralPath $SuppressionsPath).Path } else { $null })
        SeveritySummary = $severitySummary
        ExitCode        = $exitCode
        Findings       = $sortedFindings
    }
}

Export-ModuleMember -Function @(
    "Import-EventGuardEvents",
    "Invoke-EventGuardScan",
    "Format-EventGuardTextReport",
    "Format-EventGuardHtmlReport"
)
