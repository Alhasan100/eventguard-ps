# EventGuard-PS

EventGuard-PS is a PowerShell-based security event triage CLI for Windows-focused blue-team workflows. It ingests exported event data, identifies high-value security findings, and produces a readable analyst report without requiring a SIEM.

## Why this project exists

Security students and junior analysts often know Windows Event IDs in theory, but they need a practical tool that turns exported logs into actionable findings. EventGuard-PS demonstrates detection engineering, scripting, incident triage, and defensive automation in a format that is easy to explain during internships and interviews.

## Chosen stack

- PowerShell 5.1+
- Native JSON handling with no external dependencies
- Native XML parsing for exported Windows events
- Custom PowerShell test runner for portable validation

This stack fits Windows administration, IT support, and cybersecurity operations work while staying realistic for a student portfolio.

## Features in the current build

- Detects repeated failed logons within a short time window
- Detects successful logons that follow recent failures
- Detects account lockouts
- Detects new local user creation events
- Detects privileged group membership changes
- Maps findings to MITRE ATT&CK tactics and techniques
- Includes analyst recommendations in each finding
- Supports suppression files for known-benign rules, users, hosts, or IPs
- Supports text, JSON, and standalone HTML output formats
- Supports JSON arrays and Windows Event XML exports as input
- Includes sample event data for offline testing

## Project structure

```text
eventguard-ps/
  docs/
  examples/
  scripts/
  src/
  tests/
```

## Installation

1. Open PowerShell in the project directory.
2. Run the CLI with the bundled sample data:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\invoke-eventguard.ps1 -Path .\examples\security-events.json
```

## Usage

Text report:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\invoke-eventguard.ps1 -Path .\examples\security-events.json -Format Text
```

JSON report:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\invoke-eventguard.ps1 -Path .\examples\security-events.json -Format Json
```

XML input report:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\invoke-eventguard.ps1 -Path .\examples\security-events.xml -Format Text
```

HTML report export:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\invoke-eventguard.ps1 -Path .\examples\security-events.xml -Format Html -OutputPath .\reports\security-events.html
```

Report with suppressions:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\invoke-eventguard.ps1 -Path .\examples\security-events.json -SuppressionsPath .\examples\suppressions.json -Format Text
```

Run tests:

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\run-tests.ps1
```

## Example workflow

1. Export relevant security events from a Windows host or lab VM into JSON or XML format.
2. Run EventGuard-PS against the exported file.
3. Review burst failures, suspicious successful logons, account changes, and privilege changes with the ATT&CK mapping and analyst recommendations.
4. Use the findings as a starting point for incident triage or lab writeups.
5. Export an HTML report when you want a cleaner artifact for screenshots, documentation, or a portfolio walkthrough.
6. Add suppressions for approved admin activity so recurring triage reports stay focused.

## Future improvements

- Add EVTX ingestion support for direct `.evtx` processing
- Add richer account and group change detections
- Expand suppression logic with time-based exceptions and rule comments
- Add direct EVTX ingestion support for native Windows log files
- Add Sigma-aligned detection packs
