# EventGuard-PS

EventGuard-PS is a PowerShell-based security event triage CLI for Windows-focused blue-team workflows. It ingests exported event data, identifies high-value security findings, and produces a readable analyst report without requiring a SIEM.

## Why this project exists

Security students and junior analysts often know Windows Event IDs in theory, but they need a practical tool that turns exported logs into actionable findings. EventGuard-PS demonstrates detection engineering, scripting, incident triage, and defensive automation in a format that is easy to explain during internships and interviews.

## Chosen stack

- PowerShell 5.1+
- Native JSON handling with no external dependencies
- Custom PowerShell test runner for portable validation

This stack fits Windows administration, IT support, and cybersecurity operations work while staying realistic for a student portfolio.

## Features in the current build

- Detects repeated failed logons within a short time window
- Detects successful logons that follow recent failures
- Detects account lockouts
- Detects new local user creation events
- Detects privileged group membership changes
- Supports text and JSON output formats
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

Run tests:

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\run-tests.ps1
```

## Example workflow

1. Export relevant security events from a Windows host or lab VM into JSON format.
2. Run EventGuard-PS against the exported file.
3. Review burst failures, suspicious successful logons, account changes, and privilege changes.
4. Use the findings as a starting point for incident triage or lab writeups.

## Future improvements

- Add EVTX and XML ingestion support
- Add MITRE ATT&CK mapping for each finding type
- Add severity scoring and suppression rules
- Generate HTML reports for case documentation
- Add Sigma-aligned detection packs

