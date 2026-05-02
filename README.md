# EventGuard-PS

EventGuard-PS is a PowerShell-based security event triage CLI for Windows-focused blue-team workflows. I built it to help turn exported Windows security events into findings that are easier to review, explain, and document without needing a full SIEM.

## Why this project exists

I wanted a project that reflects the kind of work I am interested in: Windows security monitoring, scripting, and practical defensive tooling. Instead of building a generic demo, I focused on a CLI that can ingest exported event data, highlight suspicious activity, and produce outputs that are useful for triage, lab work, and documentation.

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
- Detects account password resets plus account enable and disable actions
- Detects privileged group membership additions and removals
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
5. Export an HTML report when you want a cleaner artifact for screenshots, documentation, or case notes.
6. Add suppressions for approved admin activity so recurring triage reports stay focused.

## Future improvements

- Add direct EVTX ingestion support for native Windows log files
- Add event collection helper scripts for lab endpoints
- Expand suppression logic with time-based exceptions and rule comments
- Add Sigma-aligned detection packs
