# EventGuard-PS

**Version:** 1.0.0 | **Author:** Alhasan Al-Hmondi

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

EventGuard-PS is a PowerShell-based security event triage CLI for Windows-focused blue-team workflows. It turns exported Windows Security events into findings that are easier to review, explain, and document without needing a full SIEM.

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
- Supports JSON arrays, Windows Event XML exports, and native EVTX files as input
- Skips malformed or incomplete records with explicit parse warnings instead of failing the whole scan
- Includes a collection helper that exports recent Security log data from a Windows lab host into EventGuard-ready files
- Includes sample event data for offline testing
- Supports strict parsing mode for automation workflows that should fail when records are skipped

## Project structure

```text
eventguard-ps/
  docs/
  examples/
  LICENSE
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

EVTX input report:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\invoke-eventguard.ps1 -Path .\exports\Security.evtx -Format Text
```

Collect recent Security log events into JSON:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\export-security-events.ps1 -OutputPath .\reports\lab-security-events.json -Format Json -HoursBack 12 -MaxEvents 300
```

Collect recent Security log events into XML:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\export-security-events.ps1 -OutputPath .\reports\lab-security-events.xml -Format Xml -HoursBack 12
```

Collect recent Security log events into EVTX:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\export-security-events.ps1 -OutputPath .\reports\lab-security-events.evtx -Format Evtx -HoursBack 12
```

HTML report export:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\invoke-eventguard.ps1 -Path .\examples\security-events.xml -Format Html -OutputPath .\reports\security-events.html
```

Report with suppressions:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\invoke-eventguard.ps1 -Path .\examples\security-events.json -SuppressionsPath .\examples\suppressions.json -Format Text
```

Strict parsing mode:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\invoke-eventguard.ps1 -Path .\examples\security-events.json -StrictParsing
```

Run tests:

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\run-tests.ps1
```

## Example workflow

1. Use the collection helper on a Windows host or lab VM to export recent Security log activity into JSON, XML, or EVTX.
2. Run EventGuard-PS against the exported file.
3. Review burst failures, suspicious successful logons, account changes, and privilege changes with the ATT&CK mapping and analyst recommendations.
4. Export an HTML report when you want a cleaner artifact for screenshots, documentation, or case notes.
5. Add suppressions for approved admin activity so recurring triage reports stay focused.
6. Review any parse warnings so you can spot broken exports or incomplete records before trusting the full result.
7. Use the results as a starting point for incident triage, lab notes, or detection tuning.

## Final scope

This version is intentionally focused on Windows Security event triage. It covers ingestion, detection, suppression, reporting, collection helpers, malformed-record handling, and automation-friendly exit codes without turning into a large SIEM replacement.

## Future improvements

- Expand suppression logic with time-based exceptions and rule comments
- Add Sigma-aligned detection packs
- Add CSV export if spreadsheet handoff becomes useful

## License

This project is licensed under the GNU General Public License v3.0. See `LICENSE` for the full license text.
