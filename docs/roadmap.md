# EventGuard-PS Roadmap

## Current State

EventGuard-PS now has the core shape I wanted for a first finished version: Windows Security event ingestion, detection logic, ATT&CK context, suppression support, text/JSON/HTML reporting, collection helpers, malformed-record handling, strict parsing mode, and regression tests.

## Priorities

- Keep the tool focused on realistic Windows security triage workflows
- Improve the detection coverage without turning the project into a noisy rules dump
- Make the reporting useful for both analyst review and case documentation
- Keep the codebase readable, testable, and easy to maintain

## What Is Done

- Completed: ATT&CK annotations and analyst recommendations
- Completed: suppression support for rule IDs, users, machine names, and IP addresses
- Completed: XML ingestion for exported Windows Event data
- Completed: native EVTX ingestion support for offline Security log files
- Completed: HTML report export for documentation and portfolio screenshots
- Completed: expanded account-state and privileged group removal detections
- Completed: Security log collection helper for JSON, XML, and EVTX exports
- Completed: malformed-record handling with warning-aware input normalization
- Completed: strict parsing mode for automation workflows that should fail on skipped records
- Completed: repository polish with license, tags, and a clearer README

## Practical Next Steps

- Expand tests around edge cases, parsing behavior, and detection coverage
- Add collection refinements such as custom log names or tighter scope controls where they improve realism
- Add CSV export only if spreadsheet handoff becomes useful

## Notes

- Some tasks may change once implementation details or platform limitations become clearer
- If a better direction appears during development, the roadmap should be updated to match the work
