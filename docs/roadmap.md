# EventGuard-PS Roadmap

## Purpose

This document tracks where I want to take EventGuard-PS next. It is meant to keep the project focused, while still leaving room to adjust when testing, platform limits, or better ideas change the priority.

## Priorities

- Keep the tool focused on realistic Windows security triage workflows
- Improve the detection coverage without turning the project into a noisy rules dump
- Make the reporting useful for both analyst review and case documentation
- Keep the codebase readable, testable, and easy to maintain

## Current status

- Completed: ATT&CK annotations and analyst recommendations
- Completed: suppression support for rule IDs, users, machine names, and IP addresses
- Completed: XML ingestion for exported Windows Event data
- Completed: native EVTX ingestion support for offline Security log files
- Completed: HTML report export for documentation and portfolio screenshots
- Completed: expanded account-state and privileged group removal detections
- Current focus: final hardening, edge-case validation, and workflow polish

## Next steps

- Improve the examples so they reflect a cleaner analyst workflow
- Expand tests around edge cases, parsing behavior, and detection coverage
- Tighten the README and project explanations so the project is easier to review

## Notes

- Some tasks may change once implementation details or platform limitations become clearer
- If a better direction appears during development, the roadmap should be updated to match the work
