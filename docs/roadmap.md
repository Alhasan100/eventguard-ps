# EventGuard-PS Roadmap

## Working direction

This roadmap is meant to stay practical rather than rigid. The goal is to keep moving the project forward in a way that makes sense as the implementation evolves, while leaving room for new issues, better ideas, and unexpected constraints.

## Core priorities

- Keep the tool focused on realistic Windows security triage workflows
- Improve the detection coverage without turning the project into a noisy rules dump
- Make the reporting useful for both analyst review and portfolio presentation
- Keep the codebase readable, testable, and easy to explain in an interview

## Progress update

- Completed: ATT&CK annotations and analyst recommendations
- Completed: suppression support for rule IDs, users, machine names, and IP addresses
- Completed: XML ingestion for exported Windows Event data
- Completed: HTML report export for documentation and portfolio screenshots
- Completed: expanded account-state and privileged group removal detections
- Current focus: improve documentation and final hardening

## Likely next steps

- Improve the examples so the project feels closer to a realistic analyst workflow
- Add EVTX workflow notes or native ingestion if the environment supports it cleanly
- Expand tests around edge cases, parsing behavior, and detection coverage
- Tighten the README and project explanations so the portfolio story is clearer

## Notes

- Some tasks may change once implementation details or platform limitations become clearer
- If a better direction appears during development, the roadmap should adapt instead of pretending the original plan was perfect
