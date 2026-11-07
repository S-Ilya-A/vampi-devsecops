# Submission note

Copy this file to `NOTE.md` in the repository root and fill in every section.

## 1. Summary

Three to five sentences: what you built and the state it is in.

## 2. How to run it

Exact commands from a clean machine, in order, with expected run time and resource use.

## 3. Architecture

A diagram (Mermaid, ASCII or an image in `docs/`) showing GitLab, the runner, the scanners, the staging VM, the log shipper and OpenSearch, and how they reach each other.

## 4. Pipeline and gates

For each gate: tool, what it scans, threshold, why that threshold, where the artefact is, how false positives are suppressed.

| Gate | Tool | Scope | Fails when | Justification | Artefact |
|---|---|---|---|---|---|

## 5. Staging and DAST

How the VM is provisioned, how the runner reaches it, how deployment works, what ZAP scans and with what threshold. Which pen-test findings does your DAST set-up detect, and which does it miss?

## 6. Telemetry

Index design, how each of the three streams gets in, the trend tool's usage, and a screenshot of the dashboard.

## 7. Fixes

Which findings you fixed, how, and the trend-report output that shows them resolved.

## 8. Design decisions

| Decision | Chosen | Rejected alternatives | Why |
|---|---|---|---|

## 9. What I did not do

An honest list, with the reasons.

## 10. Scaling question

"Northwind at 200 developers, 20 teams, 60 repositories, with the same security staffing: what breaks first in your design, and what would you change?" One paragraph.

## 11. Time log

| Task | Planned | Actual | Notes |
|---|---|---|---|
