---
title: "First Programme Sprint Day 7 — Report Writing and First Submissions"
tags: [live-programme, bug-bounty, report-writing, submission, communication, practice]
module: 05-BugBountyOps-03
day: 337
related_topics:
  - First Programme Sprint Day 6 (Day 336)
  - Write-Up Sprint Day 4 (Day 329)
  - Responsible Disclosure Process (Day 269)
---

# Day 337 — First Programme Sprint Day 7: Report Writing and First Submissions

> "Every hour you spend testing after finding a bug without writing it up is
> an hour of risk. Duplicate reports happen. Programmes close. Submit. Then
> continue testing."
>
> — Ghost

---

## Goals

Convert all findings from Days 331–336 into complete, submission-ready reports.
Submit at least one report today.

**Time budget:** 5–6 hours.

---

## Finding Inventory

List every candidate finding before writing reports:

```
#  | Type              | Endpoint            | Severity Est. | Evidence Complete?
---|-------------------|---------------------|---------------|-------------------
1  | ___               | ___                 | ___           | Y/N
2  | ___               | ___                 | ___           | Y/N
3  | ___               | ___                 | ___           | Y/N
4  | ___               | ___                 | ___           | Y/N
```

---

## Report 1 — [Finding Type]

```
Title: ___

Severity: ___  CVSS: ___
Vector: AV:___/AC:___/PR:___/UI:___/S:___/C:___/I:___/A:___

Summary:
  ___

Impact:
  ___

Steps to Reproduce:
  1. ___
  2. ___
  3. ___
  4. Observe: ___

Evidence:
  HTTP Request:
  ---
  ___
  ---

  Response (relevant portion):
  ---
  ___
  ---

Root Cause:
  ___  (CWE: ___)

Remediation:
  ___

Submitted: Y/N  |  Submission time: ___  |  Report ID: ___
```

---

## Report 2 — [Finding Type]

```
Title: ___

Severity: ___  CVSS: ___

Summary:
  ___

Impact:
  ___

Steps to Reproduce:
  1. ___
  2. ___
  3. ___

Evidence: ___

Remediation: ___

Submitted: Y/N  |  Report ID: ___
```

---

## Pre-Submission Checklist (run for each report)

```
[ ] Title includes severity keyword, asset, and technique
[ ] Impact explains business consequence (not just "attacker can read data")
[ ] Reproduction steps are exact and complete — tested end-to-end before submitting
[ ] Evidence includes at least one HTTP request and one screenshot
[ ] CVSS vector justified per component
[ ] Scope confirmed — endpoint is in-scope for this programme
[ ] No personal data of real users used as PoC evidence
[ ] Report is clean prose — no typos, no broken formatting
```

---

## Post-Submission Monitoring

```
Report #1 ID: ___  Status: ___  Triaged by: ___
Report #2 ID: ___  Status: ___

Expected triage timeline for this programme: ___
  (found in programme page: "Average time to first response: ___ days")

What to do while waiting:
  [ ] Continue testing new surfaces
  [ ] Read programme's previous public disclosures
  [ ] Monitor for similar techniques in fresh write-ups
  [ ] Work on second programme recon
```

---

## Triage Response Handling

When triage arrives:

```
If "Duplicate":
  - Check submitted report date vs. duplicate report date
  - If older: ask triage to verify the dates
  - Learn: what did the duplicate reporter find that I missed? ___

If "Informational / N/A":
  - Read the triage note carefully — what was the programme's reasoning?
  - Is the reasoning valid? Y/N
  - If invalid: write a polite rebuttal explaining the impact
  - If valid: accept, take notes, improve scope reading next time

If "Needs more info":
  - Respond within 24 hours
  - Provide exactly what was requested — no more, no less

If "Triaged" (accepted):
  - Do NOT share externally until programme discloses or 90 days pass
  - Ask about disclosure timeline if relevant to CVE request
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q337.1, Q337.2 …).

---

## Navigation

← Previous: [Day 336 — First Programme Sprint Day 6](DAY-0336-First-Programme-Sprint-Day-06.md)
→ Next: [Day 338 — First Programme Sprint Day 8](DAY-0338-First-Programme-Sprint-Day-08.md)
