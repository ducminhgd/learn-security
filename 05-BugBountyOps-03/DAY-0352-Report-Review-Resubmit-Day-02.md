---
title: "Report Review and Resubmit Day 2 — Rebuttals and Additional Evidence"
tags: [live-programme, bug-bounty, rebuttal, evidence, severity-negotiation, communication]
module: 05-BugBountyOps-03
day: 352
related_topics:
  - Report Review Day 1 (Day 351)
  - Earnings Optimisation (Day 273)
  - Write-Up Sprint Day 4 (Day 329)
---

# Day 352 — Report Review and Resubmit Day 2: Rebuttals and Additional Evidence

---

## Goals

Write and submit rebuttals for incorrectly triaged reports.
Provide additional evidence for reports marked "Needs More Info".
Contest unjustified severity downgrades with CVSS arguments.

**Time budget:** 4–5 hours.

---

## Rebuttal Framework

### When to Rebuttal

```
ALWAYS rebuttal if:
  - N/A reason is factually incorrect (e.g. "not exploitable" but you have a PoC)
  - Severity downgraded without technical justification
  - Duplicate date is later than your submission

NEVER rebuttal if:
  - Programme explicitly says the behaviour is by design (accept and learn)
  - You misread the scope (accept and note the lesson)
  - The triage explanation is technically sound

Tone rule: Professional, evidence-first, never emotional.
```

### Rebuttal Template

```
Subject: Re: [Report Title] — Additional Clarification

Hello [Triage team],

Thank you for reviewing this report. I would like to provide additional
context on the [impact / severity / scope] question.

The vulnerability allows an attacker to [SPECIFIC ACTION]. The triage
response noted [TRIAGE CLAIM]. I respectfully disagree for the following reasons:

1. [Technical argument 1 with evidence]
2. [Technical argument 2 with evidence / PoC link]

Based on CVSS 3.1, the Scope component should be C (Changed) because
[REASON], which raises the score from ___ to ___.

I am happy to provide further evidence or a live demonstration if helpful.

Thank you for your time.
```

---

## Rebuttals Written Today

### Rebuttal 1 — Report #___

```
Original triage status: ___
Dispute: ___
CVSS argument:
  Triage vector: ___  Score: ___
  My vector:     ___  Score: ___
  Difference argument: ___

Evidence appended to report: ___
  [ ] Additional screenshot
  [ ] PoC script demonstrating impact
  [ ] Video walkthrough (if needed for complex chain)

Rebuttal submitted: Y/N  |  Date: ___
```

### Rebuttal 2 — Report #___

```
Original status: ___
Dispute: ___
Evidence: ___
Submitted: Y/N
```

---

## Additional Evidence Provided

### Report #___ — "Needs More Info"

```
Information requested: ___

Additional evidence provided:
  ___

Clearer reproduction steps:
  1. ___
  2. ___
  3. ___

Why the previous steps were unclear: ___
How I made them clearer: ___

Responded: Y/N  |  Date: ___
```

---

## Severity Negotiation Tracker

```
Report  | My Severity | Triaged As | Rebuttal Sent | Final Severity
--------|-------------|------------|---------------|----------------
#___    | ___         | ___        | Y/N           | ___
#___    | ___         | ___        | Y/N           | ___
#___    | ___         | ___        | Y/N           | ___

Negotiation success rate: ___  / ___  attempts
Average CVSS delta achieved: ___
```

---

## Post-Rebuttal Reflection

```
Triage engineers I am working with: fair / inconsistent / responsive
Notes on programme's triage quality: ___

One thing I will write differently in future reports to avoid this dispute:
  ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q352.1, Q352.2 …).

---

## Navigation

← Previous: [Day 351 — Report Review Day 1](DAY-0351-Report-Review-Resubmit-Day-01.md)
→ Next: [Day 353 — Report Review and Resubmit Day 3](DAY-0353-Report-Review-Resubmit-Day-03.md)
