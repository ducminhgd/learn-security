---
title: "Second Programme Sprint Day 2 — Priority Surface Testing"
tags: [live-programme, bug-bounty, second-sprint, testing, priority, practice]
module: 05-BugBountyOps-03
day: 342
related_topics:
  - Second Programme Sprint Day 1 (Day 341)
  - Bug Bounty Methodology Synthesis (Day 275)
---

# Day 342 — Second Programme Sprint Day 2: Priority Surface Testing

---

## Goals

Test the top-priority surfaces identified in Day 341.
Apply the "Sprint 1 adjustment" — skip low-yield techniques from last sprint.

**Time budget:** 5–6 hours.

---

## Sprint 1 Adjustment in Practice

```
Technique skipped today (was low-yield in Sprint 1): ___
Technique prioritised today (was high-yield in Sprint 1): ___

Time saved by not repeating low-yield work: ___ hours
Redirected to: ___
```

---

## Priority 1 Surface Testing

```
Surface: ___  (identified Day 341)
Time budget: ___ hours

Testing log:
  Endpoint/parameter: ___
  Technique applied: ___
  Payloads / tools used: ___
  Responses noted: ___
  Anomalies: ___
  Finding: Y/N  →  Type: ___  Severity: ___
```

---

## Priority 2 Surface Testing

```
Surface: ___
Time budget: ___ hours

Testing log:
  ___
  Finding: Y/N  →  Type: ___  Severity: ___
```

---

## Priority 3 Surface Testing

```
Surface: ___
Time budget: ___ hours

Testing log:
  ___
  Finding: Y/N  →  Type: ___  Severity: ___
```

---

## Nuclei Automated Scan

```bash
# Run Nuclei against live hosts with relevant template categories
nuclei -l p2-live.txt \
  -t ~/nuclei-templates/ \
  -tags cves,exposures,misconfigurations \
  -severity medium,high,critical \
  -rate-limit 20 \
  -o nuclei-p2-results.txt

# Review results
cat nuclei-p2-results.txt | grep -v "false_positive"
```

```
Nuclei findings:
  True positive: ___
  False positive: ___
  Interesting (needs manual verification): ___
```

---

## Day 2 Finding Log

```
Finding #1: ___  Severity: ___
Finding #2: ___  Severity: ___

If no findings: what surface will I pivot to tomorrow?
  ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q342.1, Q342.2 …).

---

## Navigation

← Previous: [Day 341 — Second Programme Sprint Day 1](DAY-0341-Second-Programme-Sprint-Day-01.md)
→ Next: [Day 343 — Second Programme Sprint Day 3](DAY-0343-Second-Programme-Sprint-Day-03.md)
