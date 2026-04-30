---
title: "Gate Preparation Day 3 — Report Writing and Defensive Mastery"
tags: [gate-prep, Year-1, report-writing, defensive, mastery, CVSS]
module: 05-BugBountyOps-03
day: 363
related_topics:
  - Gate Preparation Day 2 (Day 362)
  - Year-1 Review Day 2 (Day 357)
  - Write-Up Sprint Day 4 (Day 329)
---

# Day 363 — Gate Preparation Day 3: Report Writing and Defensive Mastery

---

## Goals

Polish report writing to professional standard.
Ensure detection and fix explanations are precise and defensible.
Both skills are assessed in the Day 365 gate.

**Time budget:** 4–5 hours.

---

## Part 1 — Report Writing Rapid Drill

Write three complete "Summary + Impact + Remediation" sections from these scenarios.
No reference. Time: 15 minutes per scenario.

### Scenario A: Stored XSS in Comment Field

```
Title: ___

Severity: ___   CVSS: AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N   Score: ___

Summary:
  ___

Impact:
  ___

Remediation:
  ___
```

### Scenario B: IDOR Exposing Other Users' PII

```
Title: ___

Severity: ___   CVSS: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N   Score: ___

Summary:
  ___

Impact:
  ___

Remediation:
  ___
```

### Scenario C: AWS S3 Bucket Publicly Readable — Credentials Exposed

```
Title: ___

Severity: ___   CVSS: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H   Score: ___

Summary:
  ___

Impact:
  ___

Remediation:
  ___
```

---

## Part 2 — CVSS Vector Justification Drill

For each vector string, explain WHY each component has the stated value:

```
Vector 1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
  AV:N  — ___
  AC:L  — ___
  PR:N  — ___
  UI:N  — ___
  S:U   — ___
  C:H   — ___
  I:H   — ___
  A:N   — ___
  Score: ___

Vector 2: AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H
  AV:N  — ___
  AC:H  — ___
  PR:L  — ___
  UI:R  — ___
  S:C   — ___
  Score: ___

Common mistake: what does "S:C (Scope Changed)" actually mean?
  ___
```

---

## Part 3 — Defensive Mastery Final Check

For each technique, give the detection log query AND the root-cause fix:

```
1. SQL injection:
   Detection: ___
   Fix: ___

2. SSRF → metadata:
   Detection: ___
   Fix: ___

3. JWT alg confusion:
   Detection: ___
   Fix: ___

4. S3 public read:
   Detection: ___
   Fix: ___

5. Race condition (coupon double-redeem):
   Detection: ___
   Fix: ___
```

---

## Part 4 — Explain-to-Junior Drill

Explain each concept as if teaching a junior developer.
No jargon. One paragraph. Focus on why it matters.

```
BOLA:
  ___

JWT alg:none:
  ___

Scope changed (S:C) in CVSS:
  ___
```

---

## Pre-Gate Confidence Check

```
Area                    | Confidence (1–5)
------------------------|------------------
Report writing          | ___
CVSS vector calculation | ___
Detection rule writing  | ___
Fix explanation         | ___
Live exploitation       | ___
Oral Q&A               | ___

Overall gate readiness: ___/5
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q363.1, Q363.2 …).

---

## Navigation

← Previous: [Day 362 — Gate Preparation Day 2](DAY-0362-Gate-Preparation-Day-02.md)
→ Next: [Day 364 — Gate Preparation Day 4](DAY-0364-Gate-Preparation-Day-04.md)
