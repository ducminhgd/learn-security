---
title: "Write-Up Sprint Day 2 — Cloud and API Bug Analysis"
tags: [write-up, cloud, API, analysis, learning, practice, bug-bounty]
module: 05-BugBountyOps-02
day: 327
related_topics:
  - Write-Up Sprint Day 1 (Day 326)
  - HTB Cloud Series Day 5 (Day 310)
  - HTB API Series Day 5 (Day 305)
---

# Day 327 — Write-Up Sprint Day 2: Cloud and API Bug Analysis

---

## Goals

Read and analyse two public write-ups specifically from the cloud and API
vulnerability categories. Build a personal technique library for these areas.

**Time budget:** 3 hours.

---

## Focus Areas for Today

```
Cloud write-up targets:
  - AWS IAM misconfiguration bounty reports
  - SSRF → metadata credential theft reports
  - S3 bucket exposure reports
  - Azure/GCP misconfiguration reports

API write-up targets:
  - BOLA / IDOR on REST APIs
  - GraphQL exploitation reports
  - Mass assignment account takeover
  - OAuth on API flows
  - JWT abuse leading to privilege escalation
```

---

## Cloud Write-Up Analysis

```
URL: ___
Programme: ___
Vulnerability: ___  (IAM / SSRF / S3 / other)
Payout: ___

Discovery method:
  ___

Attack chain:
  Step 1: ___
  Step 2: ___
  Step 3: ___

AWS service exploited: ___

CloudTrail event that would have caught this:
  ___

Defence control that would have prevented it:
  ___

Can I replicate this technique? Y/N
What specific IAM permission made this possible? ___
```

---

## API Write-Up Analysis

```
URL: ___
Programme: ___
Vulnerability: ___  (BOLA / BFLA / mass assignment / JWT / GraphQL / other)
Payout: ___

Discovery method:
  Was it found by: Burp proxy + manual / Nuclei / Postman / other: ___

Authentication bypass technique (if any):
  ___

Object or endpoint targeted:
  ___

Impact demonstrated in the report:
  [ ] PII of other users accessed
  [ ] Admin functionality accessed
  [ ] Data modified
  [ ] Account takeover
  [ ] Payment manipulation

Report quality observations:
  Title clarity: ___
  CVSS stated: Y/N  Value: ___
  Remediation specificity: ___

One technique I should add to my API testing checklist:
  ___
```

---

## Technique Library Update

After reading both write-ups, update your personal technique library:

```
New technique learned: ___
Trigger: "Test this when I see ___"
Payload/approach: ___
Source write-up: ___

New tool or flag learned: ___
When to use it: ___
```

---

## Programme Pattern Matching

```
Both of today's write-ups: does either programme match programmes you plan to test?
  Write-up 1 programme: ___  → Similar to target: ___
  Write-up 2 programme: ___  → Similar to target: ___

Tech stack match:
  Write-up 1 tech: ___   Your target has same tech: Y/N
  Write-up 2 tech: ___   Your target has same tech: Y/N
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q327.1, Q327.2 …).

---

## Navigation

← Previous: [Day 326 — Write-Up Sprint Day 1](DAY-0326-Write-Up-Sprint-Day-01.md)
→ Next: [Day 328 — Write-Up Sprint Day 3](DAY-0328-Write-Up-Sprint-Day-03.md)
