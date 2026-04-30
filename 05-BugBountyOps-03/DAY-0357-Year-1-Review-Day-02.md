---
title: "Year-1 Review Day 2 — Defensive Translation"
tags: [Year-1, review, defensive, detection, hardening, blue-team, gate-prep]
module: 05-BugBountyOps-03
day: 357
related_topics:
  - Year-1 Review Day 1 (Day 356)
  - Defensive Track (B-01 to B-10)
  - HTB Web Series (Days 291–295)
---

# Day 357 — Year-1 Review Day 2: Defensive Translation

> "The red team skill without the defensive translation is half the job.
> Every technique you know how to execute, you must also know how to detect
> and how to fix. That is what separates a security engineer from a script
> runner."
>
> — Ghost

---

## Goals

For every offensive technique mastered in Year 1, write the detection rule
and the one-line fix. No tools — from memory.

**Time budget:** 4–5 hours.

---

## Offensive → Defensive Translation Table

Complete each row from memory. Check against reference after.

```
Technique        | How to Detect                     | How to Fix
-----------------|-----------------------------------|------------------------------------------
SQLi             | ___                               | ___
Blind SQLi       | ___                               | ___
SSTI             | ___                               | ___
XSS (reflected)  | ___                               | ___
XSS (stored)     | ___                               | ___
SSRF             | ___                               | ___
SSRF → metadata  | ___                               | ___
JWT alg:none     | ___                               | ___
JWT weak secret  | ___                               | ___
IDOR/BOLA        | ___                               | ___
Mass assignment  | ___                               | ___
OAuth state CSRF | ___                               | ___
GraphQL intr.    | ___                               | ___
Race condition   | ___                               | ___
XXE              | ___                               | ___
Deserialization  | ___                               | ___
AWS IAM escalat. | ___                               | ___
S3 public bucket | ___                               | ___
Rate limit bypass| ___                               | ___
File upload RCE  | ___                               | ___
```

---

## Detection Rule Writing Drill

Write a Sigma rule for SQL injection detection in a web application log:

```yaml
title: SQL Injection Attempt in Web Request
status: experimental
description: Detects common SQL injection patterns in HTTP query parameters
author: ghost-student
date: ___
logsource:
  category: webserver
  product: nginx
detection:
  selection:
    cs-uri-query|contains:
      - ___
      - ___
      - ___
  condition: selection
falsepositives:
  - ___
level: high
tags:
  - attack.initial_access
  - attack.t1190
```

---

## YARA Rule Writing Drill

Write a YARA rule that detects a PHP webshell uploaded via file upload:

```yara
rule PHP_Webshell_Generic
{
  meta:
    description = "___"
    author = "ghost-student"
    date = "___"
    severity = "high"

  strings:
    $s1 = ___
    $s2 = ___
    $s3 = ___

  condition:
    ___
}
```

---

## Hardening One-Liners

For each attack, write the exact code change or config that closes it:

```
IDOR:
  Before: user_data = db.get_user(request.params['id'])
  After:  ___

Mass assignment:
  Before: user.update(request.body)
  After:  ___

JWT alg:none:
  Before: jwt.verify(token, secret)  // no algorithm pinning
  After:  ___

SSRF:
  Before: requests.get(user_supplied_url)
  After:  ___

XXE:
  Before: parser.parse(xml_input)   // default parser
  After:  ___
```

---

## Blue Team Perspective Score

```
Correct detections from memory: ___ / 20
Correct fixes from memory: ___ / 20

Technique where I know the attack but not the detection:
  ___

Action: add detection/fix to notes before Day 365
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q357.1, Q357.2 …).

---

## Navigation

← Previous: [Day 356 — Year-1 Review Day 1](DAY-0356-Year-1-Review-Day-01.md)
→ Next: [Day 358 — Year-1 Review Day 3](DAY-0358-Year-1-Review-Day-03.md)
