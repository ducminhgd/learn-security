---
title: "CTF Web Competition Day 4 — Logic Flaws and Business Rules"
tags: [CTF, web, competition, logic-flaw, race-condition, IDOR, business-logic,
       practice, bug-bounty]
module: 05-BugBountyOps-02
day: 314
related_topics:
  - CTF Web Competition Day 3 (Day 313)
  - Access Control Review (Day 195)
  - API Security (R-04)
---

# Day 314 — CTF Web Competition Day 4: Logic Flaws and Business Rules

---

## Goals

Target CTF challenges requiring exploitation of application logic rather than
classic injection vulnerabilities. Logic flaws require reading the application,
not running payloads.

**Time budget:** 4–5 hours.

---

## Logic Flaw Pattern Library

```
Price tampering:
  - POST /checkout with price=0.01 in body
  - Negative quantity: qty=-1 → negative total → store credit
  - Discount code stacking (apply same code twice)
  - Coupon applied after price locked

IDOR / access control:
  - Change user_id / account_id / order_id in request
  - GUIDs: test with known IDs from other users (registration leaks them)
  - Horizontal vs vertical: same-level vs elevated access

Race conditions:
  - Withdraw balance twice (parallel requests, both see old balance)
  - Coupon code used twice (parallel redemption)
  - Inventory check bypass (check → reserve time window)
  - Email verification link used twice

Workflow bypass:
  - Skip step 2 in a multi-step process
  - Go directly to /payment-success without paying
  - Replay old signed requests (if no nonce/expiry)

Parameter pollution:
  - email=victim@x.com&email=attacker@x.com → which does the app use?
  - uid=1&uid=2 → first or last wins?

Mass assignment:
  - Add isAdmin: true to registration body
  - Add role: "admin" to profile update
  - Add balance: 99999 to any update endpoint
```

---

## Challenge Log

### Challenge 1 — Price Manipulation

```
Points: ___
Application type: ___  (shop / coupon system / subscription)

Manipulation attempt:
  - Request before modification: ___
  - Modified field: ___
  - Modified value: ___
  - Server response: ___

Flag: ___
Time: ___ min
```

### Challenge 2 — Workflow Bypass

```
Points: ___
Multi-step process:
  Step 1: ___
  Step 2: ___
  Step 3: ___ (target — skip to here)

How step was bypassed:
  ___

Server check missing: ___
Flag: ___
Time: ___ min
```

### Challenge 3 — Race Condition

```
Points: ___
Vulnerable operation: ___  (balance / coupon / vote / like)

Race condition test:
  # Turbo Intruder script (Burp)
  # Send 20 parallel requests at exact same time
  # Target: single-use action done twice

  # Python parallel requests
  import concurrent.futures, requests

  def exploit(i):
      r = requests.post("URL", json={"action": "redeem", "code": "PROMO50"})
      return r.status_code, r.text

  with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
      results = list(ex.map(exploit, range(20)))

  [print(r) for r in results]

Result: ___  (how many succeeded?)
Flag: ___
Time: ___ min
```

### Challenge 4 — IDOR Chain

```
Points: ___
Object type: ___  (user / document / order)
Your ID:     ___
Target ID:   ___  (found by: ___) 

Levels attempted:
  Horizontal (same-level IDOR): ___
  Vertical (elevated access): ___

Flag path: ___
Flag: ___
Time: ___ min
```

---

## Session Metrics

```
Challenges attempted: ___
Flags captured: ___
Most interesting logic flaw class today: ___

Lesson: "What assumption did the developer make that an attacker can break?"
  Challenge 1 assumption: ___  → broken by: ___
  Challenge 2 assumption: ___  → broken by: ___
  Challenge 3 assumption: ___  → broken by: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q314.1, Q314.2 …).

---

## Navigation

← Previous: [Day 313 — CTF Web Competition Day 3](DAY-0313-CTF-Web-Competition-Day-03.md)
→ Next: [Day 315 — CTF Web Competition Day 5](DAY-0315-CTF-Web-Competition-Day-05.md)
