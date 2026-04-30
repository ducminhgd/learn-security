---
title: "Live Programme Practice Day 9 — Advanced Techniques and Chaining"
tags: [practice, live-programme, vulnerability-chaining, race-conditions,
       business-logic, advanced-web, HTTP-smuggling, bug-bounty, methodology]
module: 05-BugBountyOps-01
day: 284
related_topics:
  - Live Programme Practice Day 8 (Day 283)
  - Chaining Vulnerabilities (Day 139)
  - Race Conditions (Day 131)
  - Business Logic Flaws (Day 130)
  - HTTP Request Smuggling (Day 126)
---

# Day 284 — Live Programme Practice Day 9: Advanced Techniques and Chaining

> "You have tested the common surfaces. Today you look for the things that
> require thinking, not just checking. Business logic flaws, race conditions,
> and vulnerability chains — these are the bugs that separate the people who
> earn from the people who browse."
>
> — Ghost

---

## Goals

Apply advanced techniques to your target and attempt to chain existing findings.

**Time budget:** 5–6 hours.

---

## Block 1 — Chain Analysis (60 min)

Review your finding log. Map potential chains:

```
Chain Candidate 1:
  Finding A: ___  (Severity: ___)
  Finding B: ___  (Severity: ___)
  Combined scenario: ___
  Combined severity estimate: ___

Chain Candidate 2:
  Finding A: ___
  Finding B: ___
  Combined scenario: ___
  Combined severity: ___
```

---

## Block 2 — Business Logic Testing (90 min)

```
[ ] Workflow bypass: Can you skip a required step?
    (e.g., skip email verification, skip payment confirmation)
    Test: ___  Result: ___

[ ] Negative quantity / out-of-range values:
    Test: quantity=-1, price=0.001, amount=-100
    Result: ___

[ ] Privilege-dependent features with wrong order:
    (Set admin role via mass assignment, then access admin endpoints)
    Result: ___

[ ] Coupon / discount double application:
    Can you apply the same discount code twice?
    Result: ___
```

---

## Block 3 — Race Condition Testing (60 min)

Identify race-condition-vulnerable endpoints:
- Anything that checks a condition then acts on it
- Discount/coupon application
- Account balance deduction
- Rate-limited actions (OTP verification, password attempts)

```python
# Burp Turbo Intruder for race condition testing:
# Use "race single-packet attack" mode
# 20–30 concurrent requests to the target endpoint

# Python example:
import asyncio, aiohttp

async def exploit():
    url = "https://target.example.com/api/use-coupon"
    payload = {"code": "DISCOUNT50"}
    headers = {"Authorization": f"Bearer {TOKEN}"}
    async with aiohttp.ClientSession() as session:
        tasks = [session.post(url, json=payload, headers=headers) for _ in range(20)]
        results = await asyncio.gather(*tasks)
        for r in results:
            print(r.status, await r.text())

asyncio.run(exploit())
```

---

## Block 4 — CORS and Host Header Testing (60 min)

```bash
# Test CORS misconfiguration:
curl -s -H "Origin: evil.attacker.com" \
     -H "Authorization: Bearer $TOKEN" \
     https://api.$TARGET/ \
  | grep -i "access-control"

# Check for null origin:
curl -s -H "Origin: null" \
     -H "Authorization: Bearer $TOKEN" \
     https://api.$TARGET/ \
  | grep -i "access-control"

# Test host header injection:
curl -s -H "Host: evil.attacker.com" \
     https://$TARGET/password-reset

# Does the response redirect to attacker domain?
# Does the password reset email contain the attacker domain?
```

---

## Block 5 — Second Report Preparation (60 min)

```
[ ] Select second finding from finding log
[ ] Write full report draft
[ ] Apply checklist from Day 283
[ ] Ready to submit? Y/N  If N: what is missing?
```

---

## Session Debrief

```
Advanced techniques applied: ___
Race condition result: ___
Chain candidate status: ___
Reports ready: ___
Remaining gaps to explore: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q284.1, Q284.2 …).

---

## Navigation

← Previous: [Day 283 — Live Programme Practice Day 8](DAY-0283-Live-Programme-Practice-Day-08.md)
→ Next: [Day 285 — Live Programme Practice Day 10](DAY-0285-Live-Programme-Practice-Day-10.md)
