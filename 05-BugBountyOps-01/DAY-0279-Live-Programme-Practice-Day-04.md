---
title: "Live Programme Practice Day 4 — IDOR and Access Control Deep Dive"
tags: [practice, live-programme, IDOR, BOLA, access-control, Autorize,
       privilege-escalation, bug-bounty, methodology]
module: 05-BugBountyOps-01
day: 279
related_topics:
  - Live Programme Practice Day 3 (Day 278)
  - IDOR Fundamentals (Day 101)
  - BOLA in APIs (Day 108)
  - Access Control for Bug Bounty (Day 109)
---

# Day 279 — Live Programme Practice Day 4: IDOR and Access Control Deep Dive

> "IDOR is the most consistently rewarded vulnerability class in bug bounty.
> It is not because programmes are careless — it is because access control
> is hard to build correctly across hundreds of endpoints. Your job today is
> to check every single one."
>
> — Ghost

---

## Goals

Deep-test access control across all discovered endpoints. Document every
object reference and test each one.

**Time budget:** 5–6 hours.

---

## Block 1 — Object Reference Inventory (60 min)

Map every object identifier visible in your testing session:

```
Object: User profile
  Endpoint: ___
  Identifier type: numeric / UUID / hash / username
  Identifier in: URL path / query param / POST body / header
  Example value: ___

Object: [Next object]
  ...
```

List all objects found:
```
1. ___  ID type: ___  Endpoint: ___
2. ___  ID type: ___  Endpoint: ___
3. ___  ID type: ___  Endpoint: ___
4. ___  ID type: ___  Endpoint: ___
5. ___  ID type: ___  Endpoint: ___
```

---

## Block 2 — IDOR Testing (120 min)

For each object with a direct reference:

```
[ ] Test with Account A accessing Account B's object:
    Request: [paste]
    Expected: 403 / 404
    Actual: ___

[ ] Test with unauthenticated request:
    Remove Authorization header entirely
    Actual: ___

[ ] Test role-based access (admin endpoint accessible by user):
    Enumerate admin-looking paths from ffuf results
    Actual: ___

[ ] Test HTTP method switching:
    If GET is protected, try POST, PUT, DELETE with same path
    Actual: ___

[ ] Test ID prediction (if numeric):
    Your ID: ___
    Other IDs tested: ___
    Results: ___
```

---

## Block 3 — Privilege Escalation Testing (90 min)

```
[ ] Mass assignment: Add "role": "admin" to any user update endpoint
    Endpoint: ___
    Result: ___

[ ] Forced browsing: Access admin endpoints as regular user
    Endpoints tested: ___
    Results: ___

[ ] Parameter tampering: Modify account_type, subscription_level, is_admin
    Parameters tested: ___
    Results: ___
```

---

## Block 4 — Autorize Review and Chain Analysis (60 min)

```
[ ] Review all Autorize "Bypassed!" results from Days 277–279
[ ] Manually verify each bypassed endpoint
[ ] For confirmed bypasses: assess impact and draft finding notes

Confirmed bypasses:
1. ___  Impact: ___  Chain potential: ___
2. ___  Impact: ___  Chain potential: ___
```

---

## Session Debrief

```
Object references tested: ___
Confirmed IDOR findings: ___
Potential privilege escalation paths: ___
Impact assessment of best finding: ___
Next session: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q279.1, Q279.2 …).

---

## Navigation

← Previous: [Day 278 — Live Programme Practice Day 3](DAY-0278-Live-Programme-Practice-Day-03.md)
→ Next: [Day 280 — Live Programme Practice Day 5](DAY-0280-Live-Programme-Practice-Day-05.md)
