---
title: "HTB Web Series Day 3 — Authentication Bypass Focus"
tags: [HTB, HackTheBox, CTF, web, authentication-bypass, JWT, OAuth, session,
       practice, methodology, bug-bounty]
module: 05-BugBountyOps-02
day: 293
related_topics:
  - HTB Web Series Day 2 (Day 292)
  - JWT Advanced Attacks (Day 169)
  - OAuth Abuse Deep Dive (Day 171)
  - Account Takeover Chains (Day 174)
---

# Day 293 — HTB Web Series Day 3: Authentication Bypass Focus

> "Authentication bypass is the highest-value single vulnerability class in
> bug bounty. One auth bypass on the right target is a P1. Study every variant
> you encounter in CTF — each one maps to a real implementation flaw you will
> find in production."
>
> — Ghost

---

## Goals

Complete one HTB web challenge with authentication bypass as the primary vector.

**Time budget:** 4–5 hours.

---

## Pre-Engagement Plan

```
Recommended machines: JWT/session-focused HTB web challenges
  (search HTB for: JWT, session, auth bypass, token)

My hypothesis:
  Auth mechanism visible: JWT / session cookie / API key / custom
  First thing I will check: ___
  Attack variant most likely: ___

Tools:
  jwt.io for decoding
  jwt_tool for testing
  Burp Repeater for manual testing
```

---

## Engagement Log

### Auth Mechanism Analysis

```
Token type: ___
Token location: ___
Token format / decoded header: ___
Algorithm: ___
Claims present: ___
```

### Attack Testing

```
[ ] alg: none — Result: ___
[ ] Algorithm confusion (RS256→HS256) — Result: ___
[ ] Expired token — Result: ___
[ ] kid path traversal — Result: ___
[ ] Custom claim manipulation — Result: ___
[ ] Session fixation — Result: ___
[ ] Password reset token — Result: ___
```

### Successful Attack

```
Exploit vector: ___
Payload used: ___
Evidence of bypass: ___
```

### Flag

```
FLAG{___}
Time to flag: ___ min
```

---

## Debrief — Real World Connection

```
1. What implementation mistake caused this auth bypass?
   ___

2. What library or framework version was responsible?
   ___

3. How would a code reviewer catch this in a PR review?
   ___

4. Fix:
   ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q293.1, Q293.2 …).

---

## Navigation

← Previous: [Day 292 — HTB Web Series Day 2](DAY-0292-HTB-Web-Series-Day-02.md)
→ Next: [Day 294 — HTB Web Series Day 4](DAY-0294-HTB-Web-Series-Day-04.md)
