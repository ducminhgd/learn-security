---
title: "HTB API Series Day 4 — Rate Limiting Bypass and Credential Attacks"
tags: [HTB, HackTheBox, CTF, API, rate-limiting, credential-stuffing, brute-force,
       bypass, practice, bug-bounty]
module: 05-BugBountyOps-02
day: 304
related_topics:
  - HTB API Series Day 3 (Day 303)
  - Rate Limiting Bypass (Day 167)
  - API Rate Limiting and DoS (Day 153)
---

# Day 304 — HTB API Series Day 4: Rate Limiting Bypass and Credential Attacks

---

## Goals

Bypass rate limiting on an API login or OTP endpoint.

**Time budget:** 3–4 hours.

---

## Rate Limiting Analysis

```
Endpoint: ___
Rate limit trigger: ___  (requests before block)
Block mechanism: IP-based / account-based / token-based
```

## Bypass Techniques Tested

```
[ ] X-Forwarded-For rotation
    curl -H "X-Forwarded-For: 1.2.3.4" ...
    Result: ___

[ ] User-agent rotation
    Result: ___

[ ] Parameter padding (email case, spaces, + suffix)
    Result: ___

[ ] Distributing across accounts
    Result: ___

[ ] Null byte in parameter
    Result: ___
```

## Successful Bypass

```
Method: ___
Script (if automated): ___
Outcome: ___
```

### Flag

```
FLAG{___}
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q304.1, Q304.2 …).

---

## Navigation

← Previous: [Day 303 — HTB API Series Day 3](DAY-0303-HTB-API-Series-Day-03.md)
→ Next: [Day 305 — HTB API Series Day 5](DAY-0305-HTB-API-Series-Day-05.md)
