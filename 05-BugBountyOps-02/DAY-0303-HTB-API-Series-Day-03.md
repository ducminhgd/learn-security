---
title: "HTB API Series Day 3 — Mass Assignment and JWT Attacks"
tags: [HTB, HackTheBox, CTF, API, mass-assignment, JWT, privilege-escalation,
       practice, bug-bounty]
module: 05-BugBountyOps-02
day: 303
related_topics:
  - HTB API Series Day 2 (Day 302)
  - Mass Assignment and API Injection (Day 149)
  - JWT Advanced Attacks (Day 169)
---

# Day 303 — HTB API Series Day 3: Mass Assignment and JWT Attacks

---

## Goals

Exploit mass assignment or JWT weakness in an API challenge.

**Time budget:** 3–4 hours.

---

## Engagement Log

### Mass Assignment

```
Endpoint tested: ___
POST body sent: ___
Injected property: ___
Effect: ___
```

### JWT Attack

```
Token decoded: ___
Algorithm: ___
Attack used: ___
Forged payload: ___
Result: ___
```

### Flag

```
FLAG{___}
Path taken: ___
```

---

## Combined Technique Drill

Write from memory:

```bash
# Decode a JWT without a library:
echo "HEADER_PAYLOAD" | base64 -d

# Forge JWT with alg:none:
___

# Forge JWT with HS256 using RS256 public key:
python3 -c "..."
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q303.1, Q303.2 …).

---

## Navigation

← Previous: [Day 302 — HTB API Series Day 2](DAY-0302-HTB-API-Series-Day-02.md)
→ Next: [Day 304 — HTB API Series Day 4](DAY-0304-HTB-API-Series-Day-04.md)
