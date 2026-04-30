---
title: "HTB API Series Day 2 — GraphQL Introspection and Exploitation"
tags: [HTB, HackTheBox, CTF, API, GraphQL, introspection, exploitation, practice, bug-bounty]
module: 05-BugBountyOps-02
day: 302
related_topics:
  - HTB API Series Day 1 (Day 301)
  - GraphQL Attack Lab (Day 150)
  - OWASP API Top 10 (Day 146)
---

# Day 302 — HTB API Series Day 2: GraphQL Introspection and Exploitation

---

## Goals

Exploit a GraphQL API challenge via introspection, field-level access bypass, or injection.

**Time budget:** 3–4 hours.

---

## Engagement Log

### GraphQL Discovery

```
Endpoint: ___
Introspection enabled: Y/N

Introspection query:
  curl -X POST $ENDPOINT -d '{"query":"{__schema{types{name fields{name}}}}"}'

Types found: ___
Mutations available: ___
```

### Exploitation

```
Attack vector:
  [ ] Hidden field access (add sensitive field to query)
  [ ] Mass assignment via mutation
  [ ] Injection in argument
  [ ] Batch query bypass of rate limiting

Technique used: ___
Payload: ___
Result: ___
```

### Flag

```
FLAG{___}
```

---

## Debrief

```
How would you harden this GraphQL endpoint?
  1. ___
  2. ___

Does this machine's GraphQL vulnerability appear commonly in bug bounty?
___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q302.1, Q302.2 …).

---

## Navigation

← Previous: [Day 301 — HTB API Series Day 1](DAY-0301-HTB-API-Series-Day-01.md)
→ Next: [Day 303 — HTB API Series Day 3](DAY-0303-HTB-API-Series-Day-03.md)
