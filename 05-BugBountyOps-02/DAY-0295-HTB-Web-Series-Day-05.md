---
title: "HTB Web Series Day 5 — API Exploitation Focus"
tags: [HTB, HackTheBox, CTF, web, API, REST, GraphQL, BOLA, mass-assignment,
       practice, methodology, bug-bounty]
module: 05-BugBountyOps-02
day: 295
related_topics:
  - HTB Web Series Day 4 (Day 294)
  - OWASP API Top 10 (Day 146)
  - GraphQL Attack Lab (Day 150)
  - REST API Lab Episode 1 (Day 151)
---

# Day 295 — HTB Web Series Day 5: API Exploitation Focus

> "API security is where most of the money is right now. Every modern
> application has an API. Most teams secure the frontend and forget the API.
> The flag today is hidden behind an API flaw — find the flaw, find the flag,
> then explain it well enough to write the report."
>
> — Ghost

---

## Goals

Complete one HTB challenge with API exploitation as the primary vector.
Produce a report-quality writeup at the end.

**Time budget:** 5–6 hours.

---

## Pre-Engagement Plan

```
Recommended challenges: HTB API challenges, ProLabs API modules,
  or custom GraphQL/REST challenges

My hypothesis:
  API type: REST / GraphQL / gRPC
  Auth mechanism: JWT / API key / none
  Most likely vulnerability: BOLA / mass-assignment / introspection / injection
```

---

## Engagement Log

### API Discovery

```
Documentation found: ___
Endpoints enumerated: ___
Auth mechanism: ___
Schema/introspection available: Y/N
```

### API Testing

```
BOLA test:
  Endpoint: ___  Your ID: ___  Other ID: ___  Result: ___

Mass assignment:
  Endpoint: ___  Injected property: ___  Result: ___

GraphQL (if present):
  Introspection query:
    curl -X POST .../graphql -d '{"query":"{__schema{types{name}}}"}'
  Result: ___
  Hidden fields found: ___
  Auth bypass via field access: ___

Injections:
  NoSQL: ___  Result: ___
  GraphQL: ___  Result: ___
```

### Flag

```
FLAG{___}
Time to flag: ___ min
```

---

## Report-Quality Writeup (write this after getting the flag)

```
Title: ___
Severity: ___  CVSS: ___
Summary: ___
Impact: ___
Steps to Reproduce:
  1. ___
  2. ___
  3. ___
Evidence: [describe request/response]
Remediation: ___
```

---

## Web Series Retrospective (Days 291–295)

```
Machines completed: ___/5
Techniques reinforced: ___
Weakest area identified: ___
One technique to practice more before live programme return: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q295.1, Q295.2 …).

---

## Navigation

← Previous: [Day 294 — HTB Web Series Day 4](DAY-0294-HTB-Web-Series-Day-04.md)
→ Next: [Day 296 — HTB Linux Series Day 1](DAY-0296-HTB-Linux-Series-Day-01.md)
