---
title: "Write-Up Sprint Day 3 — Chained Attack Write-Up Analysis"
tags: [write-up, chaining, attack-chain, analysis, learning, practice, bug-bounty]
module: 05-BugBountyOps-02
day: 328
related_topics:
  - Write-Up Sprint Day 2 (Day 327)
  - Weak Area Reinforcement Day 9 (Day 324)
  - Bug Bounty Methodology Synthesis (Day 275)
---

# Day 328 — Write-Up Sprint Day 3: Chained Attack Write-Up Analysis

---

## Goals

Read and analyse write-ups specifically featuring vulnerability chains.
Understand how researchers identify chain opportunities and how chaining
changes severity and payout.

**Time budget:** 3 hours.

---

## Why Chained Attacks Matter in Bug Bounty

```
Single vulnerability payouts:
  IDOR (read only):  typically P3 ($100–$500)
  Self-XSS:          typically N/A (out of scope on most programmes)
  Open redirect:     typically P4 ($50–$200)

Chained payouts:
  IDOR + XSS:        P2 ($500–$2,000) — XSS becomes exploitable via IDOR
  Self-XSS + CSRF:   P2 ($1,000–$5,000) — self-XSS becomes exploitable via CSRF
  Open redirect + OAuth: P1 ($5,000–$50,000) — token theft

The chain is the finding. Individual pieces are prerequisites.
```

---

## Chained Write-Up 1

```
URL: ___
Programme: ___
Payout: ___
Severity: ___

Vulnerability chain:
  Stage 1: ___  (standalone severity: ___)
  Stage 2: ___  (standalone severity: ___)
  Stage 3: ___  (standalone severity: ___)

Final chained severity: ___
Chained CVSS: ___

What was the "glue" connecting the vulnerabilities?
  (e.g. "The IDOR exposed an internal user ID needed for the XSS endpoint")
  ___

Did the researcher submit the chain as one report or multiple?
  [ ] One report   [ ] Multiple sequential reports
  Why: ___

What intermediate data/access did Stage 1 provide for Stage 2?
  ___
```

---

## Chained Write-Up 2

```
URL: ___
Programme: ___
Payout: ___

Chain:
  ___  →  ___  →  ___

How was the chain discovered?
  [ ] Methodical (enumerated all bugs, then identified chains)
  [ ] Serendipitous (stumbled on the connection mid-test)
  [ ] Planned (designed the chain after reading source code)

Notes: ___
```

---

## Chain Pattern Recognition Exercise

Given these standalone vulnerabilities, propose possible chains:

```
Scenario A:
  - SSRF (reaches internal 10.0.0.0/8 network)
  - Redis server at 10.0.1.5:6379 (no auth)
  - Web app stores sessions in Redis

  Proposed chain: ___  →  ___  →  ___
  Impact: ___
  Severity: ___

Scenario B:
  - XSS in user profile bio (stored)
  - Admin panel that previews user profiles
  - CSRF token is present but not tied to user session (static value)

  Proposed chain: ___  →  ___  →  ___
  Impact: ___
  Severity: ___

Scenario C:
  - Mass assignment in POST /users/register (can set role: admin)
  - Admin panel checks role in JWT (signed with HS256)
  - JWT secret is the app's 8-character hostname (found in headers)

  Proposed chain: ___  →  ___  →  ___
  Impact: ___
  Severity: ___
```

---

## Writing Your Own Chain Report Section

Draft the "Summary" and "Impact" sections for one of the chains above:

```
Title: ___  [Format: Verb + Noun + via + Technique]

Summary (2–3 sentences):
  ___

Impact:
  ___

CVSS:
  Vector: AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N
  Score: ___
  Severity: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q328.1, Q328.2 …).

---

## Navigation

← Previous: [Day 327 — Write-Up Sprint Day 2](DAY-0327-Write-Up-Sprint-Day-02.md)
→ Next: [Day 329 — Write-Up Sprint Day 4](DAY-0329-Write-Up-Sprint-Day-04.md)
