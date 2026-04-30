---
title: "First Programme Sprint Day 5 — Mid-Sprint Review and Pivot"
tags: [live-programme, bug-bounty, mid-sprint, review, pivot, practice]
module: 05-BugBountyOps-03
day: 335
related_topics:
  - First Programme Sprint Day 4 (Day 334)
  - Bug Bounty Methodology Synthesis (Day 275)
  - Earnings Optimisation (Day 273)
---

# Day 335 — First Programme Sprint Day 5: Mid-Sprint Review and Pivot

> "Five days in, you either have a lead or you don't. If you don't, something
> is wrong with your approach — not the programme. Stop. Diagnose. Pivot.
> Grinding the same surface longer without changing technique is not perseverance.
> It is repetition."
>
> — Ghost

---

## Goals

Review the first four days of testing. Assess the attack surface coverage.
Decide: continue current approach, pivot to a different surface, or pivot to
a different programme.

**Time budget:** 3–4 hours.

---

## Days 331–334 Coverage Audit

```
Surfaces tested:
  [ ] Subdomain enumeration complete
  [ ] Live hosts identified
  [ ] Authentication surface tested
  [ ] IDOR / access control tested
  [ ] Injection (SQLi, SSTI, SSRF) tested
  [ ] XSS surface tested
  [ ] CSRF tested
  [ ] API endpoints enumerated and tested
  [ ] Client-side storage checked

Surfaces NOT yet tested:
  [ ] File upload (if present)
  [ ] Business logic / price manipulation
  [ ] Third-party integrations / OAuth flows
  [ ] Mobile app / API (if in scope)
  [ ] WebSocket endpoints
  [ ] GraphQL (if present)
```

---

## Findings Summary

```
Total findings documented: ___

By severity:
  Critical (CVSS ≥ 9.0): ___
  High     (CVSS 7.0–8.9): ___
  Medium   (CVSS 4.0–6.9): ___
  Low      (CVSS < 4.0):   ___
  Informational:           ___

Findings ready to report now: ___
Findings needing more evidence: ___
Findings that turned out to be N/A or by-design: ___
```

---

## Pivot Decision Matrix

```
Answer these questions honestly:

1. Have I found at least one reportable bug in 4 days? Y/N

2. Is there unexplored high-value surface remaining? Y/N
   (file upload, OAuth, GraphQL, mobile)

3. Did I encounter any behaviour that was odd but unexplained? Y/N
   (unexpected 500 errors, different response for same input, rate limit anomaly)
   Notes: ___

4. Am I testing techniques I am confident in, or am I repeating failed approaches?
   ___

Decision:
  [ ] CONTINUE — unexplored surface remains; specific next steps: ___
  [ ] PIVOT SURFACE — change focus to: ___  (reason: ___)
  [ ] PIVOT PROGRAMME — this programme exhausted; move to Programme 2 now: ___
```

---

## Targeted Deep-Dive (if continuing)

Based on the audit, pick ONE untested surface for today:

```
Surface chosen: ___

Specific test plan:
  1. ___
  2. ___
  3. ___

Tools needed: ___
Time allocated: ___ hours
```

---

## Report Drafting (use any remaining time)

If findings exist — draft or complete reports now. Do not let findings sit undocumented.

```
Finding to report today: ___
Report status:
  [ ] Title written
  [ ] CVSS calculated
  [ ] Reproduction steps complete
  [ ] Evidence (screenshots / requests) attached
  [ ] Remediation written
  [ ] Submitted: Y/N
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q335.1, Q335.2 …).

---

## Navigation

← Previous: [Day 334 — First Programme Sprint Day 4](DAY-0334-First-Programme-Sprint-Day-04.md)
→ Next: [Day 336 — First Programme Sprint Day 6](DAY-0336-First-Programme-Sprint-Day-06.md)
