---
title: "Live Programme Practice Day 11 — Programme Rotation or Deep Dive Decision"
tags: [practice, live-programme, programme-rotation, target-selection, strategy,
       deep-dive, bug-bounty, methodology, time-management]
module: 05-BugBountyOps-01
day: 286
related_topics:
  - Live Programme Practice Day 10 (Day 285)
  - Choosing the Right Program (Day 263)
  - Tracking Findings and Notes (Day 268)
  - Earnings Optimisation (Day 273)
---

# Day 286 — Live Programme Practice Day 11: Programme Rotation or Deep Dive Decision

> "After 10 days you know this target better than most researchers who ever
> looked at it. The question is: is there more to find, or have you hit the
> ceiling for your current technique set? Make the decision deliberately.
> Staying too long on an exhausted target is a slow way to earn nothing."
>
> — Ghost

---

## Goals

Make a data-driven rotation decision and execute it, or continue deep-dive
testing with a new technique angle.

**Time budget:** 5–6 hours.

---

## Block 1 — Rotation Decision (45 min)

Evaluate your current primary programme against the rotation criteria from
Day 263:

```
Stop signals present:
[ ] 3+ sessions with zero new leads
[ ] Last 5 report drafts were all duplicates
[ ] Every interesting endpoint returns 403
[ ] Programme > 12 months since last scope update
[ ] SLA consistently > 60 days

Continue signals present:
[ ] Found a P3 recently (cluster effect)
[ ] Scope expanded recently
[ ] New technique not yet applied
[ ] Triage team is responsive

Decision: Continue / Rotate
Justification: ___
```

---

## Block 2A — If Continuing: New Angle Testing (240 min)

Apply the one technique area you have not yet systematically applied:

Options:
- HTTP request smuggling (if target uses reverse proxy)
- Web cache poisoning (if target has CDN)
- OAuth token theft chain (if OAuth is present)
- Password reset flow (if not yet tested)
- File upload (if not yet tested)
- Mobile API surface (if mobile app in scope)

Chosen angle: ___

```bash
# Document your approach for this session:
Technique:     ___
Target surface: ___
First test:     ___
```

---

## Block 2B — If Rotating: New Programme Setup (240 min)

```
[ ] Apply programme scoring matrix — select new programme
[ ] Complete policy analysis
[ ] Run passive recon
[ ] Build initial target profile

New programme: ___
Score: ___/30
Rationale: ___
```

---

## Block 3 — Portfolio Update (30 min)

```
[ ] Update finding tracker with all current statuses
[ ] Update monthly earnings log
[ ] Update programme allocation table
[ ] Write one sentence capturing the key insight from the past 11 days
```

---

## Session Debrief

```
Decision made: Continue / Rotate
New angle / New programme: ___
Findings this session: ___
Portfolio state:
  Total submitted: ___
  Pending: ___
  Accepted: ___
  Earnings: $___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q286.1, Q286.2 …).

---

## Navigation

← Previous: [Day 285 — Live Programme Practice Day 10](DAY-0285-Live-Programme-Practice-Day-10.md)
→ Next: [Day 287 — Live Programme Practice Day 12](DAY-0287-Live-Programme-Practice-Day-12.md)
