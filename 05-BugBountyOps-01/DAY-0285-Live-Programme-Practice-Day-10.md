---
title: "Live Programme Practice Day 10 — Second Report Submission and Triage Follow-Up"
tags: [practice, live-programme, report-writing, submission, triage, follow-up,
       severity-negotiation, bug-bounty, methodology]
module: 05-BugBountyOps-01
day: 285
related_topics:
  - Live Programme Practice Day 9 (Day 284)
  - Handling Duplicates and Triage (Day 164)
  - Responsible Disclosure Process (Day 269)
  - Earnings Optimisation (Day 273)
---

# Day 285 — Live Programme Practice Day 10: Second Report Submission and Triage Follow-Up

> "Most researchers submit and forget. The ones who earn consistently engage
> with the triage process — politely, professionally, and with evidence.
> Triage feedback is data. A downgrade tells you what you missed. A duplicate
> tells you where the competition is. An accepted report tells you your report
> quality is solid. Read each response carefully."
>
> — Ghost

---

## Goals

Submit your second report. Handle any triage responses received on report #1.

**Time budget:** 5–6 hours.

---

## Block 1 — Triage Response Review (if received) (60 min)

For each response received on Day 283's submission:

```
Report #1 status: Triaged / Pending / Resolved / Duplicate / N/A

If Triaged:
  Assigned severity: ___
  My estimated severity: ___
  Difference: ___
  Is negotiation warranted? Y/N
  My negotiation argument: ___

If Duplicate:
  Programme said: ___
  Lesson: Was this a predictable duplicate? Y/N
  Why I missed the competition signal: ___
  Adjustment to programme rotation: ___

If N/A:
  Reason given: ___
  Is the N/A correct? Y/N
  What I would do differently: ___
  Impact on my Signal score: ___

If Pending (no response):
  Days since submission: ___
  Is a follow-up warranted? (programme SLA exceeded?) Y/N
  Follow-up drafted: ___
```

---

## Block 2 — Second Report Submission (90 min)

```
[ ] Finding selected: ___
[ ] Reproduction confirmed this session (not just from memory)
[ ] Report complete — all sections filled
[ ] CVSS vector calculated: ___  Score: ___
[ ] Reproducible with test accounts only
[ ] Submitted

Report ID #2: ___
```

---

## Block 3 — Deep Dive on Current Programme (90 min)

Use what you learned from triage feedback to refocus testing:

If triage confirmed a P3 → look harder for P2 chaining opportunity in same area.
If triage N/A'd a finding → identify why and avoid that class of false positive.
If no triage yet → continue systematic coverage:

```
Untested areas remaining on this programme:
1. ___
2. ___
3. ___
```

Focused testing session on one of those areas.

---

## Block 4 — Week 1 Retrospective (60 min)

Ten days into live programme practice. Assess:

```
Reports submitted: ___
Accepted/triaged: ___
Duplicates: ___
N/A: ___
Pending: ___

Technique hit rate:
  Auth attacks: ___/___  tested → found
  IDOR testing: ___/___
  SSRF testing: ___/___
  Injection:    ___/___

Most productive session: Day ___  Why: ___
Least productive session: Day ___  Why: ___
Key insight from this week: ___
One methodology change I am making: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q285.1, Q285.2 …).

---

## Navigation

← Previous: [Day 284 — Live Programme Practice Day 9](DAY-0284-Live-Programme-Practice-Day-09.md)
→ Next: [Day 286 — Live Programme Practice Day 11](DAY-0286-Live-Programme-Practice-Day-11.md)
