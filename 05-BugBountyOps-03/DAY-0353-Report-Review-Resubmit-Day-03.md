---
title: "Report Review and Resubmit Day 3 — Unresponsive Programmes and Escalation"
tags: [live-programme, bug-bounty, escalation, unresponsive, disclosure-timeline, practice]
module: 05-BugBountyOps-03
day: 353
related_topics:
  - Report Review Day 2 (Day 352)
  - Responsible Disclosure Process (Day 269)
  - Bug Bounty Legal and Ethics (Day 270)
---

# Day 353 — Report Review and Resubmit Day 3: Unresponsive Programmes and Escalation

---

## Goals

Handle reports that have not received a triage response within the expected window.
Understand the escalation ladder and coordinated disclosure timelines.
Practise the professional escalation process.

**Time budget:** 3–4 hours.

---

## Response Time Benchmarks

```
Expected first response times by platform:
  HackerOne (managed bounty):  1–3 business days
  HackerOne (VDP):             5–10 business days
  Bugcrowd:                    3–5 business days
  Intigriti:                   3–5 business days
  Direct programme (email):    5–15 business days

Reports requiring follow-up (no response after expected window):
  Report #___: Submitted ___  Days waiting: ___
  Report #___: Submitted ___  Days waiting: ___
```

---

## Escalation Ladder

```
Level 1 — Polite follow-up (Day 7–10 with no response):
  "Hello, I wanted to follow up on report #[ID] submitted on [DATE].
  Please let me know if you need any additional information.
  Thank you."

Level 2 — State your disclosure timeline (Day 20–30):
  "Hello, following up on report #[ID]. I plan to disclose this
  vulnerability publicly after the standard 90-day coordinated
  disclosure window from the submission date [DATE], which would
  be [DATE + 90]. Please let me know if you have any questions."

Level 3 — Final notice (Day 80–85):
  "This is a final notice before public disclosure. Report #[ID]
  has been open since [DATE]. I will disclose on [DATE + 90]
  unless we reach an agreement. I am available to discuss."

Level 4 — Disclosure (Day 90+):
  If the vulnerability has been fixed: full disclosure is ethical.
  If NOT fixed: limited disclosure (technique, not target) or defer.
  Always consult programme policy on disclosure before acting.
```

---

## Follow-Up Messages Written

### Report #___

```
Days since submission: ___
Escalation level: 1 / 2 / 3
Message sent:
  ___
Date sent: ___
```

### Report #___

```
Days since submission: ___
Escalation level: ___
Message sent: ___
Date sent: ___
```

---

## Platform Escalation (if programme is unresponsive on a managed platform)

```
HackerOne: "Report" button → "Request mediation" if programme unresponsive > 14 days
Bugcrowd:  Contact programme manager through platform dashboard
Intigriti: Contact support via live chat or email for mediation

Platform escalation triggered: Y/N
  Report #___  |  Platform: ___  |  Date escalated: ___
  Outcome: ___
```

---

## Direct Email Programmes — Escalation

```
If the target has no platform (direct email / VDP page only):
  1. Send to the primary security contact (security@TARGET.com)
  2. CC psirt@TARGET.com or security-response@TARGET.com if different
  3. If no response after 30 days: search LinkedIn for CISO / Head of Security
  4. CERT/CC mediation as last resort before public disclosure

Escalation attempted: Y/N
Contact used: ___
Response: ___
```

---

## Disclosure Decision Log

```
For any vulnerability approaching Day 90:
  Report #___:
    Submission date: ___
    Day 90 date: ___
    Fix confirmed: Y/N
    Disclosure decision: Full / Limited / Defer
    Reason: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q353.1, Q353.2 …).

---

## Navigation

← Previous: [Day 352 — Report Review Day 2](DAY-0352-Report-Review-Resubmit-Day-02.md)
→ Next: [Day 354 — Report Review and Resubmit Day 4](DAY-0354-Report-Review-Resubmit-Day-04.md)
