---
title: "Live Programme Practice Day 8 — First Report Draft and Submission"
tags: [practice, live-programme, report-writing, submission, CVSS, impact-analysis,
       bug-bounty, methodology, triage]
module: 05-BugBountyOps-01
day: 283
related_topics:
  - Live Programme Practice Day 7 (Day 282)
  - Report Structure and Format (Day 161)
  - CVSS Scoring and Risk Rating (Day 162)
  - PoC Writing and Impact Analysis (Day 163)
---

# Day 283 — Live Programme Practice Day 8: First Report Draft and Submission

> "The best finding in the world is worthless if the report is bad. Today
> you submit your first real report — or your first real report draft if you
> are not yet ready to submit. The standard is: could a triage engineer who
> has never seen this application reproduce this bug in 10 minutes using
> only your report?"
>
> — Ghost

---

## Goals

Write and submit at least one professional finding report.

**Time budget:** 5–6 hours.

---

## Block 1 — Finding Selection (30 min)

From your finding log (Days 276–282), select the report to write first:

```
Criteria for first submission:
  - Clear, reproducible vulnerability (triage can confirm without asking)
  - Complete evidence (request, response, screenshot)
  - Honest severity assessment
  - You tested it with two controlled accounts (not real user data)

Selected finding: ___
Severity estimate: ___
Reason this is the right first submission: ___
```

---

## Block 2 — Report Writing (120 min)

Use your report template from Day 275. Complete every section.

**Quality checklist before writing:**
```
[ ] I can reproduce this bug right now in less than 5 minutes
[ ] My reproduction steps use only my own test accounts
[ ] I have not accessed real user data
[ ] I have a screenshot of the exact request and response
[ ] I have a curl command that reproduces the issue
```

**Report sections to complete:**
```
[ ] Title (format: Vulnerability — Location — Impact)
[ ] Severity + CVSS 3.1 vector string + calculated score
[ ] Summary (2–3 sentences)
[ ] Impact (business impact with scale + regulatory dimension)
[ ] Steps to Reproduce (numbered, exact commands)
[ ] Evidence (annotated screenshots + raw request/response)
[ ] Root Cause (one sentence)
[ ] Remediation (specific, code-level)
```

---

## Block 3 — Peer Review (30 min)

Before submitting, answer these questions:

```
Q1: Could a developer who has never seen a bug report reproduce this in 10 min?
    Answer: ___

Q2: Does my severity estimate have evidence? Is my CVSS vector defensible?
    CVSS: ___  Justification: ___

Q3: Is my business impact statement specific enough?
    "Attacker can access all user records" is better than "data exposure."
    Check: ___

Q4: Does my remediation recommend a specific fix, not a vague instruction?
    "Implement an authorization check that verifies the requesting user owns
    the resource before returning it" is better than "fix the access control."
    Check: ___
```

---

## Block 4 — Submission (30 min)

```
[ ] Submit through the platform (not email)
[ ] Attach all evidence files
[ ] Set severity to your estimate (you can negotiate later)
[ ] Confirm submission received (report ID assigned)

Report ID: ___
Submitted: YYYY-MM-DD HH:MM
Estimated response time per programme SLA: ___
Follow-up reminder set for: ___
```

---

## Block 5 — Second Finding Preparation (90 min)

While you wait for triage on finding #1, continue testing:

```
Next technique to apply: ___
Next endpoint to test: ___
Next finding candidate in my log: ___
```

---

## Session Debrief

```
Reports submitted today: ___
Finding type: ___
Confidence in report quality: Low / Medium / High
Aspect of the report I am least confident in: ___
What I will do differently on the next report: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q283.1, Q283.2 …).

---

## Navigation

← Previous: [Day 282 — Live Programme Practice Day 7](DAY-0282-Live-Programme-Practice-Day-07.md)
→ Next: [Day 284 — Live Programme Practice Day 9](DAY-0284-Live-Programme-Practice-Day-09.md)
