---
title: "Day 365 — Bug Bounty Hunter Gate: Year 1 Capstone"
tags: [Year-1, gate, capstone, assessment, competency, bug-bounty]
module: 05-BugBountyOps-03
day: 365
related_topics:
  - Gate Preparation Day 4 (Day 364)
  - Web Exploitation Competency Gate (Day 165)
  - BroadSurface Competency Check (Day 260)
---

# Day 365 — Bug Bounty Hunter Gate: Year 1 Capstone

> "Three hundred and sixty-five days. Every concept from first principles.
> Every technique drilled until it was automatic. Every report written until
> the format was instinct. Now you operate on an unknown target with no hints,
> no hints on the door, no 'VULNERABILITY HERE' comments.
>
> This is what the training was for. Show me what you built."
>
> — Ghost

---

## Gate Structure

| Part | Format | Time | Criteria |
|---|---|---|---|
| 1 | Oral — Concept Questions | 30 min | ≥ 6/8 correct, no reference |
| 2 | Live Engagement — Unknown Target | 3 hours | ≥ 1 confirmed P1–P3 finding |
| 3 | Report Writing | 90 min | Professional quality (see rubric) |
| 4 | Defensive Translation | 20 min | Detection + fix technically correct |
| 5 | Year-2 Reflection | 15 min | Demonstrates self-awareness and plan |

**Pass requirement:** All five parts must pass. No weighted average.

---

## Part 1 — Oral Concept Questions (30 min)

Answer without any reference material. Write directly here.

```
Q1: Explain BOLA. Why is it #1 in the OWASP API Top 10?
    Write the vulnerable pseudocode and the fixed version.
A: ___

Q2: A target application uses JWT with HS256. You discover the public RSA key
    at /jwks.json. Describe the full attack chain.
A: ___

Q3: You find blind SQL injection in a POST parameter. The database is PostgreSQL.
    Write the minimal payload to extract the first character of the DBA username
    using time-based injection.
A: ___

Q4: What is the CVSS 3.1 Scope component? Give one example of a finding where
    scope is Changed vs. Unchanged — and explain the CVSS impact.
A: ___

Q5: You find SSRF in a form that fetches URLs. The target runs on AWS EC2.
    List the exact request sequence to obtain IAM role credentials.
    What would you do with them next?
A: ___

Q6: A bug bounty programme's safe harbour language says "we will not pursue
    legal action against researchers acting in good faith." You test an endpoint
    and find a misconfigured S3 bucket containing customer data. What do you do?
    What do you NOT do?
A: ___

Q7: GraphQL introspection is enabled on the target. Describe the exact HTTP
    request you send, what you look for in the response, and two attack vectors
    introspection enables.
A: ___

Q8: You have AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN
    from the EC2 metadata service. The role appears to have
    iam:CreatePolicyVersion. Describe the full escalation.
A: ___
```

```
Part 1 score: ___/8  (≥ 6 required to pass)
Pass: Y/N
```

---

## Part 2 — Live Engagement (3 hours)

```
Target: ___  (ghost assigns — you have not seen this machine before)
Start time: ___

Pre-engagement plan (10 min):
  First hypothesis: ___
  First technique: ___
  Tools to run immediately: ___

Engagement log:
  00:00–00:30: ___
  00:30–01:30: ___
  01:30–02:30: ___
  02:30–03:00: ___

Finding confirmed:
  Type: ___
  Severity: ___  (P1 / P2 / P3)
  Evidence: ___
  CWE: ___

Pass criteria: confirmed P1–P3 finding with evidence
Pass: Y/N
```

---

## Part 3 — Report Writing (90 min)

```
Title: ___

Severity: ___   CVSS: ___
Vector: AV:___/AC:___/PR:___/UI:___/S:___/C:___/I:___/A:___

CVSS Justification:
  ___

Summary:
  ___

Impact:
  ___

Steps to Reproduce:
  1. ___
  2. ___
  3. ___

HTTP Request:
  ___

Response (relevant):
  ___

Root Cause (CWE: ___):
  ___

Remediation:
  ___
```

### Report Rubric

```
[ ] Title: severity + asset + technique
[ ] CVSS vector and score present and justified
[ ] Impact in business terms (not just "attacker can read data")
[ ] Reproduction steps complete — could be followed by a non-security engineer
[ ] Evidence (HTTP request + response or screenshot)
[ ] Root cause references a CWE
[ ] Remediation is specific (not "add input validation")
[ ] No spelling errors, no broken formatting
[ ] ≤ 800 words

Score: ___/9 checklist items  (≥ 7 required)
Pass: Y/N
```

---

## Part 4 — Defensive Translation (20 min)

```
For the finding you just reported:

Detection:
  What log source captures this attack? ___
  What is the log field / pattern to alert on? ___
  Write a Sigma rule title and detection block:
    title: ___
    detection:
      selection:
        ___
      condition: selection

Fix:
  Root cause (one sentence): ___
  Exact code change:
    Before: ___
    After:  ___
  Config / architecture change: ___

Assessment:
  Detection technically correct: Y/N
  Fix addresses root cause: Y/N
  Pass: Y/N
```

---

## Part 5 — Year-2 Reflection (15 min)

```
Q: What is the single most important technical skill you built in Year 1?
A: ___

Q: What technique do you know how to execute but still cannot explain
   from first principles?
A: ___

Q: Year 2 focuses on binary exploitation, reverse engineering, mobile security,
   and red team operations. Name the module you are most and least prepared for.
   Explain both.
A: ___

Q: If you had to test a completely unknown application today — with no lab,
   no hints, and a 4-hour time limit — what would your first 30 minutes look like?
A: ___

Assessment:
  Demonstrates honest self-awareness: Y/N
  Has a coherent Year-2 plan: Y/N
  Pass: Y/N
```

---

## Year-1 Gate — Final Verdict

```
Part 1 — Oral:       PASS / FAIL  (score: ___/8)
Part 2 — Live:       PASS / FAIL  (finding: ___, severity: ___)
Part 3 — Report:     PASS / FAIL  (score: ___/9)
Part 4 — Defensive:  PASS / FAIL
Part 5 — Reflection: PASS / FAIL

OVERALL: PASS / FAIL
```

---

## On Pass — Year-2 Entry

```
You have completed Year 1.

The road ahead: binary exploitation, reverse engineering, hardware security,
mobile, and full red team operations. The foundation you built in Year 1 is
not a ceiling — it is the floor of Year 2.

The skills that transfer directly:
  - Methodical thinking under time pressure
  - Report writing at professional standard
  - Ethical framework — the law, the scope, the responsibility
  - The Ghost Method: Recon → Exploit → Detect → Harden

Year 2 starts with a question: "You can break web applications. Can you break
the thing the web application runs on?"

Welcome to the next level.
```

---

## On Failure — Targeted Remediation

```
Part(s) failed: ___

Targeted remediation plan:
  Part 1 failure → re-read: ___  Complete two labs on: ___  Re-gate in 7 days
  Part 2 failure → complete 3 more HTB machines in 2 weeks. Re-gate: ___
  Part 3 failure → write 3 complete reports from past findings. Re-gate: ___
  Part 4 failure → defensive translation drill (Day 357 format). Re-gate: ___
  Part 5 failure → re-read Year-1 retrospective (Day 358). Re-gate: ___

Re-gate date: ___
```

---

## Final Entry

```
Date completed: ___
Ghost's assessment: ___

Year 1 — complete.
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q365.1, Q365.2 …).

---

## Navigation

← Previous: [Day 364 — Gate Preparation Day 4](DAY-0364-Gate-Preparation-Day-04.md)
→ Next: Year 2 begins.
