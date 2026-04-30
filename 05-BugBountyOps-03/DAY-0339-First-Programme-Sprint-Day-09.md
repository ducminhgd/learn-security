---
title: "First Programme Sprint Day 9 — Chaining and Impact Escalation"
tags: [live-programme, bug-bounty, chaining, impact-escalation, P1, practice]
module: 05-BugBountyOps-03
day: 339
related_topics:
  - First Programme Sprint Day 8 (Day 338)
  - Write-Up Sprint Day 3 (Day 328)
  - Weak Area Reinforcement Day 9 (Day 324)
---

# Day 339 — First Programme Sprint Day 9: Chaining and Impact Escalation

> "You have been hunting for nine days. Look at every finding from a different
> angle. Not 'what did I find?' but 'what does this finding enable?' The IDOR
> you logged as a Medium might be the first step of an account takeover chain.
> Check."
>
> — Ghost

---

## Goals

Review all findings from Days 331–338.
Identify chain opportunities that elevate severity.
Attempt to escalate at least one finding from its current severity.

**Time budget:** 5–6 hours.

---

## Finding Review Table

```
#  | Type    | Severity | Can It Chain To?           | Chained Severity
---|---------|----------|----------------------------|-----------------
1  | ___     | ___      | ___                        | ___
2  | ___     | ___      | ___                        | ___
3  | ___     | ___      | ___                        | ___
4  | ___     | ___      | ___                        | ___
```

---

## Chain Attempt Log

### Chain Attempt 1

```
Starting finding: #___  (___type, ___severity)
Goal: escalate to ___

Step 1: Use finding #___ to obtain: ___
Step 2: Use obtained data/access to: ___
Step 3: Final impact: ___

Chain successful: Y/N
New severity: ___
CVSS before chain: ___
CVSS after chain: ___

Evidence of full chain:
  1. ___
  2. ___
```

### Chain Attempt 2

```
Starting finding: #___
Chain: ___ → ___ → ___
Outcome: ___
New severity: ___
```

---

## Self-XSS to Full XSS — Escalation Drill

```
Self-XSS found: Y/N
  Location: ___
  Payload: ___

Escalation attempt (requires CSRF or login CSRF):
  Step 1: Attacker posts malicious content via CSRF on victim's behalf
    CSRF payload to trigger self-XSS on victim's account: ___
    CSRF protection present: Y/N → bypassable: Y/N

  OR

  Step 1: Find a way to make victim's browser render attacker's data
    (e.g. shared document, comment visible to other users)

  Escalation successful: Y/N
  New impact: ___
```

---

## Open Redirect to Token Theft

```
Open redirect found: Y/N
  Parameter: ___  Endpoint: ___
  Payload: ?next=https://attacker.com

OAuth integration present: Y/N
  Can I use the open redirect as the redirect_uri in OAuth flow?
    Attempt: ?redirect_uri=https://TARGET.com/redirect?to=https://attacker.com
    Authorization server accepts: Y/N
    Token/code delivered to attacker.com: Y/N

  Chained severity: Open redirect alone = P4 → OAuth token theft = P1
```

---

## Severity Negotiation Prep

```
For each finding with a severity upgrade:
  Old severity: ___   New severity after chain: ___
  
  Justification I will include in the report:
    "This vulnerability can be chained with [FINDING X] to achieve
    [FULL IMPACT]. Without this chain, impact is [LOW]. With the chain,
    the attacker can [HIGH IMPACT ACTION]."

CVSS vector before chain: ___  Score: ___
CVSS vector after chain:  ___  Score: ___
Difference: ___
```

---

## Updated Submission Plan

```
Report to update with chain evidence: #___
Updated severity to request: ___

New report for chained finding: Y/N
  Report ready: Y/N
  Submission target: today / Day 340
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q339.1, Q339.2 …).

---

## Navigation

← Previous: [Day 338 — First Programme Sprint Day 8](DAY-0338-First-Programme-Sprint-Day-08.md)
→ Next: [Day 340 — First Programme Sprint Day 10](DAY-0340-First-Programme-Sprint-Day-10.md)
