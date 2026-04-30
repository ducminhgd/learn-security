---
title: "Write-Up Sprint Day 4 — Report Writing Practice"
tags: [write-up, report-writing, communication, practice, bug-bounty]
module: 05-BugBountyOps-02
day: 329
related_topics:
  - Write-Up Sprint Day 3 (Day 328)
  - Responsible Disclosure Process (Day 269)
  - Earnings Optimisation (Day 273)
---

# Day 329 — Write-Up Sprint Day 4: Report Writing Practice

> "The vulnerability is half the battle. The report is the other half. A
> mediocre bug in an excellent report gets triaged as High. An excellent bug in
> a mediocre report gets triaged as Low. Triage engineers have ten reports to
> read before lunch. Make yours unmissable."
>
> — Ghost

---

## Goals

Practise writing a complete, professional bug bounty report from scratch.
Use a vulnerability found during Days 291–328 as the subject,
or use a scenario below if no real finding is available.

**Time budget:** 3 hours.

---

## Report Writing Template — Fill All Sections

### Title

```
Format: [Severity] [Verb] + [Asset/Endpoint] + via + [Technique]
Good:   "Unauthenticated Account Takeover on /api/v1/users via IDOR"
Bad:    "IDOR bug found"

Your title: ___
```

### Severity and CVSS

```
CVSS 3.1 vector: AV:___/AC:___/PR:___/UI:___/S:___/C:___/I:___/A:___

Explain each component (do not just copy — prove you understand):
  AV (Attack Vector):        ___  because: ___
  AC (Attack Complexity):    ___  because: ___
  PR (Privileges Required):  ___  because: ___
  UI (User Interaction):     ___  because: ___
  S (Scope):                 ___  because: ___
  C (Confidentiality):       ___  because: ___
  I (Integrity):             ___  because: ___
  A (Availability):          ___  because: ___

Score: ___   Severity: ___
```

### Summary (100 words max)

```
[Write here — a senior developer with no security background should understand
the bug, how it works, and why it matters after reading this.]

___
```

### Impact

```
Business impact (not technical — answer: "so what?"):
  ___

Affected users: ___  (count, type)
Data exposed: ___  (PII, financial, credentials)
Action available to attacker: ___
Regulatory implications: ___  (GDPR, PCI, HIPAA — if applicable)
```

### Steps to Reproduce

```
Environment: ___  (browser, OS, auth state)

1. Navigate to ___
2. Intercept the request with Burp Suite:
   ___
3. Modify parameter ___ from ___ to ___
4. Forward request.
5. Observe: ___

The attacker now has access to ___
```

### Evidence

```
Screenshot 1: ___  (shows: ___)
Screenshot 2: ___  (shows: ___)
HTTP request/response:
  [paste relevant request here]

  [paste relevant response here]

PoC script (if written):
  ___
```

### Root Cause

```
The application does not verify that the requesting user has permission to
access the resource identified by [PARAMETER].

Vulnerable code pattern (if visible):
  ___

CWE: ___
MITRE ATT&CK: ___
```

### Remediation

```
Short-term (patch within 48 hours):
  ___

Long-term (architectural fix):
  ___

Reference: ___  (OWASP / CWE link)
```

---

## Report Self-Review Checklist

```
[ ] Title includes severity, asset, and technique
[ ] CVSS score calculated and justified per component
[ ] Impact explained in business terms (not just technical)
[ ] Reproduction steps are exact — a non-security engineer could follow them
[ ] Evidence includes at least one HTTP request and one screenshot
[ ] Root cause references a CWE
[ ] Remediation is specific (not "add input validation")
[ ] No internal jargon without explanation
[ ] Report is ≤ 800 words (concise wins triage)
```

---

## Scenario (If No Real Finding Available)

Use this scenario to practise:

```
Scenario: You find that GET /api/v1/invoices?invoice_id=1234 returns
          the invoice PDF for invoice 1234. Incrementing the ID to 1235
          returns another user's invoice containing name, address, and
          purchase history. The endpoint requires authentication (Bearer token)
          but does not check whether the authenticated user owns invoice 1235.

Severity: High (CVSS ~7.5)
Write the full report above using this scenario.
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q329.1, Q329.2 …).

---

## Navigation

← Previous: [Day 328 — Write-Up Sprint Day 3](DAY-0328-Write-Up-Sprint-Day-03.md)
→ Next: [Day 330 — Write-Up Sprint Day 5](DAY-0330-Write-Up-Sprint-Day-05.md)
