---
title: "BugBountyOps-1 Competency Check — Platforms, Strategy, Automation, Reporting"
tags: [competency-check, bug-bounty, platforms, automation, Nuclei, recon-pipeline,
       reporting, CVSS, scope, methodology, self-assessment]
module: 05-BugBountyOps-01
day: 290
related_topics:
  - Live Programme Practice Day 14 (Day 289)
  - All Days 261–289
  - CTF and Skill Sharpening (Days 291–330)
---

# Day 290 — BugBountyOps-1 Competency Check

> "Fifteen days of theory and practice. Today you demonstrate mastery of the
> operational foundation: the platforms you use, the pipelines you run, the
> reports you write, and the decisions you make when the situation is not
> in the textbook. This is not a final exam — it is a baseline snapshot.
> Every gap you identify here is an investment target for Days 291–330."
>
> — Ghost

---

## Structure

| Section | Format | Time |
|---|---|---|
| Part 1: Platform and Policy | Written, no notes | 30 min |
| Part 2: Live Recon Task | Hands-on | 45 min |
| Part 3: Report Writing Sprint | Hands-on | 60 min |
| Part 4: Nuclei Template | Written/code | 30 min |
| Part 5: Decision Scenarios | Written | 20 min |
| **Total** | | **~3–4 hours** |

---

## Part 1 — Platform and Policy (No Notes)

Answer all questions.

**Q1.** Describe the HackerOne Signal system:
(a) How is Signal calculated?
(b) What types of report outcomes raise Signal?
(c) What types lower it?
(d) What threshold unlocks private programme invitations?

---

**Q2.** You find a vulnerability on `payments.example.com` while testing a
programme scoped to `*.example.com`. Your recon shows `payments.example.com`
resolves to a Stripe-hosted checkout page.

(a) Is this target in scope?
(b) What do you do with the vulnerability?
(c) Write the exact message you send to the programme.

---

**Q3.** A programme's policy says:
```
"Out-of-scope vulnerability classes:
  Self-XSS, rate limiting on non-auth endpoints,
  missing security headers without demonstrated impact,
  software version disclosure."
```

You find:
(i) A reflected XSS that only triggers if the attacker is also the victim.
(ii) A missing X-Frame-Options header on the login page.
(iii) An Apache version in the Server header.
(iv) No rate limiting on the password reset endpoint.

For each: submit or do not submit? Justify.

---

**Q4.** Calculate CVSS 3.1 for:

> An authenticated attacker (any regular user) can access the profile
> data of any other user (name, email, phone, address) by incrementing
> a numeric user ID. No further interaction is required. The data is read-only.

Write the full vector string and score.

---

## Part 2 — Live Recon Task (45 min, no notes)

Select any currently active VDP programme from HackerOne.

```bash
# START TIMER
# Your goals within 45 minutes:

[ ] Complete passive subdomain enumeration
[ ] Validate live hosts with httpx
[ ] Identify 3 interesting targets with reasons
[ ] Document technology stack for the primary domain
[ ] Produce the target profile template sections 1–4

# Record:
Subdomains found: ___
Live hosts: ___
Priority target 1: ___  Why: ___
Priority target 2: ___  Why: ___
Priority target 3: ___  Why: ___
```

---

## Part 3 — Report Writing Sprint (60 min, no notes)

You will be given a bug description. Write a complete, publishable report.

**Bug description:**
```
You are testing api.example.com (scope: *.example.com, authenticated users only).
You discover that GET /api/v1/users/{id}/transactions returns the full
transaction history of any user when you provide their user ID.
You tested this with your own account ID (ID: 1234) and a second test account
(ID: 1235). The response includes:
  - Transaction amount
  - Merchant name
  - Transaction date
  - Card last 4 digits

You have two test accounts. You did NOT access any real user data.
The programme pays up to $2,000 for High severity findings.
```

Produce a complete report with all sections. Submit it to the Questions
section below when finished.

---

## Part 4 — Nuclei Template (30 min, no notes)

Write a valid Nuclei YAML template that detects the vulnerability described
in Part 3. Requirements:
- Correct YAML structure
- Correct template ID and info section
- Request that would trigger the vulnerability
- Matchers that detect transaction data in the response (not just status 200)
- Appropriate severity

---

## Part 5 — Decision Scenarios (20 min)

For each scenario, state your exact decision and one-sentence justification:

**Scenario A:** You submitted a P2 IDOR 12 days ago. The programme SLA says
"first response within 7 business days." No response. What do you do?

**Scenario B:** Triage downgrades your P2 to P3. Their reason: "Requires
authentication to exploit." Your IDOR requires a logged-in user. Are they right?
What is your response?

**Scenario C:** You are testing a programme and your Nuclei scan triggers
200 requests to `admin.example.com` in 60 seconds. The programme policy says
"testing must not disrupt normal service." You notice some admin pages are now
returning 503. What do you do?

**Scenario D:** You discover a critical SQL injection that bypasses authentication
entirely. The programme's safe harbour is: "We appreciate responsible disclosure."
No explicit legal language. What do you do before submitting?

---

## Competency Gate Criteria

| Criterion | Minimum bar |
|---|---|
| Platform/policy questions | ≥ 3/4 fully correct |
| Recon task | Target profile completed within 45 min |
| Report writing | All sections complete, CVSS within ±0.5, reproducible |
| Nuclei template | Syntactically valid, correct matchers |
| Decision scenarios | All 4 correct with valid reasoning |

**If you do not pass:**

| Failed section | Return to |
|---|---|
| Platform/policy | Days 261–262, 270 |
| Recon task | Days 265, 276–277 |
| Report writing | Days 161–164, 283 |
| Nuclei template | Day 264 |
| Decision scenarios | Days 262, 269–270 |

---

## What Comes Next

BugBountyOps-01 is complete. You have the operational foundation:
platforms, policy, pipeline, tools, and reporting.

**Days 291–330:** CTF and skill sharpening — sharpen every technique area
using structured HackTheBox and CTF challenges before returning to live
programmes with refined skills.

---

## Questions and Competency Check Answers

> Part 1 — Write your answers here. Label Q1 through Q4.

> Part 3 — Paste your complete report here.

> Part 4 — Paste your Nuclei template here.

> Part 5 — Write your decisions for Scenarios A–D here.

> General questions use numbering Q290.1, Q290.2 …

---

## Navigation

← Previous: [Day 289 — Live Programme Practice Day 14](DAY-0289-Live-Programme-Practice-Day-14.md)
→ Next: [Day 291 — HTB Web Series Day 1](../05-BugBountyOps-02/DAY-0291-HTB-Web-Series-Day-01.md)
