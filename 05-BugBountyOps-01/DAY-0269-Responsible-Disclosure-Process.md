---
title: "Responsible Disclosure Process — Disclosure Timeline, Triage Expectations, Escalation"
tags: [responsible-disclosure, triage, timeline, escalation, coordination, CVD,
       bug-bounty, communication, SLA, disclosure-policy, operations]
module: 05-BugBountyOps-01
day: 269
related_topics:
  - Bug Bounty Legal and Ethics (Day 270)
  - Report Structure and Format (Day 161)
  - Handling Duplicates and Triage (Day 164)
  - Portfolio and Reputation Building (Day 272)
---

# Day 269 — Responsible Disclosure Process

> "You found the bug. Now you have a decision, not a right. The decision is
> how to use what you know. Responsible disclosure is not weakness — it is
> the thing that keeps this ecosystem alive. A researcher who drops a zero-day
> publicly burns one bridge. A researcher who discloses responsibly builds
> relationships with every security team they work with."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Navigate the full disclosure timeline from discovery to resolution.
2. Set appropriate triage expectations and follow up professionally.
3. Handle unresponsive organisations with a documented escalation process.
4. Understand the difference between coordinated disclosure and full disclosure.
5. Know your rights and limits when an organisation becomes hostile.

**Time budget:** 2–3 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| Bug bounty platforms overview | Day 261 |
| Bug bounty legal and ethics | Day 270 (read together) |
| Report structure and format | Day 161 |

---

## Part 1 — The Disclosure Spectrum

From researcher-friendliest to organisation-friendliest:

```
Full Disclosure ←──────────────────────────────→ No Disclosure
(immediate public)                              (never published)

     │            │              │               │
  Full          Coordinated    Limited        Silent
  Disclosure    Disclosure     Disclosure     Fix
  (rare,        (standard       (delayed       (no acknowledgement,
  extreme)      practice)       public         no credit,
                                after fix)     no disclosure)
```

**Standard practice:** Coordinated Vulnerability Disclosure (CVD).
You give the organisation time to fix before you go public. The industry
norm is 90 days, established by Google Project Zero.

---

## Part 2 — Standard Disclosure Timeline

### Platform-Based (Bug Bounty Programme)

When submitting through a platform (HackerOne, Bugcrowd):

```
Day 0:   You submit the report.
Day 1–3: Platform triage team reviews (if platform-triaged).
Day 3–7: Programme security team receives triaged report.
Day 7–14: Programme acknowledges severity + sets bounty expectation.
Day 30–60: Fix is deployed (varies enormously by programme).
Day 60–90: Bounty is paid after fix verification.
Day 90+:  Disclosure request can be made after fix + bounty.
```

**Realistic SLAs from HackerOne statistics:**
- Median time to first response: 2 days
- Median time to triage: 6 days
- Median time to bounty: 53 days
- Median time to resolution: 110 days

### Direct Disclosure (No Platform)

When the organisation has no platform and you email security@company.com:

```
Day 0:   Send the report to security@company.com.
         BCC yourself. Keep the email receipt.
Day 3:   If no response, send a follow-up.
Day 7:   If still no response, search for a security lead on LinkedIn.
         Try CERT/CC or a national CERT (CISA, CERT-EU) as an intermediary.
Day 30:  Formal notice: "I will disclose in 60 days if unresolved."
Day 90:  Public disclosure if unresolved (see Part 4).
```

---

## Part 3 — Communication Best Practices

### Initial Report

- Clear, factual, no hyperbole.
- Include reproduction steps that work without asking for clarification.
- State your severity estimate with brief justification.
- Do not demand a specific bounty in the initial report.
- Do not threaten disclosure in the initial report.

### Follow-Up on No Response (7 days)

```
Subject: Follow-up: Security Report #[REPORT_ID] — [Short title]

Hi [Security Team],

Following up on my report submitted on [DATE] regarding [short description].
I have not received an acknowledgement yet.

Please confirm receipt at your earliest convenience. I am happy to provide
additional information if needed.

[Your handle / name]
```

### Responding to Triage Decisions

If your report is triaged as "Informational" or N/A when you believe it
is valid:

1. Do not send an angry reply.
2. Re-read your report — is the severity clearly demonstrated?
3. Add additional evidence: a video PoC, a second attack scenario,
   or business impact language they may have missed.
4. Reply professionally: "I understand the initial assessment. I'd like
   to provide additional context..."
5. If the triager is clearly wrong and escalation is needed: look for
   a "Request mediation" option on the platform, or flag to the
   programme manager through the platform messaging.

### Severity Negotiation

Triage teams often downgrade severity. Counter professionally:

```
"I'd like to discuss the severity assessment. The CVSS score I
calculated was 8.1 (High) based on:
- Attack Vector: Network
- Privileges Required: Low (authenticated user)
- Impact: High Confidentiality (full user database accessible)

The assigned P3 (Medium) would apply if the scope were limited to a
single user's data. Given that the vulnerability allows access to any
user record by incrementing the ID, the scope is Complete (all users),
which I believe warrants the High severity I initially reported."
```

---

## Part 4 — Unresponsive Organisations

If an organisation does not respond at all within 90 days:

### Escalation Ladder

```
Step 1: Send report to security@, abuse@, contact@.
Step 2: Find a named security contact on LinkedIn/Twitter.
Step 3: Contact the organisation's CISO via LinkedIn.
Step 4: Contact a national CERT (CISA.gov, CERT-EU, NCSC) as an intermediary.
Step 5: Contact a trusted third-party coordinator (CERT/CC, HackerOne mediation).
Step 6: At 90+ days with no engagement: prepare for limited public disclosure.
```

### Documentation Requirements Before Public Disclosure

Before publishing anything:

```
[ ] Sent initial report — have email receipt
[ ] Sent at least 3 follow-ups via different channels
[ ] Attempted to contact a named individual
[ ] Attempted CERT intermediary
[ ] Gave formal 30-day final notice of intent to disclose
[ ] All attempts documented with timestamps
[ ] Confirm the vulnerability still exists (it may have been silently fixed)
[ ] Consult with a lawyer if the vulnerability is critical
```

### Public Disclosure Format

If you must disclose:

1. Publish a factual, technical description.
2. Include the full timeline of your disclosure attempts.
3. Redact or generalise any information that would enable immediate harm
   (specific API keys, active credentials, etc.).
4. State the current status: "Unresolved as of [DATE]."
5. Choose a responsible publication venue: your own blog,
   FullDisclosure mailing list, or HackerOne public disclosure.

---

## Part 5 — Platform-Specific Disclosure Mechanics

### HackerOne Disclosure

```
1. After your report is resolved: click "Request disclosure"
2. Disclosure types:
   - Full: researcher name, full report text, vendor reply visible
   - Limited: reporter anonymised
   - No disclosure: remains private forever
3. Programme must approve — they can accept, modify, or decline
4. Most programmes agree to disclosure 30–90 days after fix
```

### Disclosure Without Platform (CVE Route)

If the vulnerability is in open-source software or a widely-used product:

```
1. Request a CVE from MITRE: https://cveform.mitre.org/
   (Provide: product name, version, vulnerability description, impact)
2. MITRE assigns a CVE ID (e.g., CVE-2024-XXXXX)
3. Coordinate fix with the vendor
4. Publish advisory on: your blog, GitHub Security Advisories,
   Full Disclosure list, NVD (via MITRE)
```

A CVE on your public profile is significant credibility. Prioritise
getting CVEs for vulnerabilities in software that affects many users.

---

## Key Takeaways

1. **90 days is the floor, not the ceiling.** If a company is actively
   working on a fix and communicating, extend the timeline. Reasonable
   extensions for complex fixes are standard practice. What is not standard
   is extending indefinitely for a company that never responds.
2. **Your disclosure leverage is real, but use it carefully.** Threatening
   public disclosure in the first email is aggressive and unprofessional.
   It is appropriate in the escalation phase — after 60+ days of no engagement.
3. **Document every communication.** If the situation ever becomes legal,
   your documentation is your defence. Timestamps, receipts, attempts at
   escalation — keep all of it.
4. **Silent fixes happen.** A company may fix your bug without telling you,
   without paying you, and without crediting you. This is legally questionable
   but happens. Always verify the vulnerability is still present before
   extending the timeline.
5. **Coordinated disclosure protects users, not companies.** The point is
   to give the organisation time to protect its users — not to protect the
   company's reputation indefinitely. If users are at risk and the company
   is unresponsive, disclosure becomes a moral obligation.

---

## Exercises

1. Research three publicly disclosed reports on HackerOne Hacktivity.
   For each: (a) How long was the disclosure timeline from submission
   to public disclosure? (b) Was the researcher's name disclosed or
   anonymised? (c) Was the full report disclosed or a summary?

2. Write a professional follow-up email for this scenario: You submitted
   a P1 SQLi report 14 days ago. No response. The programme SLA says
   "first response within 7 days." Draft the follow-up.

3. Research CERT/CC's coordinated disclosure process. What are their
   criteria for accepting a case? How do they handle an unresponsive vendor?

4. Find one example of a "full disclosure" (uncoordinated, public drop)
   from the past 5 years. Assess: Was the researcher's decision justified?
   What was the outcome for the users, the company, and the researcher?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q269.1, Q269.2 …).
> Follow-up questions use hierarchical numbering (Q269.1.1, Q269.1.2 …).

---

## Navigation

← Previous: [Day 268 — Tracking Findings and Notes](DAY-0268-Tracking-Findings-and-Notes.md)
→ Next: [Day 270 — Bug Bounty Legal and Ethics](DAY-0270-Bug-Bounty-Legal-and-Ethics.md)
