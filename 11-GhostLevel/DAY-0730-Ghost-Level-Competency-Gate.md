---
title: "Day 730 — Ghost Level Competency Gate"
tags: [ghost-level, competency-gate, final-assessment, year-2-complete,
  module-11-ghost-level]
module: 11-GhostLevel
day: 730
prerequisites:
  - Day 729 — Ghost Level Extended Day 3: Report Polish and Oral Prep
  - Full Ghost Level engagement (Days 707–729)
related_topics:
  - Day 731 — Career Path Planning (Module 12, Post-Gate)
---

# Day 730 — Ghost Level Competency Gate

> "730 days. Two years. Every module, every gate, every late night of
> debugging something that should not be this hard. It all comes down to
> this room, this report, and this conversation.
>
> I am not going to tell you what I expect from you. You already know.
> You have known since Day 1 what Ghost Level means. Now prove it."
>
> — Ghost

---

## Gate Overview

```
╔══════════════════════════════════════════════════════════════════════╗
║                GHOST LEVEL COMPETENCY GATE — DAY 730                 ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  Format: Three components, assessed sequentially                     ║
║                                                                      ║
║  Component 1: Report Review          45 minutes                      ║
║  Component 2: Live Technical Demo    30 minutes                      ║
║  Component 3: Oral Defence           30 minutes                      ║
║                                                                      ║
║  Pass criterion: All three components must achieve Acceptable or     ║
║  above. Any single Unacceptable = remediation required.              ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

## Component 1 — Report Review (45 minutes)

The assessor reads your Project SABLE report and scores it on the
following rubric. You are not present during this phase — submit the
report and wait.

```
REPORT ASSESSMENT RUBRIC

Executive Summary
  Exemplary:     Non-technical, accurate, actionable, < 300 words
  Acceptable:    Minor technical jargon; business impact stated
  Unacceptable:  Technical-only, no business context, or > 500 words
  Score: E / A / U

Findings Quality (score each finding, weight average)
  For each finding:
  Exemplary:     Root cause explained, CVSS justified, ATT&CK mapped,
                 evidence present, remediation specific and correct
  Acceptable:    Finding documented with evidence; minor gaps in CVSS or
                 remediation wording
  Unacceptable:  Finding stated without evidence, or remediation generic/wrong
  Scores:
    F-01 JWT:         E / A / U
    F-02 Stack BOF:   E / A / U
    F-03 Kerberoast:  E / A / U
    F-04 ADCS ESC1:   E / A / U
    F-05 CGI Inject:  E / A / U
    F-06 SMB Null:    E / A / U

Attack Timeline
  Exemplary:     Every major action timestamped; narrative coherent
  Acceptable:    Timeline present; minor gaps in timestamps
  Unacceptable:  Timeline absent or cannot be reconstructed

Detection and Hardening (from Day 728 addendum)
  Exemplary:     Detection rules present, technically correct, gap analysis
                 identifies tooling gaps with remediation estimates
  Acceptable:    Rules present; gap analysis partial
  Unacceptable:  No detection component

COMPONENT 1 RESULT: PASS / FAIL (all sections must be Acceptable or above)
```

---

## Component 2 — Live Technical Demo (30 minutes)

The assessor will select one finding from your report. You must:

1. Re-execute the attack in the Project SABLE environment — live, in front
   of the assessor — within 15 minutes.
2. Explain each step as you perform it: "I am running this command because…
   and the expected output is…"
3. Answer two follow-up questions from the assessor during execution.

```
LIVE DEMO ASSESSMENT

Finding assigned: _____________________________________________

Step 1: Pre-demo (2 min)
  Describe your plan before starting:
  "I will demonstrate ___________ by performing the following steps:
   1. _____ 2. _____ 3. _____"
  Assessor: Clear and accurate plan? Y / N

Step 2: Execution (15 min max)
  Execution quality:
  [ ] Correct tool choices
  [ ] Commands executed without excessive errors
  [ ] Explained rationale for each command
  [ ] Finding reproduced successfully
  Assessor: Finding reproduced? Y / N  Time taken: _____ min

Step 3: Follow-up questions (5 min)
  Q1: ___________________________________________________________
  Answer quality: Exemplary / Acceptable / Unacceptable

  Q2: ___________________________________________________________
  Answer quality: Exemplary / Acceptable / Unacceptable

COMPONENT 2 RESULT: PASS (reproduced + both questions Acceptable or above)
                    FAIL (did not reproduce OR two Unacceptable answers)
```

---

## Component 3 — Oral Defence (30 minutes)

Six questions selected from the Day 729 question bank. You have 90 seconds
per question. No notes. No references. Answer from memory.

```
ORAL DEFENCE ASSESSMENT

Q1: _______________________________________________________________
    Answer summary: ______________________________________________
    Quality: Exemplary / Acceptable / Unacceptable

Q2: _______________________________________________________________
    Answer summary: ______________________________________________
    Quality: Exemplary / Acceptable / Unacceptable

Q3: _______________________________________________________________
    Answer summary: ______________________________________________
    Quality: Exemplary / Acceptable / Unacceptable

Q4: _______________________________________________________________
    Answer summary: ______________________________________________
    Quality: Exemplary / Acceptable / Unacceptable

Q5: _______________________________________________________________
    Answer summary: ______________________________________________
    Quality: Exemplary / Acceptable / Unacceptable

Q6: _______________________________________________________________
    Answer summary: ______________________________________________
    Quality: Exemplary / Acceptable / Unacceptable

Oral results: ___ Exemplary, ___ Acceptable, ___ Unacceptable

COMPONENT 3 RESULT: PASS (≤ 1 Unacceptable)
                    FAIL (≥ 2 Unacceptable)
```

---

## Gate Result

```
╔══════════════════════════════════════════════════════════════════════╗
║                     GHOST LEVEL GATE RESULT                          ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  Component 1 (Report Review):     PASS / FAIL                        ║
║  Component 2 (Live Technical Demo):PASS / FAIL                       ║
║  Component 3 (Oral Defence):      PASS / FAIL                        ║
║                                                                      ║
║  GATE:  ██ PASS  — Ghost Level Achieved                               ║
║         ██ FAIL  — Remediation required (see below)                  ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝

IF FAILED:
  Failed component: ____________________________________________
  Specific failure: ____________________________________________
  Remediation:
    [ ] Report revision: rewrite failed sections, re-submit
    [ ] Demo repeat: re-execute with 72-hour preparation window
    [ ] Oral repeat: 1-week preparation, full question bank review
  Retry date: _________________________________________________

IF PASSED:

  Date of Ghost Level gate pass: ______________________________

  Programme complete: Days 1–730.

  "You started Day 1 not knowing how the internet actually worked.
   You finish Day 730 having found real vulnerabilities in unknown
   code, having owned a domain from a single web token, and having
   written detection rules that would catch everything you just did.

   You understand the attack because you performed it.
   You understand the defence because you built it.
   You understand what matters because you have done the work.

   That is the job. You have it now. Go do it in the real world."

                                                    — Ghost
```

---

## What Ghost Level Means

Passing the Ghost Level gate proves you can:

1. **Conduct an end-to-end engagement** — from recon through exploitation,
   lateral movement, domain compromise, and exfiltration — on an unknown
   target, without guidance.
2. **Produce professional-grade output** — a report that meets the standard
   of a commercial penetration testing firm's deliverable.
3. **Communicate technical findings** — to both technical peers and
   non-technical decision-makers, live, under pressure.
4. **Build detection** — not just break systems, but tell defenders exactly
   what to watch for and how to fix it.
5. **Operate with professional ethics** — every action taken was within
   authorised scope, documented, and disclosed responsibly.

This is not the end of your training. It is the beginning of your career.

---

## Key Takeaways

1. **The Ghost Level was designed to be hard enough that passing it means
   something.** It is a 48-hour solo engagement on an unknown target. It
   requires cross-module synthesis. It requires professional documentation.
   It requires oral reasoning under pressure. All of that is what real
   security work requires.
2. **Two years of daily practice produce compound returns.** Skills built on
   Day 50 appear on Day 730 in a completely different context. The TCP/IP
   knowledge from Day 1 is present in every network scan you run. The binary
   analysis from Day 431 is present in every firmware dump you read. The
   curriculum is a compound investment — and you have been making it daily.
3. **The programme ends. The learning does not.** Bug classes evolve. New
   techniques emerge. Defensive tooling changes. The methodology — hypothesis,
   exploit, detect, harden — is invariant. Apply it to whatever the next two
   years bring.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q730.1, Q730.2 …).

---

## Navigation

← Previous: [Day 729 — Ghost Level Extended Day 3](DAY-0729-Ghost-Level-Extended-Day3.md)
→ Next: [Day 731 — Career Path Planning](../12-PostGate/DAY-0731-Career-Path-Planning.md)
