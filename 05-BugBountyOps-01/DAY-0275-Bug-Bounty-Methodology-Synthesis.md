---
title: "Bug Bounty Methodology Synthesis — End-to-End Personal Methodology Document"
tags: [methodology, synthesis, bug-bounty, workflow, end-to-end, personal-methodology,
       recon, exploitation, reporting, operations, checklists]
module: 05-BugBountyOps-01
day: 275
related_topics:
  - All Days 261–274
  - Bug Bounty Methodology (Day 072)
  - Vulnerability Chaining (Day 139)
  - Bug Bounty Reporting (Days 161–165)
  - Live Programme Practice (Days 276–289)
---

# Day 275 — Bug Bounty Methodology Synthesis

> "A methodology is not a checklist. A checklist is the shadow a methodology
> casts. The methodology is the understanding of *why* each step exists. When
> you know why, you adapt. When you only know what, you get stuck the moment
> the target does not behave as expected. Today you build yours — not mine.
> A methodology that is not yours will fail you when it matters."
>
> — Ghost

---

## Goals

By the end of today's session you will have:

1. Produced a complete, written, personal bug bounty methodology document.
2. Mapped every phase from programme selection to report submission.
3. Integrated your recon pipeline, tool stack, and technique priorities.
4. Defined your execution cadence and programme rotation strategy.
5. Created a reference you will use starting on Day 276.

**Time budget:** 5–6 hours (this is a writing and synthesis day).

---

## Prerequisites

Everything from Days 261–274.

---

## Part 1 — The Methodology Template

Write your personal methodology below. This is your Day 276+ operational guide.
The structure is given; the content must come from your skills, tools, and
decisions. Do not copy this template verbatim — adapt it.

---

### Phase 0 — Programme Selection

**Goal:** Choose the highest-signal-to-noise target for the current session.

Criteria I use to select a programme:
```
1. ___
2. ___
3. ___
```

How I check for new programme launches:
```
___
```

My current programme allocation:
```
Primary (60% effort):   [Programme name]
Secondary (30% effort): [Programme name]
VDP/Exploration (10%):  [Programme name]
```

Rotation trigger: I rotate a programme when ___

---

### Phase 1 — Policy and Scope Analysis

**Goal:** Define exactly what I can and cannot test before touching the target.

Checklist:
```
[ ] Read full policy (all 8 sections)
[ ] Build explicit in-scope list
[ ] Build explicit OOS list
[ ] Note excluded vulnerability classes
[ ] Note testing constraints (rate limits, no social engineering, etc.)
[ ] Assess safe harbour quality
[ ] Define 3 OOS edge cases for this target and how I will handle them
```

My OOS decision rule: When I am unsure if something is in scope, I ___

---

### Phase 2 — Recon

**Goal:** Enumerate the full attack surface before exploiting any of it.

**Passive Recon (no packets to target):**
```bash
# My passive recon commands (fill in):
subfinder -d $TARGET -silent -o subs.txt
# ...
```

**Active Recon (packets to target — only after scope confirmation):**
```bash
# My active recon commands:
cat subs.txt | httpx -silent -status-code -tech-detect -o live.txt
# ...
```

**Endpoint and Parameter Discovery:**
```bash
# My endpoint fuzzing workflow:
# 1. Custom wordlist build (JS mining + katana + historical)
# 2. ffuf with tuned filters
# 3. Param Miner in background on interesting endpoints
```

**Recon deliverable:** A written target profile doc (template: Day 268)
covering subdomains, technology stack, endpoints of interest, auth flow.

---

### Phase 3 — Systematic Testing

**Goal:** Apply my highest-value technique set against the enumerated surface.

My testing priority order (most → least likely to produce a finding):

```
1. Authentication and session management
   - Account registration / login flow anomalies
   - JWT structure and algorithm
   - OAuth redirect_uri handling
   - Password reset flow

2. Access control (IDOR / BOLA / privilege escalation)
   - Sequential IDs on any resource endpoint
   - Role parameters in POST bodies
   - Admin-only paths accessible to low-priv users
   - Autorize running throughout browsing session

3. Server-side features that fetch external URLs
   - SSRF via webhook, image URL, PDF generator, import
   - AWS metadata via SSRF
   - Internal port scan via blind SSRF

4. Input injection
   - SQLi on all search / filter parameters
   - SSTI on templated fields
   - XXE on any XML input
   - Command injection on any system-interacting feature

5. File handling
   - File upload bypass
   - Path traversal on file download

6. Chaining and business logic
   - Map all P3s found — can any two chain?
   - Workflow bypass (skip payment, bypass verification)
   - Race conditions on limit-enforcing endpoints
```

**Per-session time management:**
```
0:00–0:30   Refresh recon (any new subdomains since last session?)
0:30–3:00   Focused testing on my priority technique
3:00–4:00   Chain analysis — connect current session findings to previous
4:00–4:30   Document all leads and draft promising findings
```

---

### Phase 4 — Finding Documentation

**Goal:** Capture all evidence before closing Burp.

Before ending any session:
```
[ ] Export Burp project file
[ ] Export Autorize results
[ ] Screenshot all interesting requests/responses
[ ] Save curl commands reproducing every finding
[ ] Write a one-paragraph lead note for anything not yet a full finding
```

Finding log template: Day 268 — FIND-NNN format

---

### Phase 5 — Report Writing

**Goal:** Transform documented findings into reports that get accepted
and paid at the correct severity.

My report template sections:
```
1. Title: [Vulnerability class] — [Location] — [Impact]
2. Severity: [Critical/High/Medium/Low] + CVSS 3.1 vector + score
3. Summary: 2–3 sentences
4. Impact: business impact with scale and regulatory dimension
5. Steps to Reproduce: exact curl commands, numbered
6. Evidence: screenshots with annotations
7. Root Cause: one sentence
8. Remediation: specific code-level or config change
```

My severity calibration check:
```
Before submitting, I answer:
  - What can an attacker do with this?
  - Who is affected? (one user / all users / unauthenticated)
  - What data is exposed? (none / low-value / PII / financial)
  - Is authentication required to exploit?
  - Can this be chained with anything else on this target?
```

---

### Phase 6 — Post-Submission

**Goal:** Maintain tracking, engage with triage, update performance metrics.

```
[ ] Log submission in finding tracker (programme, date, severity, status)
[ ] Set reminder for follow-up if no response in 7 days
[ ] Update programme time log
[ ] After resolution: request disclosure
[ ] After disclosure: publish write-up
[ ] Monthly: update earnings metrics and programme allocation
```

---

## Part 2 — Technique Prioritisation by Target Type

Build this based on your actual skill assessments from Days 261–274:

| Target type | My first 3 checks |
|---|---|
| SaaS with OAuth | 1. ___ 2. ___ 3. ___ |
| REST API | 1. ___ 2. ___ 3. ___ |
| E-commerce | 1. ___ 2. ___ 3. ___ |
| Mobile app with API | 1. ___ 2. ___ 3. ___ |
| Government/public sector | 1. ___ 2. ___ 3. ___ |

---

## Part 3 — Tool Stack Reference

Fill in your actual configured tool setup:

```
Subdomain enumeration: subfinder, amass, crt.sh
DNS resolution:        dnsx
Live host validation:  httpx
Crawling:              katana
Directory fuzzing:     ffuf
Parameter discovery:   Param Miner (Burp), arjun
Vulnerability scan:    Nuclei (templates: ...)
Proxy:                 Burp Suite (extensions: Autorize, Active Scan++, J2EEScan)
Notification:          notify → Slack/Discord/Telegram
Note-taking:           Obsidian / Notion
```

---

## Part 4 — The Decision Points

For each of these situations, write your decision rule:

| Situation | My decision |
|---|---|
| Found something that looks OOS | ___ |
| Found a P4 that might chain | ___ |
| Duplicate on my last 3 submissions | ___ |
| No findings after 20 hours | ___ |
| Programme does not respond in 7 days | ___ |
| Triage downgrades my P2 to P3 | ___ |
| Found real user data accidentally | ___ |

---

## Key Takeaways

1. **A written methodology is a forcing function.** Writing forces clarity.
   If you cannot write down your decision rule for a situation, you do not
   actually have a rule — you have a vague instinct that will fail under pressure.
2. **Your methodology is a living document.** Update it after every 10 findings.
   What worked? What wasted time? What would you add? A methodology that
   never changes is a methodology that stopped learning.
3. **Days 276–289 are the test.** This document is your guide. Apply it on a
   real programme. Document every place it breaks down or needed adaptation.
   Those are the places to improve it.
4. **Methodology beats technique.** A researcher with a consistent, well-executed
   methodology finds more bugs over 6 months than a researcher with brilliant
   technique but no systematic approach.
5. **The best methodology is one you actually follow.** Complexity for its own
   sake creates friction. If you would skip a step under time pressure, the
   step is either wrong or needs to be made simpler.

---

## Exercises

1. Complete every blank section in your personal methodology document.
   Do not leave anything empty — make a decision, even if it is provisional.

2. Dry-run your methodology against the gate lab from Day 165 (reset it).
   Time yourself. Where did the methodology help? Where did it slow you down?
   Where did you deviate from it?

3. Have a trusted peer (or an AI) red-team your methodology: identify every
   decision point that is ambiguous or missing and every technique priority
   that you cannot justify with evidence from your actual skill set.

4. Compare your methodology to one published by a top researcher
   (Jason Haddix's methodology is public). What are the 3 biggest
   differences? Which differences are genuine strategic choices and which
   are gaps you should close?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q275.1, Q275.2 …).
> Follow-up questions use hierarchical numbering (Q275.1.1, Q275.1.2 …).

---

## Navigation

← Previous: [Day 274 — Community and Resources](DAY-0274-Community-and-Resources.md)
→ Next: [Day 276 — Live Programme Practice Day 1](DAY-0276-Live-Programme-Practice-Day-01.md)
