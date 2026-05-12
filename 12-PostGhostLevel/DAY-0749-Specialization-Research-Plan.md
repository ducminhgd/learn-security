---
title: "30-Day Specialization Research Plan — Choosing Your Domain, Lab Plan, Publication Target"
tags: [specialization, research-plan, 30-day-plan, lab, publication, module-12-postghost]
module: 12-PostGhostLevel
day: 749
prerequisites:
  - Day 731 — Career Path Planning
  - Day 748 — Methodology Crystallisation
related_topics:
  - Day 750 — Programme Complete
---

# Day 749 — 30-Day Specialization Research Plan

> "You have 750 days of training behind you. That is not the end — it is the
> start of the actual work. The programme gave you breadth and depth across a
> wide surface area. Now you go narrow. Extremely narrow. Pick one domain.
> For the next 30 days, that domain is all you do. What you build in those
> 30 days will set the trajectory of your next year."
>
> — Ghost

---

## Goals

Finalize your specialization choice based on the Day 731 career plan. Build a
complete, specific 30-day research plan for your chosen domain. Identify a
concrete publication target — a write-up, advisory, or talk proposal — for
the 30-day window. Commit to the plan.

**Prerequisites:** Days 731, 748.
**Estimated study time:** 3 hours (planning-intensive).

---

## 1 — Confirming Your Specialization

```
FINAL SPECIALIZATION DECISION FRAMEWORK

From Day 731, you have a primary path. Now sharpen it:

NOT: "Vulnerability Research"
BUT: "Memory safety vulnerabilities in C network parsers, targeted via AFL++
      and manual taint analysis, with a focus on IoT firmware and embedded systems."

NOT: "Red Team"
BUT: "Active Directory attack path exploitation, specializing in ADCS abuse
      (ESC1-ESC8) and cross-forest trust attacks in enterprise environments."

NOT: "Malware Analysis"
BUT: "RAT/infostealer analysis with a focus on .NET and Go-based malware,
      specializing in config extraction, C2 protocol analysis, and detection engineering."

The narrower your specialization statement, the more targeted your next 30 days.

EXERCISE:
  Write your specialization statement in one sentence.
  It must contain:
  - The technical domain (vuln research / red team / malware)
  - The specific techniques or bug classes
  - The target environment or system type
  - Your intended contribution (find bugs / build detections / produce reports)
```

---

## 2 — The 30-Day Plan Template

```
MY 30-DAY SPECIALIZATION RESEARCH PLAN

Specialization: ___________________________________________________
Primary domain: ___________________________________________________
Target output:  ___________________________________________________
  (CVE report / blog post / CTF write-up / tool release / conference CFP)

ENVIRONMENT SETUP (Days 1–3)
  Lab configuration needed: ________________________________________
  Tools to install/update: ________________________________________
  Reference reading (3 papers/posts max): __________________________
  __________________________________________________________________

WEEK 1: Foundation and Scope (Days 1–7)
  [ ] Day 1–2: Read 2–3 foundational resources on the specialization
  [ ] Day 3–4: Set up the specific lab environment
  [ ] Day 5–6: Reproduce one documented example (CVE, CTF, paper demo)
  [ ] Day 7:   Write a brief internal report: "Here is what I understand
               and what I do not yet understand"

  Week 1 deliverable: _______________________________________________

WEEK 2: Deep Execution (Days 8–14)
  [ ] Day 8–10: Begin original research/practice (audit, engagement, analysis)
  [ ] Day 11–12: Document findings (preliminary notes only)
  [ ] Day 13–14: Identify one concrete finding, candidate, or interesting result

  Week 2 deliverable: _______________________________________________

WEEK 3: Depth and Iteration (Days 15–21)
  [ ] Day 15–17: Go deeper on the most interesting result from Week 2
  [ ] Day 18–19: PoC development or detection validation
  [ ] Day 20–21: Document the finding in full (Day 659/743 format)

  Week 3 deliverable: _______________________________________________

WEEK 4: Output and Publication (Days 22–30)
  [ ] Day 22–24: Write the publication (blog post, advisory, CFP abstract)
  [ ] Day 25–27: Review, edit, get one external technical review
  [ ] Day 28:    Publish or submit
  [ ] Day 29–30: Retrospective and 30-day plan for the next cycle

  Week 4 deliverable: _______________________________________________

PUBLICATION TARGET:
  Type:     [ ] Blog post  [ ] CVE report  [ ] CFP abstract  [ ] Tool release
  Platform: ___________________________________________________________
  Target date: ________________________________________________________
```

---

## 3 — Domain-Specific 30-Day Plans

Choose your domain and adapt:

### 3.1 Vulnerability Research (Memory Safety)

```
30-DAY VR PLAN

Week 1:
  Target: select 1 open-source C/C++ parser not yet on OSS-Fuzz
  Setup: ASan build + AFL++ campaign + CodeQL query
  Read: James Forshaw "Project Zero Blog" series on your bug class
  Reproduce: 1 documented CVE in a related project

Week 2:
  Run AFL++ campaign continuously (background)
  Begin manual source audit (Day 666 campaign methodology)
  Document all candidates in FINDING log

Week 3:
  Deep analysis of strongest candidate
  PoC development
  Write advisory draft (Day 659 format)

Week 4:
  Complete advisory
  Submit to vendor (if finding is confirmed)
  Publish write-up covering the methodology (even if no bug found)

Output target: one security advisory OR one methodology blog post
```

### 3.2 Red Team (Active Directory)

```
30-DAY RED TEAM PLAN

Week 1:
  Target: complete all ADCS escalation paths (ESC1–ESC8) in a lab
  Setup: lab domain controller + CA server (vulnerable by design)
  Read: Certifried paper, ESC8 writeup, Specterops AD research

Week 2:
  Practice each ESC path manually (no tooling automation yet)
  Document the exact conditions required for each path
  Practise with two tooling approaches per path (Certipy + manual)

Week 3:
  Build a personal AD attack flow reference card
  Run a timed full engagement: external → DA via ADCS in under 4 hours
  Document time per phase, bottlenecks

Week 4:
  Write up the ADCS kill chain as a blog post (your personal reference + community value)
  Submit one CFP abstract to a regional BSides using this as the topic

Output target: blog post + BSides CFP draft
```

### 3.3 Malware Analysis (RAT Family)

```
30-DAY MALWARE PLAN

Week 1:
  Target: analyse 3 samples from the same RAT family (AsyncRAT / NjRat / Quasar)
  Setup: FlareVM + REMnux + MISP event for the family
  Read: existing published analyses of the family

Week 2:
  Deep analysis of one sample per day
  Extract: config, C2 protocol, persistence, evasion techniques
  Write malware report in Day 619 format for each sample

Week 3:
  Build a YARA rule that detects all 3 samples
  Build a Sigma rule that detects the persistence mechanism
  Test both against 20 benign binaries (false positive check)

Week 4:
  Publish a detailed blog post: "A Practitioner's Guide to AsyncRAT Config Extraction"
  Publish YARA rules to GitHub with documentation
  Submit YARA rules to YARAhub or Malpedia

Output target: blog post + YARA rule set on GitHub
```

---

## 4 — Accountability Framework

```
MAKING THE PLAN STICK

Public commitment:
  Post the plan (at a high level) on Twitter/X or your blog.
  "For the next 30 days I am doing [domain]. Here is my target output."
  Public commitments are 3× more likely to be completed (accountability effect).

Weekly check-in (with yourself or a peer):
  "Did I achieve this week's deliverable? Yes/No.
   If No: what blocked me? What do I do differently next week?"

The only acceptable reason to miss a week's deliverable:
  Not: "I was busy" — everyone is busy
  Not: "It was harder than I thought" — that is the point
  Acceptable: unexpected life event that genuinely required full attention

Retrospective format (Day 29–30):
  What did I find/produce?
  What did I expect vs. what actually happened?
  What one thing would I do differently in the next 30-day cycle?
  What is my next 30-day plan?

The 30-day cycle repeats indefinitely.
This is how you become an expert over 24 months, not 5 years.
```

---

## Key Takeaways

1. **Narrow your specialization statement to one specific sentence.** "Vulnerability
   research" is not a plan. "Memory safety bugs in Go network servers via AFL++"
   is a plan.
2. **Week 4's publication target is non-negotiable.** A research cycle without
   a published output is a cycle where the knowledge stays inside your head.
   The publication is the forcing function for depth.
3. **The 30-day cycle is the correct cadence.** Long enough to produce something
   real; short enough to course-correct if the direction was wrong.
4. **Public commitments work.** Post the plan. The accountability to the
   community that watched you get here is real motivation.

---

## Exercises

1. Write your complete 30-day plan using the template above.
2. Set a calendar reminder for each week's deliverable check-in.
3. Post the plan (high-level, no sensitive details) publicly.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q749.1, Q749.2 …).

---

## Navigation

← Previous: [Day 748 — Methodology Crystallisation](DAY-0748-Methodology-Crystallisation.md)
→ Next: [Day 750 — Programme Complete](DAY-0750-Programme-Complete.md)
