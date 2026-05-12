---
title: "Career Path Planning — Red Team, Malware Analysis, Vulnerability Research, AppSec"
tags: [career, specialization, red-team, malware-analysis, vulnerability-research, appsec,
  module-12-postghost]
module: 12-PostGhostLevel
day: 731
prerequisites:
  - Day 730 — Ghost Level Competency Gate
related_topics:
  - Day 732 — Building Your Public Profile
  - Day 734 — Certification Strategy
---

# Day 731 — Career Path Planning: Choosing Your Specialization

> "You can do a little of everything for the rest of your career and be mediocre at
> all of it. Or you can pick one domain, go deeper than almost anyone alive, and be
> the person organisations call when they have a problem no one else can solve.
> Both are valid choices. But you need to make the choice deliberately — not by
> accident."
>
> — Ghost

---

## Goals

Map your two years of training against four major security career paths. Conduct an
honest skills audit. Select a primary specialization. Write a one-page career plan
with a 12-month horizon.

**Prerequisites:** Day 730 (passed).
**Estimated study time:** 3 hours (reflection-heavy — do not rush).

---

## 1 — The Four Paths

### 1.1 Red Team Specialist

```
WHAT YOU DO:
  Simulate advanced threat actors in authorized engagements. Full kill chain:
  recon → initial access → lateral movement → objective. Report to CISO.

KEY SKILLS:
  AD exploitation (BloodHound, ADCS, Kerberos) ✔ Days 499–547
  C2 infrastructure + evasion                  ✔ Days 492–519
  Custom payload development                   ✔ Days 496, 542
  Phishing + social engineering                ✔ Days 504–505
  Report writing for executives                ✔ Day 510, 549

DAILY WORK:
  Pre-engagement: ROE review, infrastructure setup, OPSEC plan
  Engagement: 2–4 week phased attack simulation
  Post: detailed narrative report + debrief with client

CAREER TRAJECTORY:
  Red Team Consultant → Senior Red Team Lead → Red Team Director
  HackerOne/Bugcrowd freelance ←→ Staff red teamer at large org

COMPENSATION RANGE (2025 USD):
  Mid-level: $130K–$160K
  Senior: $160K–$220K
  Elite / boutique firm: $250K+

ORGANISATIONS HIRING:
  Mandiant, CrowdStrike, NCC Group, Bishop Fox, SpecterOps,
  Rapid7, large bank in-house red teams
```

### 1.2 Malware Analyst / Threat Intelligence

```
WHAT YOU DO:
  Reverse engineer malware samples. Extract IOCs, TTPs, C2 indicators.
  Write YARA and Sigma rules. Brief threat intelligence reports. Hunt
  for threat actor infrastructure. Support incident response.

KEY SKILLS:
  Static + dynamic malware analysis              ✔ Days 611–650
  Volatility memory forensics                    ✔ Days 641–645
  YARA rule engineering                          ✔ Days 690, 690
  Malware family attribution (APT patterns)      ✔ Days 636–640
  MITRE ATT&CK TTP mapping                       ✔ throughout
  Reverse engineering packers / obfuscation      ✔ Days 451–455

DAILY WORK:
  Sample triage queue: 5–20 samples per day
  Deep-dive: one APT campaign per week
  Intel production: threat briefs, hunting queries, YARA rules
  IR support: on-call for active incidents

CAREER TRAJECTORY:
  Malware Analyst → Senior TI Analyst → TI Lead / Researcher
  Eventually: Threat Intelligence Manager, APT researcher at vendor

COMPENSATION RANGE:
  Mid-level: $120K–$150K
  Senior: $150K–$200K
  Vendor researcher (CrowdStrike, Mandiant): $180K–$240K
```

### 1.3 Vulnerability Researcher

```
WHAT YOU DO:
  Find unknown vulnerabilities in software, hardware, or protocols.
  Write proof-of-concept code. Report responsibly (or publish CVEs).
  Build fuzzing pipelines. Audit source code.

KEY SKILLS:
  Source code auditing                           ✔ Days 651–652
  AFL++ / libFuzzer fuzzing                      ✔ Days 653–655, 686, 691
  CodeQL / Semgrep SAST                          ✔ Days 660, 687
  Binary exploitation (stack, heap, kernel)      ✔ Days 366–420
  Reverse engineering patch diffs                ✔ Days 456–457
  Security advisory writing                      ✔ Day 659

DAILY WORK:
  Audit a codebase for 2–6 hours
  Run fuzzing campaign overnight
  Reproduce CVEs to build 1-day tooling
  Submit bug reports to vendors

CAREER TRAJECTORY:
  VR Engineer → Senior Vulnerability Researcher → Principal Researcher
  Freelance: bug bounty + CVE submissions

COMPENSATION RANGE:
  Mid-level: $150K–$180K
  Senior: $180K–$250K
  Principal researcher: $250K–$350K+
  Bug bounty top earner: $500K–$2M+ (annual, rare)
```

### 1.4 Application Security Engineer (AppSec)

```
WHAT YOU DO:
  Embed in a product engineering organization. Conduct security code
  reviews. Run threat models. Design secure architecture. Build security
  tooling for developers. Own the SDLC security programme.

KEY SKILLS:
  Web exploitation (all classes)                 ✔ Days 76–165
  API security                                   ✔ Days 146–159
  Threat modelling (STRIDE, PASTA)               ✔ Module B-08 reference
  Secure design review                           ✔ Day 740 lab
  SAST / DAST integration in CI/CD               ✔ Day 660
  Developer-facing communication                 (build this skill now)

DAILY WORK:
  Code review PRs for security issues
  Threat model new features before they ship
  Run penetration tests on pre-production releases
  Champion security culture across engineering org

CAREER TRAJECTORY:
  AppSec Engineer → Senior AppSec → Staff AppSec → CISO path
  Or: product security at FAANG ($350K+)

COMPENSATION RANGE:
  Mid-level: $140K–$180K
  Senior: $180K–$250K
  Staff/Principal at FAANG: $300K–$500K+
```

---

## 2 — Skills Audit

Score yourself honestly from 1 to 5 on each dimension:

```
SKILLS AUDIT — Post-Ghost-Level

SCORING: 1 = cannot do it  2 = need help  3 = can do it solo
         4 = strong, can teach  5 = near-expert

OFFENSIVE / RED TEAM
  Active Directory full kill chain         ___/5
  C2 infrastructure setup + OPSEC         ___/5
  AV/EDR evasion (custom payloads)        ___/5
  Cloud (AWS/Azure) attack chains         ___/5
  Web app full attack chain               ___/5

MALWARE / INTEL
  Static PE analysis                      ___/5
  Dynamic analysis + sandbox              ___/5
  .NET / Java decompilation               ___/5
  Memory forensics (Volatility)           ___/5
  YARA rule engineering                   ___/5
  APT TTP attribution                     ___/5

VULNERABILITY RESEARCH
  C source code audit (buffer, arith)     ___/5
  AFL++ fuzzing campaign                  ___/5
  Crash triage + PoC development          ___/5
  Heap exploitation (tcache, FSOP)        ___/5
  Kernel vulnerability research           ___/5
  Security advisory writing               ___/5

APPSEC / DETECTION
  Web exploitation (all OWASP)            ___/5
  API security assessment                 ___/5
  Sigma rule writing                      ___/5
  Detection logic for real TTPs           ___/5
  Threat modelling                        ___/5
  Developer-facing communication          ___/5

TOTALS:
  Red Team path score:   ___/25
  Malware/Intel score:   ___/30
  VulnResearch score:    ___/30
  AppSec/Blue score:     ___/25
```

---

## 3 — Choosing Your Path

Ghost's framework for the decision:

```
DECISION FRAMEWORK

Step 1: Highest score (from audit above) → your strongest natural fit

Step 2: Ask "What energizes me?" Choose one:
  [ ] I want to break into organisations and see if I can stay hidden
  [ ] I want to stare at malware until I understand exactly what it does
  [ ] I want to find bugs in software before anyone else does
  [ ] I want to make product engineers write secure code

Step 3: Ask "What is the market need in my geography?"
  Use LinkedIn, jobs.lever.co, remoteok.com
  Search: "red team", "malware analyst", "vulnerability researcher", "appsec"
  Filter by your target location or "remote"
  Note the volume and salary ranges

Step 4: Overlay Steps 1–3
  Where your skills, passion, and market intersect = your primary path

Step 5: Name it
  Write one sentence: "I am becoming a [role] who specialises in [domain]."
  Example: "I am becoming a vulnerability researcher specialising in
  memory safety bugs in network-facing C libraries."
```

---

## 4 — 12-Month Career Plan Template

```
MY CAREER PLAN — [Date]

PRIMARY PATH: ___________________________________________________
SPECIALIZATION: ________________________________________________
TARGET ROLE: ___________________________________________________
TARGET ORGANIZATION(S): ________________________________________

CURRENT STRONGEST AREA: ________________________________________
CURRENT BIGGEST GAP: ___________________________________________

90-DAY GOALS:
  1. ____________________________________________________________
  2. ____________________________________________________________
  3. ____________________________________________________________

6-MONTH GOALS:
  1. ____________________________________________________________
  2. ____________________________________________________________

12-MONTH GOAL:
  _______________________________________________________________

MEASURABLE MILESTONES:
  Month 1: ______________________________________________________
  Month 3: ______________________________________________________
  Month 6: ______________________________________________________
  Month 12: _____________________________________________________

PUBLIC PROFILE TARGET (Day 732):
  Blog: _________________________________________________________
  GitHub: _______________________________________________________
  CVE or write-up: ______________________________________________

CERTIFICATIONS PLANNED (Day 734):
  Priority 1: ___________________________________________________
  Priority 2: ___________________________________________________
```

---

## 5 — Ghost's Opinionated Guidance

```
ON SPECIALIZATION:
  The generalist who knows "a bit of everything" is hired for junior roles
  and stays there. The specialist who can go three layers deeper than anyone
  else on one topic is hired for senior roles and gets called for the hard
  problems. Pick a lane.

ON TIMING:
  You do not need to pick permanently. You need to pick for the next 18
  months. After 18 months of focused work, you will have enough depth to
  make a more informed second decision.

ON COMPENSATION:
  Bug bounty and freelance VR have the highest ceiling but are nonlinear —
  you can earn $0 or $500K in the same year. Salaried red team and AppSec
  are more predictable. Do not choose based on ceiling; choose based on
  what you can sustain for 10 years.

ON IMPOSTER SYNDROME:
  Every person who has reached Ghost Level feels unqualified for what comes
  next. That feeling is accurate. You are stepping into work you have never
  done professionally. The answer is not to wait until you feel ready.
  The answer is to start and iterate.
```

---

## Key Takeaways

1. **There are four main career paths; you need to commit to one primary for
   the next 18 months.** Specialization is not limitation — it is positioning.
2. **Your skills audit is the most honest data you have.** Do not let ambition
   override it. A low score in a domain is a development plan, not a door
   closed.
3. **The decision is reversible.** Security professionals routinely move from
   red team to malware analysis, or from VR to AppSec. You are not locked in.
4. **Write the plan down.** A career plan in your head is a wish. A career plan
   on paper with milestones is a commitment.

---

## Exercises

1. Complete the full skills audit matrix above. Do not skip any row.
2. Fill in the 12-month career plan template.
3. Validate your chosen path against three job listings in your target market.
   Do the requirements match your training? Identify the gaps.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q731.1, Q731.2 …).

---

## Navigation

← Previous: [Day 730 — Ghost Level Competency Gate](../11-GhostLevel/DAY-0730-Ghost-Level-Competency-Gate.md)
→ Next: [Day 732 — Building Your Public Profile](DAY-0732-Building-Public-Profile.md)
