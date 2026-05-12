---
title: "Year 2 Review and Synthesis — Everything You Built, Assembled"
tags: [review, synthesis, year-2, competency, binary-exploitation, reversing,
  red-team, vulnerability-research, malware-analysis, module-11-ghost-level]
module: 11-GhostLevel
day: 705
prerequisites:
  - Day 700 — Module 10 Competency Check (Gate)
  - All Year 2 modules (Days 366–700)
related_topics:
  - Day 706 — Ghost Level Preparation
  - Day 730 — Ghost Level Competency Gate
---

# Day 705 — Year 2 Review and Synthesis

> "In Year 1 you became a hacker. In Year 2 you became a researcher. You
> can find bugs in code that no one has looked at before. You can take
> malware apart and put its indicators into production detection rules. You
> can run a red team engagement from C2 infrastructure through AD
> exploitation to persistence. Today you take stock of all of it.
> Not to celebrate — to understand how it fits together. The Ghost Level
> engagement requires everything simultaneously."
>
> — Ghost

---

## Goals

Review the complete Year 2 curriculum as a unified skill map. Understand how
Year 2 modules interconnect and compound. Identify your strongest and weakest
modules. Build a personal skill portfolio for the Ghost Level engagement.

**Prerequisites:** Year 2 complete (Days 366–700).
**Estimated study time:** 3–4 hours.

---

## 1 — Year 2 Module Map

```
YEAR 2 CURRICULUM — MODULE SUMMARY

Module 06 — Binary Exploitation (Days 366–430)
  Stack exploitation:    buffer overflows, shellcode, ROP chains
  Heap exploitation:     tcache, fastbin, house-of-X techniques
  Kernel intro:          kernel debugging, KASAN, simple LKM exploit
  Gate: Day 430          Write a working ROP chain for 64-bit ELF with ASLR

Module 07 — Reverse Engineering (Days 431–490)
  Static RE:             Ghidra, IDA Free, function reconstruction
  Dynamic RE:            GDB + pwndbg, breakpoints, watchpoints
  Packers:               UPX, custom packers, entropy analysis
  Patch diff:            BinDiff, source diff, vulnerability localisation
  Gate: Day 490          Reverse a crackme + analyse a packed binary

Module 08 — Red Team Operations (Days 491–560)
  C2 + evasion:          Cobalt Strike/Metasploit, EDR bypass techniques
  Active Directory:      Kerberoasting, AS-REP roasting, DCSync, pass-the-hash
  Kill chain:            recon → initial access → lateral movement → exfil
  Purple team:           ATT&CK emulation, blue team collaboration
  Gate: N/A (integrated into Kill Chain exercise)

Module 09 — Cryptographic Attacks (Days 561–610)
  Classical:             CBC padding oracle, ECB mode attacks
  Advanced:              Timing attacks, length extension, curve weaknesses
  Applied:               TLS attack surface, JWT attacks, custom crypto audit
  Gate: N/A (assessed via module exercises)

Module 10 — Malware Analysis + Vulnerability Research (Days 611–700)
  Malware analysis:      static, dynamic, memory forensics, family analysis
  Vulnerability research: source audit, fuzzing, bug classes, PoC, advisory
  Gate: Day 700          Malware report + vulnerability finding + oral defence
```

---

## 2 — Skill Intersection Map

The Ghost Level engagement requires cross-module skill application. This
diagram shows which modules feed into each engagement phase:

```
GHOST LEVEL ENGAGEMENT — SKILL REQUIREMENTS

Phase 1: Target Identification
  ← Module 08 (Red Team): OSINT, attack surface mapping
  ← Module 10 (VulnResearch): target selection criteria

Phase 2: Initial Vulnerability Discovery
  ← Module 10 (VulnResearch): source audit, fuzzing, manual taint
  ← Module 07 (RE): binary analysis if no source
  ← Module 09 (Crypto): crypto audit of network protocol

Phase 3: Exploit Development
  ← Module 06 (BinExploit): stack/heap exploitation techniques
  ← Module 07 (RE): gadget finding, binary patching
  ← Module 06 + 07 combined: ROP chain construction

Phase 4: Lateral Movement and Impact
  ← Module 08 (Red Team): AD techniques, C2 operations
  ← Module 10 (Malware): custom implant analysis/modification

Phase 5: Detection and Reporting
  ← Module 10 (Malware): YARA + Sigma rules for own tools
  ← Module 08 (Purple Team): ATT&CK mapping, detection engineering
  ← Module 10 (VulnResearch): advisory writing, CVSS scoring
```

---

## 3 — Personal Competency Assessment

Rate yourself honestly on each module. This is your readiness map for the
Ghost Level engagement.

```
YEAR 2 COMPETENCY RATING

Rate each skill 1–4:
  4 = Can produce gate-quality output on an unfamiliar target, under time pressure
  3 = Can produce correct output on familiar material with some effort
  2 = Understand the concept; struggle to produce under pressure
  1 = Conceptual understanding only; cannot produce independently

MODULE 06 — BINARY EXPLOITATION
  Stack exploitation (BOF, shellcode):  ___/4
  ROP chain construction (64-bit ASLR): ___/4
  Heap exploitation (tcache/fastbin):   ___/4
  pwndbg workflow:                      ___/4
  Module 06 average: ___/4

MODULE 07 — REVERSE ENGINEERING
  Ghidra: function reconstruction:      ___/4
  GDB + pwndbg: dynamic analysis:       ___/4
  Packer unpacking:                     ___/4
  Patch diffing (BinDiff/source):       ___/4
  Module 07 average: ___/4

MODULE 08 — RED TEAM
  C2 setup and evasion:                 ___/4
  AD attacks (Kerberoasting, DCSync):   ___/4
  Lateral movement TTPs:                ___/4
  ATT&CK-mapped kill chain:             ___/4
  Module 08 average: ___/4

MODULE 09 — CRYPTO ATTACKS
  CBC padding oracle:                   ___/4
  Timing attacks:                       ___/4
  JWT attacks:                          ___/4
  Length extension attack:              ___/4
  Module 09 average: ___/4

MODULE 10 — MALWARE + VULN RESEARCH
  Static malware analysis:              ___/4
  Dynamic malware analysis:             ___/4
  Memory forensics (Volatility3):       ___/4
  AFL++ fuzzing pipeline:               ___/4
  Manual taint tracking:                ___/4
  YARA rule writing:                    ___/4
  CVSS scoring + advisory:              ___/4
  Module 10 average: ___/4

OVERALL YEAR 2 AVERAGE: ___/4

THREE STRONGEST MODULES:
  1. _________________ (avg: ___/4)
  2. _________________ (avg: ___/4)
  3. _________________ (avg: ___/4)

THREE WEAKEST SKILLS ACROSS ALL MODULES:
  1. _____________________________ (___/4) — Plan: _______________
  2. _____________________________ (___/4) — Plan: _______________
  3. _____________________________ (___/4) — Plan: _______________
```

---

## 4 — The Ghost Level Target Profile

The 48-hour engagement target (Days 707–728) is designed to require a
subset of Year 2 skills simultaneously. Based on past Ghost Level exercises,
expect the target to:

```
GHOST LEVEL TARGET CHARACTERISTICS (historical)

Format: A custom lab environment containing:
  1. A network service with a binary vulnerability
     → Requires: Module 06 (exploitation) + Module 07 (RE, no source)
  2. A web application with authentication and API
     → Requires: Year 1 web skills + Module 09 (crypto/JWT)
  3. A restricted network segment reachable after exploitation
     → Requires: Module 08 (lateral movement)
  4. An unknown binary or script that requires analysis
     → Requires: Module 07 (RE) + Module 10 (malware analysis)

Deliverable: A full engagement report containing:
  - Timeline of actions
  - Vulnerability findings (advisory-format for each)
  - Evidence (screenshots, PoC inputs, crash dumps)
  - MITRE ATT&CK mapping
  - Remediation recommendations

JUDGED ON:
  - Did you find the vulnerabilities?
  - Are the findings documented at professional quality?
  - Is the methodology defensible?
  - Would you catch an investigator who asked "how did you know to look there?"
```

---

## 5 — The Ghost Level Mindset

```
GHOST LEVEL — WHAT IS DIFFERENT FROM EVERYTHING BEFORE IT

Before the Ghost Level:
  → Labs are designed so there is a "right" answer
  → Modules isolate one skill per day
  → Practice sprints tell you what bug class to look for
  → Gate criteria are specific: "find 1 confirmed vulnerability"

The Ghost Level:
  → You do not know what bug class, what technology, what protocol
  → The environment is built to be found — not to be easy
  → You have 48 hours — enough for one real researcher, not enough for shortcuts
  → No one will tell you if you are in the right place
  → The goal is not a grade — it is a result

WHAT SUCCEEDS:
  1. Systematic methodology: start with recon, build a map, prioritise surfaces
  2. Time management: 48 hours is finite; allocate time across surfaces
  3. Breadth before depth: identify ALL entry points before diving deep into one
  4. Documentation throughout: take notes as you work; the report is built from notes
  5. Cross-module synthesis: a web finding + a binary finding + lateral movement
     tells a coherent story

WHAT FAILS:
  - Spending 12 hours on one service and missing the main vulnerability
  - Not taking notes (trying to reconstruct from memory at hour 46)
  - Ignoring a service because "that was Year 1 stuff"
  - Stopping at "suspicious candidate" and not confirming it
```

---

## 6 — Resource Map for Ghost Level

```
GHOST LEVEL — QUICK REFERENCE MAP

Binary exploitation:
  Stack BOF:     Day 371–374
  ROP chain:     Day 388–390
  Heap (tcache): Day 401–408

Reverse engineering:
  Ghidra setup:  Day 432
  GDB + pwndbg:  Day 451–453
  Patch diff:    Day 461

Red team:
  C2 setup:      Day 492–495
  AD attacks:    Day 511–520
  Lateral move:  Day 523–528

Crypto attacks:
  Padding oracle: Day 563–564
  JWT attacks:    Day 577
  TLS audit:      Day 591

Malware analysis:
  Static:         Day 612–614
  Dynamic:        Day 615–616
  Volatility3:    Day 641–644

Vulnerability research:
  Audit pipeline: Day 666–670
  Bug classes:    Day 662–663, 671–674
  CVSS + advisory: Day 659, 670

Tools reference:
  GDB commands:   Day 452
  AFL++ commands: Day 653
  Volatility3:    Day 641
  Semgrep:        Day 660
  CVSS calculator: nvd.nist.gov/vuln-metrics/cvss/v3-calculator
```

---

## Key Takeaways

1. **Year 2 is a compound investment.** You can reverse a binary AND audit its
   source code AND fuzz it AND analyse malware that exploits it AND write
   detection rules for it AND emulate its firmware. No individual module gave
   you that — all of them together did.
2. **Your weakest module is your engagement bottleneck.** In the Ghost Level,
   the attacker who finds everything scores higher than the attacker who
   perfectly exploits one thing. Breadth across modules matters. Know where
   your gaps are and mitigate them before Day 707.
3. **Documentation is a first-class deliverable.** The Ghost Level is assessed
   on the report as much as on the findings. A brilliant exploit with no
   documentation is a failed gate. A solid finding with a professional advisory
   format is a passed gate.
4. **The Ghost Level is the beginning of your career, not the end of your
   training.** The 730-day programme gives you a foundation. Real security work
   — bug bounty, red team, product security, vulnerability research — is where
   that foundation becomes expertise. The Ghost Level proves you are ready to
   start building the expertise. That is what it was always for.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q705.1, Q705.2 …).

---

## Navigation

← Previous: [Day 704 — Zero-Day Mindset](DAY-0704-Zero-Day-Mindset.md)
→ Next: [Day 706 — Ghost Level Preparation](DAY-0706-Ghost-Level-Preparation.md)
