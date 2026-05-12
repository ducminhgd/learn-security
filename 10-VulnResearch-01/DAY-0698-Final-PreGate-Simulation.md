---
title: "Final Pre-Gate Full Simulation — Day 700 Complete Dress Rehearsal"
tags: [gate-preparation, simulation, malware-analysis, vulnerability-research,
  oral-defence, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 698
prerequisites:
  - Day 685 — Module Competency Check Preparation
  - Day 696 — Targeted Practice: Malware Analysis Gap Closure
  - Day 697 — Targeted Practice: Vulnerability Research Gap Closure
related_topics:
  - Day 699 — Gate Day Eve
  - Day 700 — Module 10 Competency Check
---

# Day 698 — Final Pre-Gate Full Simulation

> "Today is not a lesson day. Today is a performance day. You run the
> full Day 700 gate format — all three components, all timings — in real
> conditions. No notes on what you have not yet tried. No looking back
> at the lessons. You either have it or you do not. Today we find out."
>
> — Ghost

---

## Goals

Run a complete, timed mock of the Day 700 competency check under real
conditions: 2.5 hours malware analysis, 3 hours vulnerability research, 30
minutes oral defence. Identify any remaining gaps. Sleep tonight knowing
exactly what Day 700 will feel like.

**Prerequisites:** Days 685, 696, 697.
**Estimated study time:** 6 hours (simulation — block full day).

---

## Pre-Simulation Checklist

Complete this before the clock starts:

```
PRE-SIM SETUP (15 minutes before start)

ENVIRONMENT:
  [ ] FlareVM or Windows sandbox VM: snapshot loaded, clean state
  [ ] REMnux or Kali VM: dynamic analysis tools installed and tested
  [ ] Volatility3: vol.py --version works
  [ ] ASan build environment: clang --version; afl-fuzz --version
  [ ] Semgrep: semgrep --version
  [ ] Internet access for the simulation: ALLOWED / BLOCKED
      (Note: MITRE ATT&CK reference is allowed; lesson re-reading is not)

SAMPLES PREPARED:
  [ ] Malware sample from MalwareBazaar (AgentTesla / AsyncRAT / Mirai)
      Note the hash but do not pre-analyse it
  [ ] Vulnerability research target: a C project you have NEVER audited
      Suggested: libpcap, jasper, libssh, mujs

REFERENCES ALLOWED DURING SIMULATION:
  [ ] Day 684 reference card (your own handwritten/typed notes only)
  [ ] MITRE ATT&CK website (read-only)
  [ ] Man pages
  NOT ALLOWED: previous lesson files, AI assistance, colleague help

CLOCK SET:
  Component 1 (Malware): ___:___ → ___:___ (2.5 hours)
  Component 2 (VulnResearch): ___:___ → ___:___ (3 hours)
  Component 3 (Oral): ___:___ → ___:___ (30 minutes)
```

---

## Component 1 — Malware Analysis (2.5 hours; ≥ 5/7 sections to pass)

**START TIME: _______  TARGET FINISH: _______**

```
╔═══════════════════════════════════════════════════════════════════╗
║              MALWARE ANALYSIS REPORT — SIMULATION                ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  Sample: _________________________  Hash: _______________________  ║
║  Analysis start: ________________  Target finish: ______________  ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝

────────────────────────────────────────────────────────────────────
SECTION 1: EXECUTIVE SUMMARY  (target: 5 minutes)
────────────────────────────────────────────────────────────────────
Malware family (if identified): ___________________________________
Primary capability:
  [ ] Infostealer  [ ] RAT  [ ] Ransomware  [ ] Dropper
  [ ] Botnet       [ ] Wiper [ ] Loader     [ ] Other: ___________
Key indicator that identified the family: _________________________

────────────────────────────────────────────────────────────────────
SECTION 2: STATIC ANALYSIS  (target: 30 minutes)
────────────────────────────────────────────────────────────────────
File type: _____________________ Compiler/packer: ________________
Imports of interest:
  1. ______________________________________________________________
  2. ______________________________________________________________
  3. ______________________________________________________________
Strings of interest (C2, keys, file paths):
  1. ______________________________________________________________
  2. ______________________________________________________________
  3. ______________________________________________________________
File hash MD5: ___________________________________________________

────────────────────────────────────────────────────────────────────
SECTION 3: DYNAMIC ANALYSIS  (target: 45 minutes)
────────────────────────────────────────────────────────────────────
Process tree: ____________________________________________________
Files created: ___________________________________________________
Registry keys (persistence): _____________________________________
Network connections: _____________________________________________
Notable API calls: _______________________________________________

────────────────────────────────────────────────────────────────────
SECTION 4: IOC LIST  (target: 10 minutes)
────────────────────────────────────────────────────────────────────
Hashes: __________________________________________________________
IPs: _____________________________________________________________
Domains: _________________________________________________________
File paths: ______________________________________________________
Mutexes: _________________________________________________________
Registry: ________________________________________________________

────────────────────────────────────────────────────────────────────
SECTION 5: MITRE ATT&CK MAPPING  (target: 10 minutes)
────────────────────────────────────────────────────────────────────
T_____ — _________________________________________________________
T_____ — _________________________________________________________
T_____ — _________________________________________________________
T_____ — _________________________________________________________

────────────────────────────────────────────────────────────────────
SECTION 6: YARA RULE  (target: 20 minutes)
────────────────────────────────────────────────────────────────────
rule sim_malware_day698 {
    meta:
        author = "[your handle]"
        date   = "2026-05-09"
    strings:
        $str1 =
        $str2 =
        $hex1 = {                            }
    condition:
        uint16(0) == 0x5A4D and 2 of ($str*)
}

YARA tested against sample: Match Y / N
YARA tested against 5 clean binaries: False positives: ______

────────────────────────────────────────────────────────────────────
SECTION 7: SIGMA DETECTION RULE  (target: 15 minutes)
────────────────────────────────────────────────────────────────────
title: [Family] Behaviour Detection
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      -
  condition: selection
falsepositives:
  -
level: high

Sections completed: ___/7
Component 1 time: _______ minutes (target: 150)
Component 1 gate pass? Y / N  (need ≥ 5/7)
```

---

## Component 2 — Vulnerability Research (3 hours; need confirmed or "suspicious with evidence")

**START TIME: _______  TARGET FINISH: _______**

```
╔═══════════════════════════════════════════════════════════════════╗
║          VULNERABILITY RESEARCH — SIMULATION                      ║
╠═══════════════════════════════════════════════════════════════════╣
║  Target: _________________________ (first time seeing it)         ║
║  Language: ___________  LOC: ________  Build system: ____________ ║
╚═══════════════════════════════════════════════════════════════════╝

T+00  Target selected and cloned
      ASan build: afl-clang-fast + -fsanitize=address -g -O1
      Build successful: Y / N

T+20  Semgrep scan started: Y / N
      AFL++ started: Y / N (seed corpus: _____ files)

T+40  Semgrep complete
      Findings: _______  Top 3:
        1. ___________________________________________________________
        2. ___________________________________________________________
        3. ___________________________________________________________
      Audit function list written: Y / N  (how many functions: _____)

T+75  [Checkpoint]
      Functions reviewed: _______
      Candidates found: _______
      AFL++ crashes: _______

T+120 [Checkpoint]
      Strongest candidate: ________________________________________
      Taint path sketched: Y / N
      AFL++ crashes: _______

T+150 [Checkpoint]
      PoC attempt started: Y / N
      Crash confirmed with ASan: Y / N

T+180 [Final]
      Advisory outline written: Y / N
      CVSS score calculated: _____ Justified: Y / N

Advisory Outline:
  Title: ___________________________________________________________
  CWE: __________________ CVSS: ____________________________________
  Root cause: ______________________________________________________
  Taint chain: Source → _____________ → _____________ → SINK
  Fix: _____________________________________________________________

Finding status:
  [ ] Confirmed crash PoC
  [ ] Candidate confirmed (taint path), PoC pending
  [ ] Suspicious candidate, not confirmed
  [ ] No finding (flag reason: ___________________________________)

Component 2 time: _______ minutes (target: 180)
Component 2 gate pass? Y / N  (need "suspicious with evidence" or better)
```

---

## Component 3 — Oral Defence (30 minutes; ≥ 4/6 to pass)

Have someone ask you these (or time yourself with 90 seconds per answer,
no notes):

```
ORAL DEFENCE — SIMULATION

Q1: Walk me through your first 15 minutes with an unknown Windows PE.
    Tools, order, decisions.
  Time: _______ sec  Self-rate: ___/4  Pass: Y / N (need ≥ 3/4)

Q2: How does a tcache use-after-free lead to arbitrary code execution?
  Time: _______ sec  Self-rate: ___/4  Pass: Y / N

Q3: What is the difference between AFL++ and libFuzzer?
    When do you use each?
  Time: _______ sec  Self-rate: ___/4  Pass: Y / N

Q4: Write a 5-line C function with a heap buffer overflow via integer
    overflow. Explain exactly why it is exploitable.
  Time: _______ sec  Self-rate: ___/4  Pass: Y / N

Q5: A Cuckoo report shows no suspicious activity. What do you check next?
  Time: _______ sec  Self-rate: ___/4  Pass: Y / N

Q6: Explain dependency confusion. How does an attacker exploit it and
    how does a developer prevent it?
  Time: _______ sec  Self-rate: ___/4  Pass: Y / N

Oral score: ___/6  Pass: Y / N  (need ≥ 4/6)
```

---

## Simulation Debrief

```
SIMULATION DEBRIEF

Component 1 (Malware):     Pass / Fail  (___/7 sections)
Component 2 (VulnResearch): Pass / Fail  (finding: _____________)
Component 3 (Oral):         Pass / Fail  (___/6 correct)

Overall: ___/3 components passed
Gate simulation: PASS (≥ 2/3) / FAIL (< 2/3)

IF FAILED: which component failed and why?
  ____________________________________________________________
  Remaining gap: ______________________________________________
  Action before Day 700: ______________________________________

IF PASSED: confidence level for Day 700?
  [ ] Very confident — all 3 passed with margin
  [ ] Confident — 2 passed; 1 was close
  [ ] Borderline — scraped 2/3; weak areas identified

WHAT TO DO DIFFERENTLY IN 3 HOURS THAT WERE WASTED TODAY:
  ____________________________________________________________
```

---

## Key Takeaways

1. **Simulation at full conditions is the only reliable predictor of gate
   performance.** A simulation where you peek at notes, pause the clock, or
   choose easy targets is not a simulation. It is a comfort exercise. Make
   the simulation uncomfortable — that is the point.
2. **Time management is the most common failure mode.** Students who know
   the material still fail the gate because they spend too long on Section 2
   of the malware analysis and never write the YARA rule (Section 6). Know
   your target times per section and enforce them.
3. **"Suspicious with evidence" is a gate pass for Component 2.** You do not
   need a working exploit. You need a documented taint path, a candidate
   function, and a justified CWE. A thorough "suspicious" finding with all
   supporting evidence is a professional-quality result.
4. **Tomorrow is rest and logistics.** Day 699 is not another sprint.
   It is final toolchain check, mindset preparation, and sleep. If you
   simulated today and passed, you are ready. Trust the training.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q698.1, Q698.2 …).

---

## Navigation

← Previous: [Day 697 — Targeted Practice: Vulnerability Research Gap Closure](DAY-0697-Practice-VulnResearch-Gap-Closure.md)
→ Next: [Day 699 — Gate Day Eve](DAY-0699-Gate-Day-Eve.md)
