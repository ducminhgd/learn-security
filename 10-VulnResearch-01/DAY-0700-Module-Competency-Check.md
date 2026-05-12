---
title: "Module 10 Competency Check — Malware Analysis and Vulnerability Research Gate"
tags: [competency-check, gate, malware-analysis, vulnerability-research,
  oral-defence, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 700
prerequisites:
  - Days 611–699 (Complete Module 10)
  - Day 699 — Gate Day Eve
related_topics:
  - Day 701 — Hardware Security: UART and JTAG
  - Day 730 — Ghost Level Competency Gate
---

# Day 700 — Module 10 Competency Check

> "Ninety days of work. Two sub-modules. Malware analysis and vulnerability
> research. Today we find out what you built.
>
> I am not going to wish you luck. Luck is for people who did not prepare.
> You prepared. Go do the work."
>
> — Ghost

---

## Gate Overview

```
╔═════════════════════════════════════════════════════════════════════╗
║           MODULE 10 COMPETENCY GATE — DAY 700                       ║
╠═════════════════════════════════════════════════════════════════════╣
║                                                                     ║
║  Total time allocated: 6 hours                                      ║
║  Format: three timed, independent components                        ║
║  Pass criterion: 2 of 3 components                                  ║
║                                                                     ║
║  Component 1: Malware Analysis    2.5 hours  5/7 sections to pass   ║
║  Component 2: Vulnerability Research  3 hours  finding to pass      ║
║  Component 3: Oral Defence           30 min   4/6 questions to pass ║
║                                                                     ║
╚═════════════════════════════════════════════════════════════════════╝
```

---

## Component 1 — Malware Analysis (2.5 hours)

### Setup

1. Obtain an unknown malware sample from MalwareBazaar. If you have an
   instructor, they will provide the sample. If self-directed, choose a
   sample tagged with a family you have NOT previously analysed in full.
2. Do NOT research the sample hash or family before starting.
3. Start your timer.

### Deliverable: Malware Analysis Report

Complete all seven sections. You need ≥ 5/7 sections to pass.

```
╔═════════════════════════════════════════════════════════════════════╗
║           MALWARE ANALYSIS REPORT — MODULE 10 GATE                  ║
╠═════════════════════════════════════════════════════════════════════╣
║  Analyst: _________________________ Date: ______________________    ║
║  Sample: __________________________ Hash: ______________________    ║
║  Analysis start: __________________ Analysis end: ______________    ║
╚═════════════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 1 — EXECUTIVE SUMMARY
Target time: 5 minutes
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Malware family (if identifiable): _________________________________
Primary capability (circle): Infostealer / RAT / Ransomware / Dropper
                              Botnet / Wiper / Loader / Unknown
Key identifying indicator: ________________________________________
Estimated threat level: Critical / High / Medium / Low
Reason: ___________________________________________________________

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 2 — STATIC ANALYSIS
Target time: 30 minutes
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

File type: _______________________________________________________
Compiler / runtime: ______________________________________________
Packed / obfuscated: Y / N   Method: _____________________________

Imports of interest (name + why suspicious):
  1. ______________________________________________________________
  2. ______________________________________________________________
  3. ______________________________________________________________

Strings of interest:
  C2 / server: ____________________________________________________
  File paths: _____________________________________________________
  Keys / tokens: __________________________________________________
  Other: __________________________________________________________

File hash MD5: ___________________________________________________
File hash SHA256: ________________________________________________

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 3 — DYNAMIC ANALYSIS
Target time: 45 minutes
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Process tree: ____________________________________________________
_____________________________________________________________ (parent)
  └─ ______________________________ (spawned child, if any)

Files created / modified: ________________________________________
_________________________________________________________________

Registry persistence: ____________________________________________
_________________________________________________________________

Network connections:
  IP:port        Protocol    Purpose
  _____________  _________   ___________________________________
  _____________  _________   ___________________________________

Notable API call sequences: ______________________________________
_________________________________________________________________

Anti-analysis observed (Day 689): Y / N  Type: ___________________

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 4 — IOC LIST
Target time: 10 minutes
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

File hashes (MD5 + SHA256): ______________________________________
IP addresses: ____________________________________________________
Domains: _________________________________________________________
File paths: ______________________________________________________
Registry keys: ___________________________________________________
Mutexes: _________________________________________________________
Scheduled tasks / services: ______________________________________
Certificates (thumbprint if applicable): _________________________

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 5 — MITRE ATT&CK MAPPING
Target time: 10 minutes
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Tactic              Technique ID   Technique Name
Initial Access    : T____________  ________________________________
Execution         : T____________  ________________________________
Persistence       : T____________  ________________________________
C&C               : T____________  ________________________________
Exfiltration      : T____________  ________________________________
Defence Evasion   : T____________  ________________________________

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 6 — YARA DETECTION RULE
Target time: 20 minutes
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

rule Module10_Gate_Malware {
    meta:
        analyst     = "[your handle]"
        date        = "2026-05-09"
        sample_hash = "[MD5 here]"
        family      = "[family name or unknown]"
        description = "[one-sentence description]"
    strings:
        $str1  =
        $str2  =
        $hex1  = {                                              }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F)
        and 2 of ($str*)
}

Tested against sample: Y — Match: Y / N
Tested against 5 clean files: Y — False positives: ______

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 7 — SIGMA DETECTION RULE
Target time: 15 minutes
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

title: Module10 Gate Malware Detection
id: [generate a UUID]
status: experimental
description: >
  Detects [family] behaviour based on [specific indicator]
date: 2026-05-09
author: [your handle]
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - '[suspicious_string_1]'
      - '[suspicious_string_2]'
  condition: selection
falsepositives:
  - [expected legitimate processes that trigger this rule]
level: high
tags:
  - attack.[tactic]
  - attack.t[technique_id]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
COMPONENT 1 COMPLETION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Sections completed: ___/7
Time taken: _______ minutes (target: 150)
COMPONENT 1 RESULT: PASS (≥ 5/7) / FAIL (< 5/7)
```

---

## Component 2 — Vulnerability Research (3 hours)

### Setup

1. Choose a C/C++ open-source project you have never audited. It must
   accept file or network input and have an active codebase (> 5,000 lines).
2. You may not use any project from previous practice sprints.
3. Start your timer.

### Deliverable: Finding Report + Advisory Outline

Pass criterion: at least one finding at "suspicious with evidence" level
or above, with a complete advisory outline and CVSS score.

```
╔═════════════════════════════════════════════════════════════════════╗
║          VULNERABILITY RESEARCH REPORT — MODULE 10 GATE             ║
╠═════════════════════════════════════════════════════════════════════╣
║  Analyst: _________________________ Date: ______________________    ║
║  Target: __________________________ Version: ___________________    ║
║  Language: ___________________ LOC: _________________________       ║
╚═════════════════════════════════════════════════════════════════════╝

PIPELINE EXECUTION LOG
T+00: Target cloned and ASan build started
T+20: Build complete: Y / N  Semgrep started: Y / N  AFL++ started: Y / N
T+40: Semgrep findings: _______  Audit list created: Y / N
T+80: Functions reviewed: _______  Candidates: _______ Crashes: _______
T+120: Strongest candidate identified: Y / N
T+150: PoC attempt: Y / N  Crash confirmed: Y / N
T+180: Advisory complete: Y / N

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PRIMARY FINDING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Title: ___________________________________________________________
Affected component: _________________________ Version: ___________
File: _________________________________ Line: ___________________
Function: ________________________________________________________
CWE: ____________________________________________________________

ROOT CAUSE:
  _______________________________________________________________
  _______________________________________________________________

TAINT CHAIN:
  Source (where untrusted data enters): ________________________
  → _____________________________________________________________
  → _____________________________________________________________
  Sink (dangerous operation): __________________________________

EVIDENCE:
  Code snippet (the vulnerable lines):

  [paste relevant code here]

  Semgrep / CodeQL hit: Y / N  Rule: ___________________________
  Manual confirmation: Y / N

POC STATUS:
  [ ] Working crash PoC confirmed (paste ASan output):
    ____________________________________________________________
    ____________________________________________________________
  [ ] Candidate confirmed — taint path documented, crash not yet triggered
  [ ] Suspicious candidate — code pattern identified, taint unconfirmed

CVSS v3.1:
  AV: ___  AC: ___  PR: ___  UI: ___  S: ___  C: ___  I: ___  A: ___
  Base Score: _______ — Severity: Critical / High / Medium / Low
  Justification: ________________________________________________

RECOMMENDED FIX:
  _______________________________________________________________

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
COMPONENT 2 COMPLETION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Finding level: Confirmed / Suspicious-with-evidence / Suspicious / None
Time taken: _______ minutes (target: 180)
COMPONENT 2 RESULT: PASS / FAIL
```

---

## Component 3 — Oral Defence (30 minutes)

No notes. No references. Answer from memory in under 90 seconds per question.

```
ORAL DEFENCE — MODULE 10 GATE

Questions (drawn from the Day 684 list by your instructor or self-selected
if self-directed):

Q1: _______________________________________________________________
    Answer: _______________________________________________________
    _____________________________________________________________
    Result: PASS / FAIL

Q2: _______________________________________________________________
    Answer: _______________________________________________________
    _____________________________________________________________
    Result: PASS / FAIL

Q3: _______________________________________________________________
    Answer: _______________________________________________________
    _____________________________________________________________
    Result: PASS / FAIL

Q4: _______________________________________________________________
    Answer: _______________________________________________________
    _____________________________________________________________
    Result: PASS / FAIL

Q5: _______________________________________________________________
    Answer: _______________________________________________________
    _____________________________________________________________
    Result: PASS / FAIL

Q6: _______________________________________________________________
    Answer: _______________________________________________________
    _____________________________________________________________
    Result: PASS / FAIL

Oral score: ___/6
COMPONENT 3 RESULT: PASS (≥ 4/6) / FAIL (< 4/6)
```

---

## Gate Result

```
╔═════════════════════════════════════════════════════════════════════╗
║                     MODULE 10 GATE RESULT                           ║
╠═════════════════════════════════════════════════════════════════════╣
║                                                                     ║
║  Component 1 (Malware Analysis):       PASS / FAIL  (___/7)         ║
║  Component 2 (Vulnerability Research): PASS / FAIL  (level: ___)    ║
║  Component 3 (Oral Defence):           PASS / FAIL  (___/6)         ║
║                                                                     ║
║  Components passed: ___/3                                           ║
║                                                                     ║
║  GATE:  ██ PASS  (proceed to Module 11 — Ghost Level)               ║
║         ██ FAIL  (remediation: see below)                           ║
║                                                                     ║
╚═════════════════════════════════════════════════════════════════════╝

IF FAILED:
  Failed components: ___________________________________________
  Remediation plan:
    [ ] Repeat Component 1 drill (Day 649/650 format)
    [ ] Repeat Component 2 sprint (Day 664/665 format)
    [ ] Oral preparation (Day 684 oral list, daily for 1 week)
  Scheduled retry date: ________________________________________

IF PASSED:
  Date of Module 10 gate pass: _________________________________
  Signed off by: _________________________ (instructor or self)

  "Module 10 is done. You can analyse malware and find vulnerabilities
  in unknown code. Those two skills, combined, make you dangerous in
  any security role — red team or blue.

  Module 11 starts tomorrow. It is different. Harder. You will be
  working without source code, on hardware, with a 48-hour clock.

  Everything you built for 700 days leads to that. Rest tonight.
  Start fresh tomorrow."

  — Ghost
```

---

## Key Takeaways

1. **This gate is proof, not certification.** Anyone can pass a multiple-choice
   test by memorising answers. This gate requires production of real output —
   a malware report, a vulnerability finding, oral reasoning — under time
   pressure. Passing it means you can actually do this work.
2. **The skills tested here are used on every engagement.** Malware analysis
   appears in incident response, threat hunting, and threat intelligence.
   Vulnerability research appears in red team ops, product security, and bug
   bounty. These are not niche skills — they are core.
3. **A gate fail is information, not punishment.** The failed component tells
   you exactly what to fix. Fix it. Retry. The programme does not proceed until
   the gate passes — that is not a penalty, it is a quality bar.
4. **Module 11 is the capstone.** 730 days of training lead to a 48-hour solo
   engagement on an unknown target. Module 11 is that engagement. You are
   30 days from the finish line.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q700.1, Q700.2 …).

---

## Navigation

← Previous: [Day 699 — Gate Day Eve](DAY-0699-Gate-Day-Eve.md)
→ Next: [Day 701 — Hardware Security: UART and JTAG](../11-GhostLevel/DAY-0701-Hardware-Security-UART-JTAG.md)
