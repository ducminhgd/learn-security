---
title: "Module 10 Competency Check Preparation — Gate Readiness"
tags: [gate-preparation, competency-check, malware-analysis,
  vulnerability-research, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 685
prerequisites:
  - Day 684 — Module 10 Review and Self-Assessment
  - Days 611–684 (all Module 10 content)
related_topics:
  - Day 700 — Module 10 Competency Check (Gate)
  - Day 701 — Hardware Security: UART and JTAG
---

# Day 685 — Module 10 Competency Check Preparation

> "The gate is not a test of knowledge. It is a test of capability under
> pressure. You know the material. What the gate measures is whether you
> can produce a result — an advisory, a YARA rule, a crash PoC — in a
> time-bounded engagement on unfamiliar material. Today you simulate that.
> Not to study. To rehearse the performance."
>
> — Ghost

---

## Goals

Run a full gate simulation: a timed live exercise covering both the
malware analysis and vulnerability research components of the Day 700
gate. Identify any remaining gaps. Check logistics and toolchain.
Mentally prepare for Day 700.

**Estimated study time:** 5–6 hours (simulation).

---

## What the Day 700 Gate Requires

The competency check on Day 700 has three components:

```
DAY 700 GATE COMPONENTS

COMPONENT 1: MALWARE ANALYSIS EXERCISE (2.5 hours)
  → You receive an unknown malware sample (Windows PE or ELF)
  → You perform full static + dynamic analysis in a sandboxed VM
  → Deliverable: malware analysis report (7 sections, see below)
  → Pass criteria: 5 of 7 sections completed with accurate findings

COMPONENT 2: VULNERABILITY RESEARCH EXERCISE (3 hours)
  → You receive an unknown C/C++ project with no prior knowledge
  → You run the complete audit pipeline
  → Deliverable: at least one documented bug candidate, advisory outline,
    and CVSS score
  → Pass criteria: at least one confirmed or "suspicious with evidence"
    finding; advisory format correct; CVSS justified

COMPONENT 3: ORAL DEFENCE (30 minutes)
  → 5–6 questions from the Day 684 oral list, plus follow-ups
  → No notes allowed
  → Each answer must be correct and concise (< 90 seconds)
  → Pass criteria: 4 of 6 questions answered correctly

OVERALL GATE: Pass 2 of 3 components.
If you pass Component 2 (vuln research), you must pass at least one of
Components 1 or 3 as well.
```

---

## Gate Simulation — Component 1 (Timed: 2.5 hours)

### Malware Sample: Use a Real Sample

Choose a malware sample from a reputable analysis platform:
- **MalwareBazaar** (abuse.ch/bazaar): free, tagged samples
- **Any.run** sample library: pre-analysed samples with reports
- **VirusTotal Intelligence** (requires account): production samples
- **FLARE-VM labs**: packaged practice samples

For this simulation, use a sample from **MalwareBazaar** tagged as
one of: `AgentTesla`, `AsyncRAT`, `NjRat`, `Mirai`, `Emotet`.

```
COMPONENT 1 SIMULATION

Sample hash / name: _________________________________________
Download source: ____________________________________________
Start time: ___________________ Target finish: ______________

MALWARE ANALYSIS REPORT — GATE FORMAT

───────────────────────────────────────────────────────────
1. EXECUTIVE SUMMARY (5 min)
───────────────────────────────────────────────────────────
Malware family (identify if possible): _____________________
Primary capability:
  [ ] Infostealer   [ ] RAT   [ ] Ransomware   [ ] Dropper
  [ ] Botnet / DDoS [ ] Wiper [ ] Loader       [ ] Other
Suspected threat actor / campaign (if attribution visible): _
Key indicator: ______________________________________________

───────────────────────────────────────────────────────────
2. STATIC ANALYSIS (30 min)
───────────────────────────────────────────────────────────
File type (PE32/ELF/script): _______________________________
Compiler / packer: _________________________________________
Imports of interest: ________________________________________
Strings of interest (C2 IPs/domains, file paths, keys):
  ___________________________________________________________
  ___________________________________________________________
File hash (MD5): ____________________________________________

───────────────────────────────────────────────────────────
3. DYNAMIC ANALYSIS (45 min)
───────────────────────────────────────────────────────────
Process tree: _______________________________________________
Files created: ______________________________________________
Registry keys: ______________________________________________
Network connections: ________________________________________
Notable API calls: __________________________________________

───────────────────────────────────────────────────────────
4. IOC LIST
───────────────────────────────────────────────────────────
Hashes:     ________________________________________________
IPs:        ________________________________________________
Domains:    ________________________________________________
File paths: ________________________________________________
Registry:   ________________________________________________
Mutexes:    ________________________________________________

───────────────────────────────────────────────────────────
5. MITRE ATT&CK MAPPING (10 min)
───────────────────────────────────────────────────────────
T____ — _____________________________________________________
T____ — _____________________________________________________
T____ — _____________________________________________________
T____ — _____________________________________________________

───────────────────────────────────────────────────────────
6. YARA RULE (20 min)
───────────────────────────────────────────────────────────
rule malware_day685_sample {
    meta:
        author    = "[your handle]"
        date      = "2026-05-08"
        hash      = "[MD5 of sample]"
    strings:
        $str1 = "[characteristic string]"
        $str2 = "[another characteristic string]"
        $hex1 = { [hex bytes] }
    condition:
        uint16(0) == 0x5A4D and 2 of ($str*)
}

───────────────────────────────────────────────────────────
7. SIGMA DETECTION RULE (15 min)
───────────────────────────────────────────────────────────
title: [malware family] Detection
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - '[suspicious string]'
  condition: selection
falsepositives:
  - [list expected false positives]
level: high

Component 1 completed in: _______ minutes (target: 150)
Self-assessment score (sections completed accurately): ___/7
Gate pass? Y / N (need 5/7)
```

---

## Gate Simulation — Component 2 (Timed: 3 hours)

```
COMPONENT 2 SIMULATION

Target: New project NOT used in Days 666–683 campaigns
Start time: ___________________ Target finish: ______________

Pipeline execution:
  T+00: Target selected, ASan build started
  T+20: Build complete, semgrep scan started
  T+40: Semgrep complete, audit list written
  T+60: First function fully audited
  T+90: [checkpoint] Candidates found so far: _______
  T+120: Fuzzer crashes so far: _______  Candidates: _______
  T+150: [checkpoint] Strongest candidate: __________________
  T+180: PoC attempted: Y / N  Crash confirmed: Y / N

Advisory outline (from candidate):
  Title: ____________________________________________________
  CWE: ___________________ CVSS (preliminary): ______________
  Root cause: _______________________________________________
  Fix: ______________________________________________________

Component 2 completed in: _______ minutes (target: 180)
Finding status: Confirmed / Candidate / Suspicious / None
Gate pass? Y / N (need: at least "suspicious with evidence")
```

---

## Gate Simulation — Component 3 (Timed: 30 minutes)

Ask someone (or use a timer) to ask these 6 questions. Answer without
notes. Time each answer (max 90 seconds).

```
ORAL DEFENCE SIMULATION

Q1: Walk me through the first 15 minutes with an unknown Windows PE.
  Time: _______ sec  Self-rate: ___/4

Q2: What does "malfind" report in Volatility and what causes false positives?
  Time: _______ sec  Self-rate: ___/4

Q3: How does Cobalt Strike beacon config encryption work at a high level,
    and what tool extracts the config?
  Time: _______ sec  Self-rate: ___/4

Q4: Show me a 5-line C code snippet with a heap OOB write via integer
    overflow. What is the CVSS v3.1 score if it is network-reachable
    and unauthenticated?
  Time: _______ sec  Self-rate: ___/4

Q5: What is the difference between AFL++ and libFuzzer?
    When would you use each?
  Time: _______ sec  Self-rate: ___/4

Q6: Explain dependency confusion. How do you prevent it?
  Time: _______ sec  Self-rate: ___/4

Component 3 score: ___/6 questions answered correctly (≥4 to pass)
Gate pass? Y / N
```

---

## Gate Logistics

```
PRE-GATE CHECKLIST — Complete before Day 700

ENVIRONMENT:
  [ ] FlareVM or Windows sandbox VM — snapshot taken, malware tools installed
  [ ] REMnux or Kali VM — dynamic analysis tools ready
  [ ] Volatility3 installed and tested with a sample image
  [ ] ASan + clang build environment verified on a test project
  [ ] AFL++ installed and tested (runs with any target binary)
  [ ] Semgrep installed (pip install semgrep) — test: semgrep --version
  [ ] Boofuzz installed — test: python3 -c "import boofuzz; print('ok')"

REFERENCES ALLOWED DURING GATE (confirm with instructor):
  [ ] Day 684 reference card (tool commands, CWE list, CVSS table)
  [ ] MITRE ATT&CK website (reference only, no browser search)
  [ ] Man pages for standard tools

NOT ALLOWED:
  [ ] Notes from previous sprints
  [ ] AI assistance
  [ ] Reading previous lessons during the gate

MENTAL PREPARATION:
  [ ] Slept well the night before
  [ ] Ate before the gate (cognitive performance depends on it)
  [ ] Start time agreed and calendar blocked
  [ ] Interruptions eliminated for 6+ hours
```

---

## Looking Ahead: Module 11 — Ghost Level (Days 701–730)

```
WHAT COMES AFTER THE GATE

Module 11 — Ghost Level:
  Day 701: Hardware security — JTAG, UART, firmware extraction
  Day 702: Firmware analysis — binwalk, squashfs, backdoor hunting
  Day 703: Advanced iOS — binary protections, jailbreak bypass
  Day 704: Zero-day mindset — what makes a zero-day, variant analysis
  Day 705: Year 2 synthesis — all of Year 2 in one review
  Day 706: Ghost Level preparation — tools, methodology, mindset
  Days 707–728: 48-hour solo engagement on an unknown lab target
  Day 729: Debrief — timeline, findings, lessons
  Day 730: Ghost Level Competency Gate — final assessment

The Ghost Level is the capstone. Everything in the programme leads to it.
Hardware security, firmware analysis, and the zero-day mindset build on
every skill you have developed over 700 days.

The 48-hour engagement (Days 707–728) is the real graduation test.
You receive an unknown target. You have 48 hours. You bring everything.
```

---

## Key Takeaways

1. **Rehearsal is different from review.** Review = reading and thinking.
   Rehearsal = producing output under time pressure on unfamiliar material.
   Today's simulation is rehearsal. The gate is also rehearsal, at higher
   stakes. The only preparation that works for performance-based assessment
   is practice of the performance.
2. **Two of three components is the pass.** If malware analysis is your
   weakest area, make sure you pass Component 2 (vulnerability research)
   and Component 3 (oral) comfortably. The gate rewards breadth across
   both disciplines, but it allows for a weakness in one area.
3. **The reference card is a force multiplier.** A well-built reference
   card (tool commands, CWE list, CVSS table) means you do not waste
   gate time searching your memory for `strings --include-all-whitespace`
   or the exact CVSS AV values. Build it today; use it on Day 700.
4. **After Day 700: the hardest part begins.** Module 11 puts hardware
   security, firmware analysis, and a 48-hour solo engagement on an
   unknown target. Everything you have learned — reversing, binary
   exploitation, web, cloud, malware, vulnerability research — will be
   needed simultaneously. Finish Module 10 well.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q685.1, Q685.2 …).

---

## Navigation

← Previous: [Day 684 — Module 10 Review and Self-Assessment](DAY-0684-Module-Review-and-Self-Assessment.md)
→ Next: [Day 686 — Targeted Gap Closure Sprint](DAY-0686-Gap-Closure-Sprint.md)
