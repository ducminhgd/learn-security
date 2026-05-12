---
title: "Vulnerability Research Practice Sprint — Day 3 (New Target, Full Pipeline)"
tags: [vulnerability-research, lab, practice-sprint, audit, fuzzing, poc,
  module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 683
prerequisites:
  - Day 665 — VulnResearch Practice Sprint Day 2
  - Day 670 — Audit Campaign Day 5: Finding Report
  - Days 666–682 (Module 10 VulnResearch content)
related_topics:
  - Day 684 — Module Review and Self-Assessment
  - Day 700 — Vulnerability Research Module Competency Check
---

# Day 683 — Vulnerability Research Practice Sprint: Day 3

> "A third sprint on a new target. You are not doing this to fill a day —
> you are doing this because repetition is how the process becomes
> instinct. By the end of today the audit pipeline should feel automatic:
> scope, orient, taint, sink, PoC, advisory. Not a checklist you have to
> read. A reflex."
>
> — Ghost

---

## Goals

Select a new open-source target (different from the Day 666–670 campaign).
Run the complete pipeline from scratch: orient, automated pre-scan, manual
taint tracking, fuzzing, PoC, advisory. Complete everything in one day.

**Prerequisites:** Days 665, 670, 682.
**Estimated study time:** 8 hours (full-day sprint).

---

## Sprint Rules

```
DAY 3 SPRINT RULES

1. NEW TARGET: Do not use the same project as the Day 666 campaign.
   Choose a different project, language, or bug class to maximise coverage.

2. TIME-BOX EACH PHASE:
   Phase 1 — Target selection and setup:    30 minutes
   Phase 2 — Orientation and automated scan: 60 minutes
   Phase 3 — Manual audit + fuzzer launch:  180 minutes
   Phase 4 — Crash triage / PoC development: 120 minutes
   Phase 5 — Advisory and retrospective:    90 minutes
   Total:                                   480 minutes (8 hours)

3. MINIMUM DELIVERABLES:
   [ ] Target selected, ASan build working
   [ ] Semgrep run, top 5 findings triaged
   [ ] Audit function list written (min 5 functions)
   [ ] Fuzzer running (even if no crash yet)
   [ ] At least 1 candidate bug documented (confirmed or suspicious)
   [ ] Bug summary written (even if no crash)
   [ ] Advisory outline started

4. STRETCH GOAL:
   [ ] Working crash PoC
   [ ] Complete advisory at disclosure quality
   [ ] CVSS score calculated and justified
```

---

## Phase 1 — Target Selection and Setup (30 minutes)

```
TARGET SELECTION

Use the criteria from Day 666. Do not spend more than 30 minutes on this.

Target chosen: ______________________________________________
GitHub URL: _________________________________________________
Language: _____________________ LOC: _______________________
Input type: _________________________________________________
Existing CVEs: Y / N

ASan build:
  [ ] Clone successful
  [ ] ASan build successful
  [ ] Test run with sample input: crash / no crash / error

Semgrep scan started: Y / N
AFL++ started: Y / N (with seed corpus)

Time spent: _______ minutes
```

---

## Phase 2 — Orientation and Automated Scan (60 minutes)

```python
#!/usr/bin/env python3
"""
Day 683 — Automated scan phase.
Run this at the start of Phase 2 to generate candidates fast.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def run_semgrep(target_dir: str) -> list[dict]:
    """Run semgrep C/C++ rules and return JSON results."""
    result = subprocess.run(
        [
            "semgrep", "--config", "p/c",
            "--json",
            "--include", "*.c", "--include", "*.h", "--include", "*.cpp",
            target_dir,
        ],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode not in (0, 1):   # 0 = ok, 1 = findings
        print(f"[!] semgrep error: {result.stderr[:200]}")
        return []
    import json
    return json.loads(result.stdout).get("results", [])


def run_source_grep(target_dir: str) -> None:
    """Quick grep for high-risk patterns."""
    patterns = [
        r"malloc\s*(\s*.*\*",     # malloc with arithmetic
        r"memcpy.*argv",          # memcpy from argv (stack overflow)
        r"sprintf\s*(",           # unsafe format
        r"gets\s*(",              # gets() — always vulnerable
        r"scanf\s*(",             # unbounded scanf
        r"strcpy\s*(",            # unbounded strcpy
    ]
    for p in patterns:
        result = subprocess.run(
            ["grep", "-rn", "--include=*.c", "--include=*.cpp", p, target_dir],
            capture_output=True, text=True,
        )
        if result.stdout:
            print(f"\n[GREP: {p}]")
            for line in result.stdout.splitlines()[:5]:
                print(f"  {line}")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."

    print("[*] Running Semgrep...")
    findings = run_semgrep(target)
    print(f"[*] Total findings: {len(findings)}")

    from collections import Counter
    counts = Counter(f["check_id"].split(".")[-1] for f in findings)
    print("[*] Top findings by rule:")
    for rule, cnt in counts.most_common(10):
        print(f"  {cnt:4} {rule}")

    print("\n[*] Running source grep for high-risk patterns...")
    run_source_grep(target)
```

```
ORIENTATION LOG

Codebase map:
  Largest files: ____________________________________________
  Entry points: _____________________________________________
  Key subsystems: ___________________________________________

Semgrep results:
  Total findings: _______
  Unique rules triggered: _______
  Top 3 rules (by count):
    1. _______________________  count: _____
    2. _______________________  count: _____
    3. _______________________  count: _____

Time spent: _______ minutes (target: 60)
```

---

## Phase 3 — Manual Audit + Fuzzer Launch (180 minutes)

Use the Function Audit Protocol from Day 667.

```
AUDIT FUNCTION LIST (write before reading)

Priority | File                   | Function              | Reason
─────────┼────────────────────────┼───────────────────────┼──────────────────
  HIGH   | ___________________    | _____________________ | ________________
  HIGH   | ___________________    | _____________________ | ________________
  HIGH   | ___________________    | _____________________ | ________________
  MED    | ___________________    | _____________________ | ________________
  MED    | ___________________    | _____________________ | ________________

AFL++ fuzzer:
  Binary: ________________________
  Corpus: ________________________ (N files)
  Started at: ____________________

AUDIT PROGRESS (update every 45 minutes):
  T+45min:  Functions read: ______ | Candidates: ______ | Crashes: ______
  T+90min:  Functions read: ______ | Candidates: ______ | Crashes: ______
  T+135min: Functions read: ______ | Candidates: ______ | Crashes: ______
  T+180min: Functions read: ______ | Candidates: ______ | Crashes: ______
```

### Function Audit Worksheet (photocopy for each function)

```
FUNCTION: _________________________  File: _________  Line: _____

Inputs and their sources (trusted/untrusted):
  ___________________________________________________________

Validation present: Y / N / Partial → ______________________

Dangerous operation reached: Y / N
  If Y: ____________________________________________________

Taint path (brief):
  Source → __________________ → __________________ → SINK

Verdict: Clean / Suspicious / Candidate / Confirmed
Notes: ____________________________________________________
```

---

## Phase 4 — Crash Triage and PoC Development (120 minutes)

```bash
# Check for fuzzer crashes
ls afl_output/crashes/ | grep -v README | wc -l
# For each crash:
./build-asan/[target] afl_output/crashes/id:* 2>&1 | head -20

# Triage your strongest candidate (fuzzer crash or manual find):
# Apply the PoC template from Day 665/669
```

```
PoC DEVELOPMENT LOG

Candidate: _________________________________________________
Trigger value: _____________________________________________
PoC file: __________________________________________________

Attempt 1: _______________________________________________
  Crash: Y / N  ASan error: ______________________________

Attempt 2 (if needed): ___________________________________
  Crash: Y / N  ASan error: ______________________________

CONFIRMED CRASH:
  ASan error type: _________________________________________
  Crash function: __________________________________________
  Frame #0: ________________________________________________

Time spent: _______ minutes (target: 120)
```

---

## Phase 5 — Advisory and Retrospective (90 minutes)

### Abbreviated Advisory

```
SPRINT 3 ADVISORY

Title: ______________________________________________________
CWE: __________________ CVSS (preliminary): _________________
Target: _____________________  Commit: ___________________

Root cause:
  ___________________________________________________________

Taint chain:
  Source → _______________ → _______________ → SINK

Trigger: ____________________________________________________
Impact: _____________________________________________________

Fix: ________________________________________________________

Disclosure decision:
  [ ] Real finding — will disclose
  [ ] Lab exercise — internal only
  [ ] False positive

Advisory quality (self-assess against Day 659 standards):
  [ ] Title is specific (product, version, function, class)
  [ ] Root cause explained (not just symptom)
  [ ] PoC is reproducible
  [ ] Impact is concrete
  [ ] Fix is actionable
```

### Sprint Retrospective

```
DAY 3 SPRINT RETROSPECTIVE

Total time: _______ hours  (vs Day 1: _______ / Day 2: _______)

Pipeline times vs Day 666 audit campaign:
  Target selection: ______ min  (Day 666: 30 min)
  Orientation:      ______ min  (Day 667: 60 min)
  Manual audit:     ______ min  (Day 668: 180 min)
  PoC development:  ______ min  (Day 669: 120 min)
  Advisory:         ______ min  (Day 670: 90 min)

FINDING STATUS:
  [ ] Confirmed crash PoC
  [ ] Candidate confirmed (taint path), PoC pending
  [ ] Suspicious candidate, not confirmed
  [ ] No finding

SPEED COMPARISON (were you faster than Day 665–670?):
  Faster: Y / N
  What made the difference:
    ___________________________________________________________

WHAT I WOULD DO DIFFERENTLY IN A REAL ENGAGEMENT:
  ___________________________________________________________
  ___________________________________________________________

READINESS FOR DAY 700 GATE (update from Day 675 estimate):
  [ ] Ready now
  [ ] Need to practice one more sprint
  [ ] Need to revisit: ________________________________________
```

---

## Key Takeaways

1. **The pipeline gets faster with repetition.** The first time through
   (Days 666–670), each phase felt new. This sprint should feel like
   muscle memory. If it does not, the areas that still feel slow are
   your gaps. Name them.
2. **Different targets, same patterns.** No matter the project — image
   parser, network daemon, document library — the vulnerabilities are
   the same five or six classes. Integer overflow before size, missing
   bounds check, use-after-free, format string, command injection. You
   are not discovering new bug classes; you are finding the same classes
   in different code.
3. **Eight hours is a realistic single-day research sprint.** A
   professional vulnerability researcher working a serious target will
   spend 8–12 hours in a focused session. You are operating at that
   pace now. That is the standard.
4. **Incomplete findings are still findings.** A "suspicious candidate
   with taint path confirmed but no PoC yet" is a legitimate result for
   a one-day sprint. Document it exactly as it is. Real research does not
   always produce crashes on day one. The documentation of partial findings
   is how you pick up the thread the next day.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q683.1, Q683.2 …).

---

## Navigation

← Previous: [Day 682 — JavaScript Engine Vulnerability Introduction](DAY-0682-JavaScript-Engine-Vulnerability-Intro.md)
→ Next: [Day 684 — Module 10 Review and Self-Assessment](DAY-0684-Module-Review-and-Self-Assessment.md)
