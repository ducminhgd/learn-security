---
title: "Vulnerability Research Practice Sprint — Day 1 (Audit + Fuzzing)"
tags: [vulnerability-research, lab, practice-sprint, source-code-audit,
  fuzzing, AFL++, finding-report, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 664
prerequisites:
  - Day 651 — Source Code Auditing
  - Day 654 — Fuzzing Lab
  - Day 663 — Bug Class Deep Dive — Memory Safety
related_topics:
  - Vulnerability Research Practice Sprint Day 2 (Day 665)
---

# Day 664 — Vulnerability Research Practice Sprint: Day 1

> "Day 1 of a two-day sprint. You pick the target; I pick nothing for you.
> That is deliberate. Real vulnerability research does not come with a list
> of suggested CVEs. You will identify a target, read its code, run your
> tools, and find something — or not. Both outcomes teach you something.
> Tomorrow you write it up. Today you find it."
>
> — Ghost

---

## Goals

Select a real open-source project. Conduct a combined static analysis and
fuzzing campaign within a 4–5 hour session. Document all candidate findings
with triage notes. Identify at least one candidate finding for Day 2 write-up.

**Prerequisites:** Days 651, 654, 663.
**Estimated study time:** 5 hours (unguided lab).

---

## Target Selection Criteria

```
TARGET SELECTION MATRIX
═══════════════════════════════════════════════════════════════════════

REQUIRED:
  ✓ Open-source project with source code on GitHub/GitLab
  ✓ C or C++ codebase (most straightforward for memory safety research)
     OR: Python/JavaScript for injection vulnerability research
  ✓ < 30,000 lines of code (scope manageable in 2 days)
  ✓ Accepts external input (file, network socket, command-line argument)
  ✓ NOT currently in OSS-Fuzz (check: google.github.io/oss-fuzz/projects/)
  ✓ Last significant commit within 12 months (still maintained = will respond)
  ✓ No CVE assigned in the last 12 months for this specific component

PREFERRED (increases finding probability):
  ✓ Parser library (file format, network protocol, data format)
  ✓ Project with few contributors (less code review coverage)
  ✓ Project that processes untrusted data by design
  ✓ Written in C without modern sanitizer flags in build system

AVOID:
  ✗ curl, OpenSSL, FFmpeg, libpng — heavily fuzzed by OSS-Fuzz
  ✗ Linux kernel — requires specialist setup (use CTF kernel challenges instead)
  ✗ Projects > 50,000 LOC — too large to cover meaningfully in 2 days
  ✗ Projects with no build documentation (setup will eat your research time)
```

```
TARGET SELECTED:

Project name:     __________________________________________________
Repository URL:   __________________________________________________
Language:         __________________________________________________
LOC (approx):     __________________________________________________
Primary function: __________________________________________________
  (What does it do? What untrusted data does it process?)

Why this target (your reasoning):
  __________________________________________________
  __________________________________________________

OSS-Fuzz check: [ ] confirmed NOT in OSS-Fuzz
Recent CVE check: [ ] no CVE in last 12 months
Last commit date: __________________________________________________
```

---

## Sprint 1 — Setup and Reconnaissance (45 minutes)

### Environment Setup

```bash
# Clone the target
git clone <repository_url>
cd <project_name>

# Check project age and activity
git log --oneline | head -20
git log --format="%ai %s" --since="1 year ago" | wc -l

# Count lines of code
find . -name "*.c" -o -name "*.h" | xargs wc -l | tail -1
find . -name "*.py" | xargs wc -l 2>/dev/null | tail -1

# Look for existing security issues (what has been fixed before?)
git log --all --grep="CVE\|fix\|security\|vuln\|overflow\|crash" \
    --format="%h %s" | head -20

# Build with AddressSanitizer enabled
CFLAGS="-g -fsanitize=address,undefined" \
LDFLAGS="-fsanitize=address,undefined" \
./configure 2>&1 | tail -5 && make -j$(nproc) 2>&1 | tail -10

# OR cmake build:
mkdir build_asan && cd build_asan
cmake -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_C_FLAGS="-g -fsanitize=address,undefined" \
      .. && make -j$(nproc) 2>&1 | tail -10
```

```
SETUP LOG:

Build successful: Y / N
Build errors (if any):
  ________________________________________________

ASan binary location: _____________________________
Test run (confirm binary works with valid input):
  Command: ________________________________________
  Output: _________________________________________

Commit hash audited: ______________________________
```

### Reconnaissance

```bash
# Map the entry points — where does external data enter the program?
grep -rn "fopen\|fread\|fgets\|read\|recv\|getline\|scanf" \
    --include="*.c" --include="*.h" . | grep -v "test\|example"

# Map the dangerous sinks
grep -rn "memcpy\|strcpy\|strcat\|sprintf\|gets\|system\|popen\|printf(" \
    --include="*.c" . | grep -v "//\|test"

# Find the core parsing functions
grep -rn "parse\|decode\|load\|process\|handle" \
    --include="*.h" . | grep "^.*:\s*\(int\|void\|char\|size_t\)" | head -20

# Run Semgrep for quick SAST sweep
pip install semgrep 2>/dev/null || true
semgrep --config=p/c --json . 2>/dev/null | \
    python3 -c "import json,sys; \
    [print(r['check_id'], r['path'], r['start']['line']) \
     for r in json.load(sys.stdin).get('results', []) \
     if r.get('extra',{}).get('severity') in ('ERROR','WARNING')]"
```

```
RECON LOG:

Main entry point functions:
  1. ____________________________________________
  2. ____________________________________________
  3. ____________________________________________

Dangerous function calls found (top 5 from Semgrep or grep):
  1. ____________________________________________ (file:line)
  2. ____________________________________________ (file:line)
  3. ____________________________________________ (file:line)
  4. ____________________________________________ (file:line)
  5. ____________________________________________ (file:line)

Most promising attack surface (your assessment):
  ________________________________________________
```

---

## Sprint 2 — Manual Code Audit (90 minutes)

Focus on the top 2–3 candidates identified in Sprint 1. Read the code around
each candidate. Determine whether the input is attacker-controlled and whether
there is a missing check.

```
CANDIDATE 1:

File: _______________________________________________
Function: ___________________________________________
Line: _______________________________________________

VULNERABLE CODE (copy the relevant lines):
  ________________________________________________
  ________________________________________________

Input source (where does the data come from?):
  ________________________________________________

Is this input attacker-controlled? Y / N
  Reasoning: ______________________________________

Is there a validation/bounds check before the dangerous operation? Y / N
  Evidence: _______________________________________

Vulnerability class (if confirmed):
  [ ] Buffer overflow (CWE-121/122)
  [ ] Integer overflow (CWE-190)
  [ ] Format string (CWE-134)
  [ ] UAF / double-free (CWE-416/415)
  [ ] Command injection (CWE-78)
  [ ] SQL injection (CWE-89)
  [ ] Other: _______________________________________

Confidence level: LOW / MEDIUM / HIGH
  (Low = pattern match only; Medium = taint path confirmed; High = PoC works)
```

```
CANDIDATE 2:

File: _______________________________________________
Function: ___________________________________________
Line: _______________________________________________

VULNERABLE CODE:
  ________________________________________________
  ________________________________________________

Input attacker-controlled? Y / N
Validation present? Y / N
Vulnerability class: ________________________________
Confidence: LOW / MEDIUM / HIGH
```

```
CANDIDATE 3 (if any):

File: _______________________________________________
Function: ___________________________________________
Vulnerability class: ________________________________
Confidence: LOW / MEDIUM / HIGH
```

---

## Sprint 3 — Fuzzing Campaign (90 minutes)

```bash
# ══════════════════════════════════════
# WRITE HARNESS
# ══════════════════════════════════════

# Identify the parsing function signature from your audit:
# e.g. int parse_foo(const char *buf, size_t len);
# Write a libFuzzer harness (copy from Day 654 template):

cat > fuzz_harness.c << 'EOF'
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Include target library header */
/* #include "target.h" */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;     /* minimum meaningful input */
    if (size > 1024*1024) return 0;

    /* Call target parser — replace with actual function: */
    /* target_parse(data, size); */

    return 0;
}
EOF

# Compile harness:
clang -g -fsanitize=address,fuzzer \
    fuzz_harness.c \
    -I <include_dir> \
    <libfoo.a> \
    -o fuzzer_afl

# Verify harness runs:
./fuzzer_afl -runs=100

# ══════════════════════════════════════
# BUILD SEED CORPUS
# ══════════════════════════════════════

mkdir -p corpus
# Create minimal valid inputs for the target format:
# For text formats: echo 'valid input' > corpus/seed1.txt
# For binary formats: python3 -c "import struct; ..." > corpus/seed.bin
# Copy any sample files from the project:
cp tests/samples/* corpus/ 2>/dev/null || \
    cp examples/*.* corpus/ 2>/dev/null || true

ls corpus/   # confirm seeds present

# ══════════════════════════════════════
# RUN FUZZER
# ══════════════════════════════════════

# libFuzzer (90 minutes):
./fuzzer_afl corpus/ \
    -max_len=65536 \
    -timeout=10 \
    -artifact_prefix=crashes/ \
    -print_final_stats=1 \
    2>&1 | tee fuzzer_log.txt &

# Monitor progress (every 10 min):
watch -n 600 'grep -E "NEW|crash" fuzzer_log.txt | tail -5'
```

```
FUZZING LOG:

Harness compiles: Y / N
Harness runs (100 iterations): Y / N

Seed corpus size: _______ files, _______ total bytes

Fuzzing session:
  Start time: _________________
  End time:   _________________
  Exec/s:     _________________
  Coverage:   _______ edges
  Crashes found: _____________
  Unique crashes: _____________
```

---

## Sprint 4 — Crash Triage (30 minutes)

```bash
# List crashes:
ls crashes/ 2>/dev/null || ls afl_output/crashes/ 2>/dev/null

# Reproduce each unique crash:
for crash in crashes/crash-*; do
    echo "=== Crash: $crash ==="
    ./fuzzer_afl "$crash" 2>&1 | head -30
    echo "---"
done

# Minimise most interesting crash:
./fuzzer_afl crashes/crash-<hash> -minimize_crash=1 \
    -artifact_prefix=crashes/min_ 2>&1

# Confirm crash correlates with your manual audit candidate:
# Does the ASan stack trace include the function you flagged in Sprint 2?
./fuzzer_afl crashes/min_crash-<hash> 2>&1 | grep "#[0-9]"
```

```
CRASH TRIAGE:

Total crashes reproduced: _______
Unique stack traces (deduplicated): _______

MOST INTERESTING CRASH:
  Input file: _____________________________________________
  Minimised input size: _______ bytes
  
  Crash type (from ASan):
    [ ] heap-buffer-overflow   [ ] stack-buffer-overflow
    [ ] heap-use-after-free    [ ] NULL-dereference
    [ ] other: ______________________________________________

  Stack trace (top 3 frames):
    #0 ______________ in ______________ <file>:<line>
    #1 ______________ in ______________ <file>:<line>
    #2 ______________ in ______________ <file>:<line>

  Does this match a candidate from Sprint 2? Y / N
    Matching candidate: Candidate # ______

  Exploitability assessment:
    [ ] DoS only (crash, no write primitive confirmed)
    [ ] Information disclosure (heap or stack data leak)
    [ ] Potentially exploitable (overflow with write beyond crash)
    [ ] RCE confirmed (working exploit or controlled instruction pointer)
```

---

## Day 1 Summary

```
DAY 1 SPRINT SUMMARY
═══════════════════════════════════════════════════════════════════════

Target:           __________________________________________________
Total time spent: _______ hours

Manual audit candidates: _______  (HIGH confidence: _______)
Fuzzing crashes found:   _______  (unique root causes: _______)
Crash matches audit:     Y / N

BEST CANDIDATE for Day 2 write-up:
  Type: _______________________________________________
  File: _______________________________________________
  Confidence: LOW / MEDIUM / HIGH
  Finding source: [ ] Manual audit only
                  [ ] Fuzzer only
                  [ ] Both confirm same location

WHAT DID NOT WORK (honest assessment):
  ________________________________________________
  ________________________________________________

What will you focus on first on Day 2?
  ________________________________________________
```

---

## Key Takeaways

1. **Target selection determines success more than technique.** A well-chosen
   target — small, active, receives untrusted input, not fuzzed by OSS-Fuzz —
   is more likely to yield findings than a technically superior methodology
   applied to a battle-hardened project. Spend real time on target selection.
2. **Semgrep in 5 minutes beats manual grep in 30.** The moment you have the
   repository cloned, run `semgrep --config=p/c .` before reading any code.
   The output gives you a prioritised list of dangerous patterns to start with,
   and you can cross-reference against manual findings. Never audit without SAST
   as the first pass.
3. **The harness quality sets the ceiling for fuzzer effectiveness.** If your
   harness only reaches one code path, the fuzzer only finds bugs in that one
   path. Read the target API carefully; write a harness that exercises the
   most dangerous parsing functions directly, not the high-level wrapper that
   adds logging and error recovery on top.
4. **A fuzzer crash without a manual audit candidate is a data point.** If the
   fuzzer found a crash but you did not identify the location manually, that
   means either your manual coverage was incomplete (go back and look at that
   function) or the fuzzer found something truly unexpected (exciting — look
   carefully at the stack trace and understand why). Never dismiss a fuzzer crash
   without reading the code at the crash site.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q664.1, Q664.2 …).

---

## Navigation

← Previous: [Day 663 — UAF and Heap Corruption](DAY-0663-Bug-Class-UAF-Heap-Corruption.md)
→ Next: [Day 665 — Vulnerability Research Practice Sprint Day 2](DAY-0665-VulnResearch-Practice-Sprint-Day2.md)
