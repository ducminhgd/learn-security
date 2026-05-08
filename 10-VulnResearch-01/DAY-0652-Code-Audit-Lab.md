---
title: "Code Audit Lab — Auditing a Real Open-Source Project"
tags: [vulnerability-research, code-audit, lab, C, open-source,
  finding-report, CWE, CVSS, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 652
prerequisites:
  - Day 651 — Source Code Auditing
related_topics:
  - Fuzzing Fundamentals (Day 653)
  - CVE Reproduction Lab (Day 657)
---

# Day 652 — Code Audit Lab: Auditing a Real Open-Source Project

> "Reading about grep patterns is the warm-up. The lab is the workout.
> Today you pick a real project, you run your patterns against it, and you
> find at least one real issue. Not a theoretical issue — a demonstrable
> bug with a proof-of-concept input that triggers the bad behaviour. If
> you finish the day without a finding, pick a different project and go again."
>
> — Ghost

---

## Goals

Select a small open-source C/C++ project. Run the Day 651 grep patterns
against it. Read the high-risk code regions identified. Find and document
at least one genuine vulnerability with a proof-of-concept. Write a structured
finding report.

**Prerequisites:** Day 651.
**Estimated study time:** 5–6 hours (lab).

---

## Target Selection

Choose a target in this difficulty band: small (< 10,000 LOC), written in
C or C++, accepts external input (file parser, network protocol, command-line
tool), and has had no CVE in the last 12 months.

```bash
# Suggested target types:
# - File format parsers: GIF, BMP, TIFF, SVG parsers
# - Network utilities: small HTTP servers, FTP clients
# - Audio/video decoders: small codec implementations
# - Compression tools: small zip/tar implementations

# Good starting points:
# https://github.com/topics/file-format?l=c&sort=recently-updated
# https://github.com/nicowillis/tiny-servers (example small HTTP servers)
# https://github.com/richfelker/musl-libc (standard library — known safe, good training)

# Clone the target:
git clone <target_url>
cd <target_dir>

# Count lines:
find . -name "*.c" -o -name "*.h" | xargs wc -l | tail -1

# Check for prior CVEs:
# https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=<project_name>

# Confirm it compiles:
make   # or: cmake && make
```

---

## Sprint: Audit Workflow

### Phase 1: Reconnaissance (30 minutes)

```
TARGET:
  Project name:   ____________________________________________
  Language:       C / C++ / Mixed
  Lines of code:  ____________________________________________
  Last commit:    ____________________________________________
  Known CVEs:     Y / N   Count: _____

  Brief description (what does this software do?):
  ___________________________________________________________

  Entry points (where external data enters):
    □ Command-line arguments (argv)
    □ File input (open/read/fgets)
    □ Network socket (recv/read on fd)
    □ Environment variables (getenv)
    □ Standard input (stdin)

  What external data format does it parse?
    ___________________________________________________________
```

### Phase 2: Grep Sweep (30 minutes)

```bash
cd <target_dir>

# Run all patterns:
grep -rn --include="*.c" --include="*.h" \
    -E "(strcpy|strcat|sprintf|gets|scanf\s*\(\s*\"%s)" . \
    | tee grep_dangerous_functions.txt

grep -rn --include="*.c" --include="*.h" \
    -E "malloc\s*\([^)]*\*" . \
    | tee grep_malloc_multiply.txt

grep -rn --include="*.c" --include="*.h" \
    -E "(printf|fprintf)\s*\(\s*[^\"']" . \
    | tee grep_format_strings.txt

grep -rn --include="*.c" --include="*.h" \
    -E "(system|popen|exec[vle])\s*\(" . \
    | tee grep_shell_exec.txt

wc -l grep_*.txt
```

```
GREP RESULTS SUMMARY:
  Dangerous functions: ___ hits
  Malloc * multiply:   ___ hits
  Format strings:      ___ hits
  Shell execution:     ___ hits

TOP 3 MOST INTERESTING HITS (to investigate further):
  1. File: ______________ Line: ___ Function: _______________
     Code: ________________________________________________

  2. File: ______________ Line: ___ Function: _______________
     Code: ________________________________________________

  3. File: ______________ Line: ___ Function: _______________
     Code: ________________________________________________
```

### Phase 3: Deep-Dive on Interesting Hits (2–3 hours)

For each interesting hit, trace the data flow:

```
INVESTIGATION — HIT 1:

  Sink: _____________ at _______________:___ (file:line)
  Sink code:
    __________________________________________________________

  Trace backward — who calls this function?
    Callee: _________________ → Caller: _____________________
    Caller: _________________ → Caller: _____________________
    ... (trace to entry point)

  Source of data (where does the input come from?):
    □ Command-line argument   □ File read   □ Network recv
    □ Environment variable    □ Other: _____________________

  Validation before sink:
    Length check: Y / N   (if Y: what check? ______________)
    Content check: Y / N  (if Y: what check? ______________)
    Type check: Y / N

  Is the sink reachable with attacker-controlled input and no validation?
    YES → FINDING   NO → Not exploitable, move to next hit
```

### Phase 4: Proof of Concept (1 hour)

```bash
# Once you have identified a vulnerable path:

# 1. Compile with debugging and sanitizers:
CFLAGS="-g -fsanitize=address,undefined" make

# 2. Create a minimal input that reaches the vulnerable code:
python3 -c "print('A' * 300)" > test_input.txt
# OR for binary formats:
python3 -c "import sys; sys.stdout.buffer.write(b'HEADER' + b'A' * 300)" > test_input.bin

# 3. Run with the test input:
./target test_input.txt 2>&1 | head -30

# 4. Look for:
# AddressSanitizer: heap-buffer-overflow / stack-buffer-overflow
# UndefinedBehaviorSanitizer: signed integer overflow
# Segmentation fault (without sanitizer)

# 5. Minimise the PoC input:
# Reduce the input size until the crash no longer occurs → minimum reproducer
```

```
PROOF OF CONCEPT:

  PoC command:
    ___________________________________________________________

  PoC input (hex or description):
    ___________________________________________________________

  Crash / error output:
    ___________________________________________________________
    ___________________________________________________________

  AddressSanitizer output (if applicable):
    ___________________________________________________________

  Crash type: segfault / heap overflow / stack overflow / UAF / other
  Crash address: 0x___________
  Exploitability: DoS / Information Leak / Code Execution (potential)
```

---

## Finding Report

```
FINDING REPORT
Audit Lab — Day 652
Target: _________________ Version: _______________
Analyst: _______________  Date: __________________

TITLE: [CWE-NNN] <Short description> in <file>/<function>()

SEVERITY: Critical / High / Medium / Low

CWE: _______________________________________________________
CVSS v3 Score: _____________
  Vector: AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_

AFFECTED FILE: _____________________ Line: _______________
AFFECTED FUNCTION: _________________________________________

DESCRIPTION:
  ___________________________________________________________
  ___________________________________________________________
  ___________________________________________________________

VULNERABLE CODE:
  (paste the exact vulnerable lines here, with line numbers)
  ___________________________________________________________
  ___________________________________________________________

DATA FLOW:
  Source: (where does the attacker-controlled data come from?)
    ___________________________________________________________
  Path:   (call chain from source to sink)
    ___________________________________________________________
  Sink:   (dangerous operation)
    ___________________________________________________________

PROOF OF CONCEPT:
  Command: ___________________________________________________
  Input:   ___________________________________________________
  Output / crash: ___________________________________________

IMPACT:
  ___________________________________________________________

FIX:
  (show the corrected code)
  ___________________________________________________________
  ___________________________________________________________

REFERENCES:
  CWE link: https://cwe.mitre.org/data/definitions/<N>.html
  Similar CVE (if known): ___________________________________
```

---

## Responsible Disclosure Note

```
BEFORE REPORTING:
  1. Verify the bug is real and reproducible in the latest version
  2. Check whether a CVE has already been assigned for this issue
  3. Contact the project maintainer via:
     - SECURITY.md in the repository (preferred)
     - GitHub Security Advisories (private disclosure)
     - Direct email to maintainer
  4. Give them 90 days to patch before public disclosure (Google Project Zero standard)
  5. Do NOT post the PoC publicly until the fix is released

For this lab: submit your finding to Ghost for review.
Do NOT file a public issue or CVE for a lab exercise.
```

---

## Key Takeaways

1. **The grep output is a map, not a finding.** Every grep hit requires manual
   verification: trace the data flow, confirm attacker control, confirm the
   absence of validation. 90% of grep hits will be false positives. The 10%
   are your targets.
2. **AddressSanitizer is your most valuable ally.** Compile with `-fsanitize=address`
   and most memory safety bugs announce themselves loudly with full context. Without
   it, a buffer overflow might just crash silently. With it, you get the exact byte
   offset, the allocation size, and a full stack trace.
3. **Minimise your PoC.** A 300-byte string that sometimes crashes is a PoC. A
   10-byte string that always crashes in exactly the same place is a finding. The
   process of minimisation forces you to understand exactly which bytes trigger the
   bug — which is the same understanding you need to write the fix.
4. **Document as you go — the finding report is built during the audit, not after.**
   By the time you have a crash, you should already have 80% of the finding report
   filled in from your investigation notes. The report is not a post-analysis
   document — it is a running investigation log formatted for external consumption.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q652.1, Q652.2 …).

---

## Navigation

← Previous: [Day 651 — Source Code Auditing](DAY-0651-Source-Code-Auditing.md)
→ Next: [Day 653 — Fuzzing Fundamentals](DAY-0653-Fuzzing-Fundamentals.md)
