---
title: "Audit Campaign Day 3 — Deep Manual Audit and Fuzzer Triage"
tags: [vulnerability-research, code-audit, manual-audit, fuzzer-triage,
  taint-tracking, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 668
prerequisites:
  - Day 667 — Audit Campaign Day 2: Codebase Navigation
  - Day 654 — Fuzzing Lab
  - Day 663 — Bug Class: UAF and Heap Corruption
related_topics:
  - Day 669 — Audit Campaign Day 4: PoC Development
  - Day 665 — VulnResearch Practice Sprint Day 2
---

# Day 668 — Audit Campaign Day 3: Deep Manual Audit and Fuzzer Triage

> "Speed reading code is how you miss bugs. A function that looks clean in
> thirty seconds will hide a critical integer overflow from you for a week.
> Slow down at every arithmetic operation that touches user data. Slow
> down at every allocation. Slow down at every free. These are where
> the bugs live. Everywhere else, you can skim."
>
> — Ghost

---

## Goals

Deep-read the top-priority functions from your audit list. Trace every
arithmetic operation on user-controlled values. Triage any fuzzer crashes
from Day 2. Identify and document your strongest candidate bug.

**Prerequisites:** Day 667 (audit list exists, fuzzer is running).
**Estimated study time:** 5–6 hours.

---

## 1 — Deep Read Protocol

### Arithmetic Operations on User-Controlled Data

Every arithmetic operation that takes a user-controlled value as an operand
is a potential vulnerability site. Work through each one methodically.

```c
// WHAT TO ANNOTATE IN YOUR NOTES for every arithmetic site:

// Operator: *
// Operands: chunk_count (from file at offset 12, uint32_t)
//           sizeof(element) = 8 (constant)
// Result type: uint32_t (32-bit — overflow wraps at 2^32)
// Check present: NONE
// Overflow condition: chunk_count > (UINT32_MAX / 8) = 536870911
// Downstream use: malloc(result) → undersized allocation

// If the attacker sets chunk_count = 0x20000001:
//   0x20000001 * 8 = 0x100000008 → truncated to uint32_t = 0x00000008
//   malloc(8) allocates 8 bytes
//   then a loop writes chunk_count × sizeof(element) = 4GB of data
//   → heap overflow
```

### Annotation Script

```python
#!/usr/bin/env python3
"""
Integer overflow candidate analyser.
Reads C source and flags multiplication/shift of potentially user-controlled
variables that feed into malloc/memcpy/realloc.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def find_arithmetic_sinks(source: str, filename: str) -> None:
    # Find lines with arithmetic on variables followed by allocation/copy
    arith_pat = re.compile(
        r"(\w+)\s*[*+<<]\s*(\w+)",
    )
    alloc_pat = re.compile(
        r"\b(malloc|calloc|realloc|alloca|memcpy|memmove)\s*\("
    )

    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        if alloc_pat.search(line) and arith_pat.search(line):
            print(f"[CANDIDATE] {filename}:{i}")
            # Show 3 lines of context
            start = max(0, i - 2)
            end = min(len(lines), i + 1)
            for j, ctx_line in enumerate(lines[start:end], start + 1):
                marker = ">>>" if j == i else "   "
                print(f"  {marker} {j:4}: {ctx_line.rstrip()}")
            print()


if __name__ == "__main__":
    target_dir = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    for src_file in target_dir.rglob("*.c"):
        try:
            text = src_file.read_text(errors="replace")
            find_arithmetic_sinks(text, str(src_file))
        except OSError:
            pass
```

```bash
python3 arith_audit.py . 2>/dev/null | head -100
```

---

## 2 — Triage the Fuzzer Output

Check the fuzzer output from Day 2. Any crash is a signal — prioritise
those over manual candidates, because the fuzzer has already done the
triggering for you.

```bash
# Check AFL++ status
afl-whatsup afl_output/
# Look for: "unique crashes" — if > 0, triage first

# List crashes
ls afl_output/crashes/ | grep -v README

# For each crash: triage with ASan to get the root cause
for crash_file in afl_output/crashes/id:*; do
    echo "═══════════════════════════════════════════════════════"
    echo "Crash: $crash_file"
    ASAN_OPTIONS="halt_on_error=1:print_stats=0" \
        ./build-asan/[target_binary] "$crash_file" 2>&1 | head -30
    echo "───────────────────────────────────────────────────────"
done

# Remove duplicates — crashes on the same line are likely the same bug
# Use afl-collect to deduplicate:
# afl-collect -j 4 -r afl_output unique_crashes -- ./build-asan/[binary] @@
```

### Crash Triage Template

```
CRASH TRIAGE LOG

Total crashes in afl_output/crashes/: _______
After deduplication: _______

CRASH 1
  File: afl_output/crashes/__________________________________
  ASan error type: __________________________________________
  Crash function: ___________________________________________
  Stack trace (top 3 frames):
    #0  __________________________________________________
    #1  __________________________________________________
    #2  __________________________________________________
  Likely bug class:
    [ ] Heap buffer overflow (write/read beyond allocation)
    [ ] Stack buffer overflow
    [ ] Use-after-free
    [ ] Integer overflow leading to undersized allocation
    [ ] Null pointer dereference
    [ ] Other: ____________________________________________
  Same as a Semgrep candidate from Day 666? Y / N
  Will pursue PoC: Y / N

CRASH 2 (if any)
  File: ____________________________________________________
  ASan error type: __________________________________________
  Crash function: ___________________________________________
  Stack trace (top 3 frames):
    #0  __________________________________________________
    #1  __________________________________________________
    #2  __________________________________________________
  Will pursue PoC: Y / N
```

---

## 3 — Manual Taint Tracking

Choose your strongest candidate (from the audit list or fuzzer crash) and
trace the taint path manually from source to sink in the code. Write it
down as a call chain.

### Example Taint Chain (for a hypothetical PNG parser)

```
EXAMPLE — DO NOT COPY; WRITE YOUR OWN

Source: fread(buf, 1, 4, fp)  → reads chunk_length from file (user-controlled)
          in: libpng/pngread.c:png_read_chunk_header()

Propagation 1: chunk_length is stored in png_ptr->chunk_length
               no validation yet; signed/unsigned mix: chunk_length is uint32_t,
               but later passed to (int) cast without bounds check

Propagation 2: passed to png_crc_read(png_ptr, buf, length)
               in: libpng/pngrutil.c:png_decompress_chunk()

Sink: memcpy(dst, src, length)
      if chunk_length = 0xFFFFFFFF, integer cast to int = -1,
      then size_t cast of -1 = SIZE_MAX → memcpy reads gigabytes
```

### Your Taint Chain

```
TAINT CHAIN — [YOUR CANDIDATE BUG]

Source (file/function/line):
  Data element: _____________________________________________
  Data type: ________________________________________________
  Constraints at read: ______________________________________

Propagation step 1:
  Function: ________________________ File: ________ Line: ___
  What happens: _____________________________________________
  Validation: _______________________________________________

Propagation step 2:
  Function: ________________________ File: ________ Line: ___
  What happens: _____________________________________________
  Validation: _______________________________________________

Propagation step 3 (if needed):
  Function: ________________________ File: ________ Line: ___
  What happens: _____________________________________________
  Validation: _______________________________________________

Sink:
  Function: ________________________ File: ________ Line: ___
  Dangerous operation: _______________________________________
  User-controlled operand: __________________________________

MISSING VALIDATION:
  What check would close this bug?
    ___________________________________________________________
  Where should the check be placed?
    ___________________________________________________________
```

---

## 4 — Candidate Bug Documentation

Before writing a PoC, document the candidate bug fully. If you cannot fill
in every field below, you do not understand the bug well enough to exploit it.

```
CANDIDATE BUG REPORT (pre-PoC)

TITLE: ______________________________________________________
CWE:   ______________________________________________________
File:  ______________________________ Line: _________________

ROOT CAUSE (one sentence):
  ___________________________________________________________

TRIGGERING INPUT:
  Field/offset that controls the vulnerability: ______________
  Triggering value: ________________________________________
  Why this value triggers the bug: _________________________

WHAT HAPPENS AT THE SINK:
  Sink operation: ___________________________________________
  Expected size: ____________________________________________
  Actual size with trigger: _________________________________
  Delta (bytes of overflow / underflow): ____________________

ATTACK SCENARIO:
  Who can provide the input? (authenticated / unauthenticated / file owner)
    ___________________________________________________________
  What does the attacker need to do?
    ___________________________________________________________

IMPACT HYPOTHESIS:
  [ ] Denial of Service (crash, process termination)
  [ ] Information Disclosure (read adjacent heap/stack memory)
  [ ] Code Execution (write to controlled location, overwrite function ptr)
  [ ] Other: _________________________________________________

CONFIDENCE LEVEL:
  [ ] HIGH — I can describe the exact triggering condition; PoC will work
  [ ] MED  — I understand the code path; need to verify trigger in debugger
  [ ] LOW  — I see a pattern; may be false positive; needs verification
```

---

## 5 — Progress Check

End of Day 3 target state:

```
DAY 3 PROGRESS CHECK

Audit list progress:
  Total functions planned: ______
  Fully audited today: ______
  Marked "Suspicious" or "Candidate": ______

Fuzzer crashes found: ______
Fuzzer crashes triaged: ______
Fuzzer crashes worth pursuing: ______

Candidate bugs documented: ______

STRONGEST CANDIDATE:
  Title: ___________________________________________________
  Confidence: HIGH / MED / LOW
  Will develop PoC tomorrow: Y / N

What slowed me down most today?
  ___________________________________________________________

What would I do differently next time?
  ___________________________________________________________
```

---

## Key Takeaways

1. **Every arithmetic operation on user data is a candidate.** The auditor
   who skims over multiplications and additions is the auditor who misses
   the CVE. Slow down at every `*`, `+`, `<<` that involves a value from
   the input. Ask: can this overflow? What happens downstream if it does?
2. **Fuzzer crashes are gifts, not noise.** When the fuzzer crashes a
   target, it has done the hard work: it found an input that triggers a bug.
   Your job is to understand why the crash happens, not to dismiss it as
   expected. Even a null pointer dereference tells you something is not
   being validated.
3. **You cannot write a PoC for a bug you cannot describe.** Before
   writing a single line of PoC code, fill in the candidate bug template.
   If you cannot answer "what is the exact triggering value and why?", you
   are guessing, not exploiting.
4. **Taint tracking is the skill.** The tools (Semgrep, CodeQL, AFL++) find
   candidates. The human reads the code between source and sink and decides
   whether a real vulnerability exists. That read — the manual taint trace —
   is the irreplaceable human skill in vulnerability research.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q668.1, Q668.2 …).

---

## Navigation

← Previous: [Day 667 — Audit Campaign Day 2: Codebase Navigation](DAY-0667-Audit-Campaign-Codebase-Navigation.md)
→ Next: [Day 669 — Audit Campaign Day 4: PoC Development](DAY-0669-Audit-Campaign-PoC-Development.md)
